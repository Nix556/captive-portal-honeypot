import json
import os
from typing import Any

from flask import Blueprint, Response, abort, jsonify, request

# log reading
def _read_tail_text(path: str, max_bytes: int) -> str:
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - max_bytes))
            return f.read().decode("utf-8", errors="ignore")
    except FileNotFoundError:
        return ""


def _extract_json_objects(text: str) -> list[dict[str, Any]]:
    """
    Supports:
    1) NDJSON (one JSON per line)
    2) fallback embedded JSON blobs
    """

    # ndjson (fast path)
    objects: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                objects.append(obj)
        except Exception:
            continue

    if objects:
        return objects

    # fallback = scan blobs
    decoder = json.JSONDecoder()
    idx = 0
    n = len(text)

    while idx < n:
        start = text.find("{", idx)
        if start == -1:
            break
        try:
            obj, end = decoder.raw_decode(text[start:])
            idx = start + end
            if isinstance(obj, dict):
                objects.append(obj)
        except Exception:
            idx = start + 1

    return objects


# sanitize
def _sanitize_event(event: dict[str, Any]) -> dict[str, Any]:
    ts = event.get("timestamp") or {}
    network = event.get("network") or {}
    device = event.get("device") or {}
    credentials = event.get("credentials") or {}
    session = event.get("session") or {}

    email_provided = any([
        credentials.get("email_provided"),
        credentials.get("provided"),
        credentials.get("email"),
    ])

    password_len = 0
    if isinstance(credentials.get("password_len"), int):
        password_len = credentials["password_len"]
    elif isinstance(credentials.get("password"), str):
        password_len = len(credentials["password"])

    return {
        "event": event.get("event"),
        "timestamp_utc": ts.get("utc"),
        "ip": network.get("ip"),
        "ap": network.get("ap"),
        "ssid": network.get("ssid"),
        "session_duration_sec": session.get("duration_sec") or event.get("session_duration_sec") or 0,
        "device_type": device.get("type"),
        "os": device.get("os"),
        "browser": device.get("browser"),
        "email_provided": bool(email_provided),
        "password_len": password_len,
    }

# blueprint
def create_dashboard_blueprint(
    log_file: str,
    *,
    max_tail_bytes: int = 2 * 1024 * 1024,
    default_limit: int = 200,
) -> Blueprint:

    bp = Blueprint("dashboard", __name__)
    token = os.getenv("HONEYPOT_DASHBOARD_TOKEN")

    def require_token():
        if not token:
            return
        provided = request.args.get("token") or request.headers.get("X-Honeypot-Token")
        if provided != token:
            abort(403)

    # api
    @bp.get("/api/events")
    def api_events():
        require_token()

        try:
            limit = int(request.args.get("limit", default_limit))
        except Exception:
            limit = default_limit

        limit = max(1, min(limit, 2000))

        text = _read_tail_text(log_file, max_tail_bytes)
        events = _extract_json_objects(text)[-limit:]

        return jsonify({
            "log_file": log_file,
            "count": len(events),
            "events": [_sanitize_event(e) for e in events]
        })

    # dashboard page
    @bp.get("/dashboard")
    def dashboard_page():
        require_token()

        html = r"""<!doctype html>
<html lang="da">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Dashboard</title>

<style>
body {
    margin: 0;
    font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
    background: #f6f7f9;
    color: #111827;
}

.wrap {
    max-width: 900px;
    margin: 0 auto;
    padding: 36px 16px;
}

.card {
    background: #fff;
    border-radius: 10px;
    padding: 22px;
    border: 1px solid #e5e7eb;
}

h1 { margin: 0; font-size: 20px; }

.topbar {
    display:flex;
    justify-content:space-between;
    align-items:center;
    flex-wrap:wrap;
    gap:12px;
    margin-bottom:12px;
}

.actions {
    display:flex;
    gap:10px;
    align-items:center;
    flex-wrap:wrap;
}

button {
    padding:10px 12px;
    border-radius:8px;
    border:1px solid #111827;
    background:#111827;
    color:#fff;
    font-weight:600;
    cursor:pointer;
}

button:hover { background:#0b1220; }

.small { font-size:12px; color:#6b7280; }

table {
    width:100%;
    border-collapse:collapse;
    margin-top:14px;
}

th, td {
    font-size:12px;
    padding:8px;
    border-bottom:1px solid #e5e7eb;
    text-align:left;
}

.badge {
    font-size:11px;
    padding:2px 6px;
    border-radius:6px;
    background:#f3f4f6;
}

.live-dot {
    width:8px;
    height:8px;
    border-radius:50%;
    display:inline-block;
    margin-right:6px;
}

/* GREEN PULSE */
.online {
    background:#22c55e;
    animation: pulse-green 1.5s infinite;
}

/* RED PULSE */
.offline {
    background:#ef4444;
    animation: pulse-red 1.5s infinite;
}

@keyframes pulse-green {
    0%   { box-shadow: 0 0 0 0 rgba(34,197,94,0.6); }
    70%  { box-shadow: 0 0 0 10px rgba(34,197,94,0); }
    100% { box-shadow: 0 0 0 0 rgba(34,197,94,0); }
}

@keyframes pulse-red {
    0%   { box-shadow: 0 0 0 0 rgba(239,68,68,0.6); }
    70%  { box-shadow: 0 0 0 10px rgba(239,68,68,0); }
    100% { box-shadow: 0 0 0 0 rgba(239,68,68,0); }
}
</style>
</head>

<body>

<div class="wrap">
<div class="card">

<div class="topbar">
    <div>
        <h1>Honeypot Dashboard</h1>
        <div class="small">Odense · Demo</div>
    </div>

    <div class="actions">
        <button onclick="load()">Opdater</button>
        <button onclick="toggleAuto()" id="autoBtn">Auto: ON</button>

        <span class="small">
            <span id="dot" class="live-dot offline"></span>
            <span id="status">offline</span>
        </span>
    </div>
</div>

<table>
<thead>
<tr>
<th>Tid</th><th>IP</th><th>SSID</th><th>Device</th><th>OS</th><th>Browser</th><th>Email</th><th>Pw</th>
</tr>
</thead>
<tbody id="rows"></tbody>
</table>

</div>
</div>

<script>
const rows = document.getElementById("rows");
const statusEl = document.getElementById("status");
const dot = document.getElementById("dot");

let auto = true;
let timer = null;

function setLive(v){
    dot.className = "live-dot " + (v ? "online" : "offline");
    statusEl.textContent = v ? "live" : "offline";
}

async function load(){
    const qs = new URLSearchParams(location.search);
    const token = qs.get("token") || "";

    try {
        const res = await fetch("/api/events?limit=200" + (token ? `&token=${token}` : ""));
        const data = await res.json();

        const ev = (data.events || []).slice(-200);

        rows.innerHTML = ev.map(e => `
            <tr>
                <td>${new Date(e.timestamp_utc || "").toLocaleTimeString("da-DK")}</td>
                <td>${e.ip || ""}</td>
                <td>${e.ssid || ""}</td>
                <td><span class="badge">${e.device_type || ""}</span></td>
                <td>${e.os || ""}</td>
                <td>${e.browser || ""}</td>
                <td>${e.email_provided ? "yes" : "no"}</td>
                <td>${e.password_len || 0}</td>
            </tr>
        `).join("");

        setLive(true);   // only success → green
    } catch (err) {
        setLive(false);  // only real failure → red
    }
}

function toggleAuto(){
    auto = !auto;
    document.getElementById("autoBtn").textContent = "Auto: " + (auto ? "ON" : "OFF");

    if(timer) clearInterval(timer);
    if(auto) timer = setInterval(load, 5000);
}

load();
timer = setInterval(load, 5000);
</script>

</body>
</html>"""

        return Response(html, mimetype="text/html")

    return bp