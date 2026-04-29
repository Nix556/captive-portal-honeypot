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
        "ap": network.get("ap") or None,
        "ssid": network.get("ssid"),
        "session_id": session.get("id") or event.get("session_id"),
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
        
        # Get sort parameter
        sort_by = request.args.get("sort_by", "time")
        sort_dir = request.args.get("sort_dir", "desc")

        text = _read_tail_text(log_file, max_tail_bytes)
        events = _extract_json_objects(text)
        sanitized_events = [_sanitize_event(e) for e in events]

        # Sort events
        def sort_key(event):
            if sort_by == "time":
                return event["timestamp_utc"] or ""
            elif sort_by == "ip":
                return event["ip"] or ""
            elif sort_by == "session":
                return event["session_id"] or ""
            elif sort_by == "ap":
                return event["ap"] or ""
            return ""

        reverse = sort_dir == "desc"
        sanitized_events.sort(key=sort_key, reverse=reverse)
        events = sanitized_events[-limit:]  # Take last N after sorting

        return jsonify({
            "log_file": log_file,
            "count": len(events),
            "sort_by": sort_by,
            "sort_dir": sort_dir,
            "events": events
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

/* SORT BUTTONS */
.sort-btn {
    padding: 6px 12px;
    font-size: 11px;
    background: #f3f4f6;
    color: #374151;
    border: 1px solid #d1d5db;
}

.sort-btn:hover {
    background: #e5e7eb;
}

.sort-btn.active {
    background: #3b82f6;
    color: white;
    border-color: #2563eb;
}

.sort-btn.asc::after {
    content: " ▲";
    font-size: 10px;
}

.sort-btn.desc::after {
    content: " ▼";
    font-size: 10px;
}

/* TABLE CONTAINER - NY */
.table-container {
    max-height: 500px;
    overflow-y: auto;
    border: 1px solid #e5e7eb;
    border-radius: 8px;
    margin-top: 14px;
}

/* STICKY HEADER - NY */
.table-container table {
    width: 100%;
    border-collapse: collapse;
}

.table-container thead {
    position: sticky;
    top: 0;
    background: #f9fafb;
    z-index: 10;
}

.table-container thead th {
    font-size: 12px;
    padding: 12px 8px;
    border-bottom: 2px solid #e5e7eb;
    text-align: left;
    font-weight: 600;
    background: #f9fafb;
    color: #374151;
    cursor: pointer;
    user-select: none;
}

.table-container thead th:hover {
    background: #f3f4f6;
}

.table-container tbody td {
    font-size: 12px;
    padding: 12px 8px;
    border-bottom: 1px solid #f3f4f6;
    text-align: left;
}

/* Scrollbar styling */
.table-container::-webkit-scrollbar {
    width: 8px;
}

.table-container::-webkit-scrollbar-track {
    background: #f1f5f9;
    border-radius: 4px;
}

.table-container::-webkit-scrollbar-thumb {
    background: #cbd5e1;
    border-radius: 4px;
}

.table-container::-webkit-scrollbar-thumb:hover {
    background: #94a3b8;
}

.badge {
    font-size: 11px;
    padding: 2px 6px;
    border-radius: 6px;
    background: #f3f4f6;
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

.kpis {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 10px;
    margin: 14px 0 18px 0;
}

.kpi {
    border: 1px solid #e5e7eb;
    border-radius: 10px;
    padding: 12px;
    background: #fff;
}

.kpi-value {
    font-size: 18px;
    font-weight: 600;
    color: #111827;
}

.kpi-label {
    font-size: 11px;
    color: #6b7280;
    margin-top: 4px;
}

.table-container tbody tr:first-child {
    background: #f0f9ff !important;
    animation: subtleBlink 2s ease-in-out infinite !important;
}

@keyframes subtleBlink {
    0%, 100% { 
        background: #f0f9ff !important; 
        box-shadow: 0 0 6px rgba(59, 130, 246, 0.25) !important;
    }
    50% { 
        background: #e0f2fe !important; 
        box-shadow: 0 0 16px rgba(59, 130, 246, 0.12) !important;
    }
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

<div class="kpis">
    <div class="kpi">
        <div class="kpi-value" id="kpi-events">0</div>
        <div class="kpi-label">Events (5 min)</div>
    </div>

    <div class="kpi">
        <div class="kpi-value" id="kpi-ips">0</div>
        <div class="kpi-label">Unikke IP'er</div>
    </div>

    <div class="kpi">
        <div class="kpi-value" id="kpi-sessions">0</div>
        <div class="kpi-label">Sessions</div>
    </div>

    <div class="kpi">
        <div class="kpi-value" id="kpi-pw">0</div>
        <div class="kpi-label">Avg input length</div>
    </div>

    <div class="kpi">
        <div class="kpi-value" id="kpi-rate">0</div>
        <div class="kpi-label">Events/min</div>
    </div>
</div>

<div class="table-container">
<table>
<thead>
<tr>
<th onclick="setSort('time')" data-sort="time">#</th>
<th onclick="setSort('time')" data-sort="time">Tid</th>
<th onclick="setSort('ip')" data-sort="ip">IP</th>
<th onclick="setSort('ap')" data-sort="ap">AP</th>
<th>SSID</th>
<th>Device</th>
<th>OS</th>
<th>Browser</th>
<th>Email</th>
<th>Pw</th>
</tr>
</thead>
<tbody id="rows"></tbody>
</table>
</div>

</div>
</div>

<script>
const rows = document.getElementById("rows");
const statusEl = document.getElementById("status");
const dot = document.getElementById("dot");

let auto = true;
let timer = null;
let previousEventCount = 0;
let currentSort = { by: 'time', dir: 'desc' };

function setLive(v){
    dot.className = "live-dot " + (v ? "online" : "offline");
    statusEl.textContent = v ? "live" : "offline";
}

function computeKpis(events){
    const now = Date.now();
    const fiveMin = 5 * 60 * 1000;

    const recent = events.filter(e => {
        const t = new Date(e.timestamp_utc || 0).getTime();
        return now - t < fiveMin;
    });

    const ips = new Set(events.map(e => e.ip).filter(Boolean));
    const sessions = new Set(events.map(e => e.session_id).filter(Boolean));

    const avgInput = events.length
        ? (events.reduce((a, e) => a + (e.password_len || 0), 0) / events.length)
        : 0;

    const rate = recent.length / 5;

    return {
        events5m: recent.length,
        ips: ips.size,
        sessions: sessions.size,
        avgInput: avgInput.toFixed(1),
        rate: rate.toFixed(1)
    };
}

function updateSortIndicators() {
    document.querySelectorAll('th[data-sort]').forEach(th => {
        th.classList.remove('active', 'asc', 'desc');
        if (th.dataset.sort === currentSort.by) {
            th.classList.add('active', currentSort.dir);
        }
    });
}

function setSort(sortBy) {
    if (currentSort.by === sortBy) {
        currentSort.dir = currentSort.dir === 'desc' ? 'asc' : 'desc';
    } else {
        currentSort.by = sortBy;
        currentSort.dir = 'desc';
    }
    load();
}

async function load(){
    const qs = new URLSearchParams(location.search);
    const token = qs.get("token") || "";

    try {
        // FIXED: Brug URLSearchParams i stedet for new URL()
        const params = new URLSearchParams({
            limit: '200',
            sort_by: currentSort.by,
            sort_dir: currentSort.dir
        });
        if (token) {
            params.set('token', token);
        }
        
        const url = `/api/events?${params.toString()}`;
        const res = await fetch(url);
        
        if (!res.ok) {
            throw new Error(`HTTP ${res.status}`);
        }
        
        const data = await res.json();

        const ev = data.events || [];
        const currentEventCount = ev.length;

        const newRowsHtml = ev.map((e, i) => `
            <tr data-index="${i}">
                <td>${i + 1}</td>
                <td>${new Date(e.timestamp_utc || "").toLocaleTimeString("da-DK")}</td>
                <td>${e.ip || ""}</td>
                <td>${e.ap || "-"}</td>
                <td>${e.ssid || "-"}</td>
                <td><span class="badge">${e.device_type || ""}</span></td>
                <td>${e.os || ""}</td>
                <td>${e.browser || ""}</td>
                <td>${e.email_provided ? "yes" : "no"}</td>
                <td>${e.password_len || 0}</td>
            </tr>
        `).join("");

        rows.innerHTML = newRowsHtml;
        updateSortIndicators();

        previousEventCount = currentEventCount;

        const k = computeKpis(ev);

        document.getElementById("kpi-events").textContent = k.events5m;
        document.getElementById("kpi-ips").textContent = k.ips;
        document.getElementById("kpi-sessions").textContent = k.sessions;
        document.getElementById("kpi-pw").textContent = k.avgInput;
        document.getElementById("kpi-rate").textContent = k.rate;

        setLive(true);

    } catch (err) {
        console.error('Load error:', err);
        setLive(false);
    }
}

function toggleAuto(){
    auto = !auto;
    document.getElementById("autoBtn").textContent = "Auto: " + (auto ? "ON" : "OFF");

    if(timer) clearInterval(timer);
    if(auto) timer = setInterval(load, 5000);
}

load();
if (auto) timer = setInterval(load, 5000);
</script>

</body>
</html>"""

        return Response(html, mimetype="text/html")

    return bp