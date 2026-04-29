import json
import os
from typing import Any

from flask import Blueprint, Response, abort, jsonify, request


def _read_tail_text(path: str, max_bytes: int) -> str:
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            start = max(0, size - max_bytes)
            f.seek(start)
            data = f.read()
        return data.decode("utf-8", errors="ignore")
    except FileNotFoundError:
        return ""


def _extract_json_objects_from_blobs(text: str) -> list[dict[str, Any]]:
    decoder = json.JSONDecoder()
    objects: list[dict[str, Any]] = []
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


def _extract_json_objects(text: str) -> list[dict[str, Any]]:
    # ndjson: en json pr linje
    objects: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        if isinstance(obj, dict):
            objects.append(obj)

    if objects:
        return objects

    # fallback til gamle multi-line logs
    return _extract_json_objects_from_blobs(text)


def _sanitize_event(event: dict[str, Any]) -> dict[str, Any]:
    ts = event.get("timestamp") or {}
    network = event.get("network") or {}
    device = event.get("device") or {}
    credentials = event.get("credentials") or {}
    session = event.get("session") or {}

    # normalize dev/prod
    email_provided = bool(
        credentials.get("email_provided")
        or credentials.get("provided")
        or credentials.get("email")
    )

    password_len: int
    if "password_len" in credentials and credentials.get("password_len") is not None:
        try:
            password_len = int(credentials.get("password_len"))
        except Exception:
            password_len = 0
    else:
        password = credentials.get("password") or ""
        password_len = len(password) if isinstance(password, str) else 0

    return {
        "event": event.get("event"),
        "timestamp_utc": ts.get("utc"),
        "ip": network.get("ip"),
        "ap": network.get("ap"),
        "ssid": network.get("ssid"),
        "session_duration_sec": session.get("duration_sec") or event.get("session_duration_sec") or 0,
        "user_agent": device.get("user_agent"),
        "device_type": device.get("type"),
        "os": device.get("os"),
        "browser": device.get("browser"),
        "email_provided": email_provided,
        "password_len": password_len,
    }


def create_dashboard_blueprint(
    log_file: str,
    *,
    max_tail_bytes: int = 2 * 1024 * 1024,
    default_limit: int = 200,
) -> Blueprint:
    bp = Blueprint("dashboard", __name__)

    token = os.getenv("HONEYPOT_DASHBOARD_TOKEN")

    def require_token() -> None:
        if not token:
            return
        provided = request.args.get("token") or request.headers.get("X-Honeypot-Token")
        if provided != token:
            abort(403)

    @bp.get("/api/events")
    def api_events():
        require_token()

        try:
            limit = int(request.args.get("limit", str(default_limit)))
        except Exception:
            limit = default_limit
        limit = max(1, min(limit, 2000))

        text = _read_tail_text(log_file, max_tail_bytes)
        events = _extract_json_objects(text)
        events = events[-limit:]
        sanitized = [_sanitize_event(e) for e in events]
        return jsonify({"log_file": log_file, "count": len(sanitized), "events": sanitized})

    @bp.get("/dashboard")
    def dashboard_page():
        require_token()

        html = r"""<!doctype html>
<html lang="da">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Honeypot dashboard</title>
    <style>
        body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 16px; }
        header { display:flex; gap:12px; align-items: baseline; flex-wrap: wrap; }
        small { color:#444; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 6px 8px; font-size: 13px; vertical-align: top; }
        th { text-align: left; position: sticky; top: 0; background: #fff; }
        .muted { color:#666; }
    </style>
</head>
<body>
    <header>
        <h1 style="margin:0">Honeypot dashboard</h1>
        <small>Viser seneste events fra <span class="muted" id="logfile"></span></small>
        <button id="refresh">Opdater</button>
        <label style="display:flex; gap:6px; align-items:center">
            <input type="checkbox" id="auto"> auto (5s)
        </label>
        <small id="status"></small>
    </header>

    <div style="margin-top:12px; overflow:auto">
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>tid</th>
                    <th>ip</th>
                    <th>ap</th>
                    <th>ssid</th>
                    <th>device</th>
                    <th>os</th>
                    <th>browser</th>
                    <th>email</th>
                    <th>pw len</th>
                </tr>
            </thead>
            <tbody id="rows"></tbody>
        </table>
    </div>

    <script>
        const rows = document.getElementById('rows');
        const statusEl = document.getElementById('status');
        const logFileEl = document.getElementById('logfile');
        const btn = document.getElementById('refresh');
        const auto = document.getElementById('auto');

        function esc(s) {
            return String(s ?? '').replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
        }

        function normalizeIsoToMillis(iso) {
            const s = String(iso ?? '');
            const m = s.match(/^(.+?)\.(\d+)(Z|[+-]\d\d:\d\d)$/);
            if (!m) return s;
            const prefix = m[1];
            const frac = (m[2] || '').slice(0, 3).padEnd(3, '0');
            const tz = m[3];
            return `${prefix}.${frac}${tz}`;
        }

        function fmtTime(iso) {
            if (!iso) return '';
            const d = new Date(normalizeIsoToMillis(iso));
            if (Number.isNaN(d.getTime())) return String(iso);
            return d.toLocaleString('da-DK', {
                year: 'numeric', month: '2-digit', day: '2-digit',
                hour: '2-digit', minute: '2-digit', second: '2-digit'
            });
        }

        async function load() {
            const t0 = performance.now();
            statusEl.textContent = 'Henter…';
            try {
                const qs = new URLSearchParams(location.search);
                const res = await fetch('/api/events?limit=200' + (qs.toString() ? '&' + qs.toString() : ''));
                const data = await res.json();
                logFileEl.textContent = data.log_file || '';
                const ev = (data.events || []).slice().reverse().slice(0, 200);
                rows.innerHTML = ev.map((e, i) => `
                    <tr>
                        <td>${i + 1}</td>
                        <td title="${esc(e.timestamp_utc)}">${esc(fmtTime(e.timestamp_utc))}</td>
                        <td>${esc(e.ip)}</td>
                        <td>${esc(e.ap)}</td>
                        <td>${esc(e.ssid)}</td>
                        <td>${esc(e.device_type)}</td>
                        <td>${esc(e.os)}</td>
                        <td>${esc(e.browser)}</td>
                        <td>${e.email_provided ? 'yes' : 'no'}</td>
                        <td>${esc(e.password_len)}</td>
                    </tr>`).join('');
                const ms = Math.round(performance.now() - t0);
                statusEl.textContent = `OK • ${ev.length} events (seneste 200) • ${ms}ms • ${new Date().toLocaleTimeString()}`;
            } catch (e) {
                statusEl.textContent = 'Fejl ved hentning';
            }
        }

        let timer = null;
        function setAuto(enabled) {
            if (timer) clearInterval(timer);
            timer = enabled ? setInterval(load, 5000) : null;
        }

        btn.addEventListener('click', load);
        auto.addEventListener('change', () => setAuto(auto.checked));
        load();
    </script>
</body>
</html>"""
        return Response(html, mimetype="text/html")

    return bp
