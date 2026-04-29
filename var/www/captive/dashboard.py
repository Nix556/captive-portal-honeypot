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
        
        # get sort parameters
        sort_by = request.args.get("sort_by", "time")
        sort_dir = request.args.get("sort_dir", "desc")
        
        # get filter parameters
        device_filter = request.args.get("filter_device", "").strip().lower()
        pw_filter = request.args.get("filter_pw", "").strip().lower()

        text = _read_tail_text(log_file, max_tail_bytes)
        events = _extract_json_objects(text)
        sanitized_events = [_sanitize_event(e) for e in events]

        # apply filters
        filtered_events = sanitized_events
        
        if device_filter:
            filtered_events = [e for e in filtered_events if device_filter in (e.get("device_type") or "").lower()]
            
        if pw_filter:
            try:
                if '-' in pw_filter:
                    parts = pw_filter.split('-', 1)
                    pw_min = int(parts[0].strip()) if parts[0].strip() else 0
                    pw_max = int(parts[1].strip()) if parts[1].strip() else 999
                else:
                    pw_min = pw_max = int(pw_filter)
                filtered_events = [e for e in filtered_events
                                   if pw_min <= (e.get("password_len") or 0) <= pw_max]
            except ValueError:
                pass

        # sort events
        def sort_key(event):
            if sort_by == "time":
                return event["timestamp_utc"] or ""
            elif sort_by == "ip":
                return event["ip"] or ""
            elif sort_by == "session":
                return event["session_id"] or ""
            elif sort_by == "pw":
                return event["password_len"] or 0
            elif sort_by == "ssid":
                return event["ssid"] or ""
            elif sort_by == "device":
                return event["device_type"] or ""
            return ""

        reverse = sort_dir == "desc"
        filtered_events.sort(key=sort_key, reverse=reverse)
        events = filtered_events[-limit:]

        return jsonify({
            "log_file": log_file,
            "count": len(events),
            "sort_by": sort_by,
            "sort_dir": sort_dir,
            "filters": {
                "device": device_filter,
                "pw": pw_filter
            },
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
<title>Honeypot Live - Odense</title>

<style>
* { box-sizing: border-box; }

:root {
    --bg-primary: #f8fafc;
    --bg-secondary: #ffffff;
    --bg-card: #ffffff;
    --bg-table: #ffffff;
    --text-primary: #1e293b;
    --text-secondary: #64748b;
    --border: #e2e8f0;
    --border-light: #f1f5f9;
    --shadow: 0 2px 4px -1px rgba(0, 0, 0, 0.1);
}

[data-theme="dark"] {
    --bg-primary: #0f172a;
    --bg-secondary: #1e293b;
    --bg-card: #1e293b;
    --bg-table: #334155;
    --text-primary: #f1f5f9;
    --text-secondary: #cbd5e1;
    --border: #475569;
    --border-light: #475569;
    --shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
}

body {
    margin: 0;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Inter', 'Roboto', sans-serif;
    background: var(--bg-primary);
    color: var(--text-primary);
    line-height: 1.5;
    transition: background-color 0.3s ease, color 0.3s ease;
}

.wrap {
    max-width: 1400px;
    margin: 0 auto;
    padding: 1.5rem;
}

.card {
    background: var(--bg-card);
    border-radius: 12px;
    border: 1px solid var(--border);
    padding: 1.5rem;
    box-shadow: var(--shadow);
    transition: all 0.3s ease;
}

h1 {
    margin: 0 0 0.25rem 0;
    font-size: 2rem;
    font-weight: 700;
    color: var(--text-primary);
}

.tagline {
    color: var(--text-secondary);
    font-size: 1rem;
    margin-bottom: 1.5rem;
    font-weight: 400;
}

.topbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1.5rem;
    flex-wrap: wrap;
    gap: 0.75rem;
}

.actions {
    display: flex;
    gap: 0.5rem;
    align-items: center;
}

.btn {
    padding: 0.5rem 1rem;
    border: 1px solid;
    border-radius: 8px;
    font-weight: 600;
    cursor: pointer;
    font-size: 0.8rem;
    transition: all 0.2s ease;
    display: inline-flex;
    align-items: center;
    gap: 0.25rem;
}

.refresh { 
    background: #3b82f6; 
    color: white; 
    border-color: #3b82f6;
}

.refresh:hover { 
    background: #2563eb; 
    transform: translateY(-1px);
    box-shadow: 0 4px 12px rgba(59, 130, 246, 0.4);
}

.toggle { 
    background: #10b981; 
    color: white; 
    border-color: #10b981;
}

.toggle.off { 
    background: #94a3b8; 
    border-color: #94a3b8; 
}

.toggle.off:hover { background: #64748b; }

.clear { 
    background: var(--bg-card); 
    color: #ef4444; 
    border-color: var(--border);
}
.clear:hover { 
    background: #fef2f2; 
    border-color: #ef4444;
}

.dark-toggle {
    background: var(--bg-card);
    color: var(--text-secondary);
    border-color: var(--border);
    padding: 0.5rem;
    min-width: 44px;
}

.dark-toggle:hover {
    background: var(--border-light);
}

.status {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-weight: 500;
    font-size: 0.8rem;
    color: var(--text-secondary);
}

.live-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: #ef4444;
    animation: pulse 1.5s infinite;
}

.live .live-dot { background: #10b981; }

@keyframes pulse {
    0%, 100% { opacity: 1; transform: scale(1); }
    50% { opacity: 0.5; transform: scale(1.1); }
}

.filters {
    display: flex;
    gap: 1rem;
    margin-bottom: 1.5rem;
    flex-wrap: wrap;
}

.filter-group {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
    min-width: 180px;
}

.filter-label {
    font-size: 0.7rem;
    font-weight: 600;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

.filter-input {
    padding: 0.5rem 0.75rem;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: var(--bg-secondary);
    color: var(--text-primary);
    font-size: 0.8rem;
    transition: all 0.2s ease;
}

.filter-input:focus {
    outline: none;
    border-color: #3b82f6;
    box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
}

.kpis {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 1rem;
    margin: 1.5rem 0;
}

.kpi {
    text-align: center;
    padding: 1rem;
    border: 1px solid var(--border-light);
    border-radius: 10px;
    background: var(--bg-card);
    transition: all 0.2s ease;
}

.kpi:hover {
    border-color: var(--border);
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.kpi-value {
    font-size: 1.75rem;
    font-weight: 700;
    color: var(--text-primary);
    margin-bottom: 0.25rem;
}

.kpi-label {
    font-size: 0.7rem;
    color: var(--text-secondary);
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

.table-container {
    border: 1px solid var(--border);
    border-radius: 10px;
    overflow-y: auto;
    max-height: 500px;
    background: var(--bg-table);
    scrollbar-width: thin;  /* Firefox */
    scrollbar-color: #cbd5e1 var(--border-light);
}

/* Webkit browsers (Chrome, Safari, Edge) */
.table-container::-webkit-scrollbar {
    width: 8px;
}

.table-container::-webkit-scrollbar-track {
    background: var(--border-light);
    border-radius: 4px;
}

.table-container::-webkit-scrollbar-thumb {
    background: #cbd5e1;
    border-radius: 4px;
}

.table-container::-webkit-scrollbar-thumb:hover {
    background: #94a3b8;
}

table {
    width: 100%;
    border-collapse: collapse;
}

thead {
    position: sticky;
    top: 0;
    background: var(--bg-secondary);
    border-bottom: 2px solid var(--border);
}

th {
    padding: 0.75rem 0.5rem;
    text-align: left;
    font-weight: 600;
    font-size: 0.75rem;
    color: var(--text-primary);
    cursor: pointer;
    text-transform: uppercase;
    letter-spacing: 0.025em;
}

th:hover {
    background: var(--border-light);
}

td {
    padding: 0.75rem 0.5rem;
    font-size: 0.8rem;
    color: var(--text-secondary);
    border-bottom: 1px solid var(--border-light);
}

tr:hover {
    background: var(--border-light);
}

tr.new {
    background: #dbeafe !important;
    animation: flash 0.6s ease-out;
}

@keyframes flash {
    0%, 100% { background: #dbeafe; }
    50% { background: #bfdbfe; }
}

.badge {
    display: inline-block;
    padding: 0.25rem 0.5rem;
    background: #3b82f6;
    color: white;
    border-radius: 12px;
    font-size: 0.65rem;
    font-weight: 600;
    text-transform: uppercase;
}

.status-yes { background: #10b981; }
.status-no { background: #94a3b8; }

::-webkit-scrollbar {
    width: 6px;
}

::-webkit-scrollbar-track {
    background: var(--border-light);
}

::-webkit-scrollbar-thumb {
    background: #cbd5e1;
    border-radius: 3px;
}

::-webkit-scrollbar-thumb:hover {
    background: #94a3b8;
}

@media (max-width: 768px) {
    .wrap { padding: 1rem; }
    .card { padding: 1rem; }
    h1 { font-size: 1.5rem; }
    .kpis { grid-template-columns: repeat(2, 1fr); gap: 0.75rem; }
    .filters { flex-direction: column; }
    .filter-group { min-width: 100%; }
}
</style>
</head>

<body data-theme="light">
<div class="wrap">
<div class="card">
    <div class="topbar">
        <div>
            <h1>Honeypot Live</h1>
            <div class="tagline">Odense · Demo monitoring</div>
        </div>
        <div class="actions">
            <button class="btn refresh" onclick="load()">Opdater</button>
            <button class="btn toggle" id="autoBtn">Auto: ON</button>
            <button class="btn clear" onclick="clearFilters()">Ryd</button>
            <button class="btn dark-toggle" id="darkToggle" onclick="toggleDarkMode()" title="Dark/Light mode">🌙</button>
            <div class="status" id="statusLine">
                <span id="dot" class="live-dot"></span>
                <span id="status">offline</span>
            </div>
        </div>
    </div>

    <div class="filters">
        <div class="filter-group">
            <label class="filter-label">Device filter</label>
            <input class="filter-input" id="filterDevice" placeholder="mobile, android...">
        </div>
        <div class="filter-group">
            <label class="filter-label">Password length</label>
            <input class="filter-input" id="filterPW" placeholder="8-16 eller 12">
        </div>
    </div>

    <div class="kpis">
        <div class="kpi">
            <div class="kpi-value" id="kpi-events">-</div>
            <div class="kpi-label">Events (5min)</div>
        </div>
        <div class="kpi">
            <div class="kpi-value" id="kpi-ips">-</div>
            <div class="kpi-label">Unikke IPs</div>
        </div>
        <div class="kpi">
            <div class="kpi-value" id="kpi-sessions">-</div>
            <div class="kpi-label">Sessions</div>
        </div>
        <div class="kpi">
            <div class="kpi-value" id="kpi-pw">-</div>
            <div class="kpi-label">Gns. pw længde</div>
        </div>
        <div class="kpi">
            <div class="kpi-value" id="kpi-rate">-</div>
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
                    <th>SSID</th>
                    <th onclick="setSort('device')" data-sort="device">Device</th>
                    <th>OS</th>
                    <th>Browser</th>
                    <th>Email</th>
                    <th onclick="setSort('pw')" data-sort="pw">Pw len</th>
                </tr>
            </thead>
            <tbody id="rows"></tbody>
        </table>
    </div>
</div>
</div>

<script>
let auto = true, timer, isDark = false;
let currentSort = {by: 'time', dir: 'desc'};
let lastRowCount = 0;
let firstLoad = true;

const rowsEl = document.getElementById('rows');
const statusEl = document.getElementById('status');
const dotEl = document.getElementById('dot');
const statusLine = document.getElementById('statusLine');

function toggleDarkMode() {
    isDark = !isDark;
    document.body.dataset.theme = isDark ? 'dark' : 'light';
    document.getElementById('darkToggle').textContent = isDark ? '☀️' : '🌙';
    localStorage.setItem('darkMode', isDark);
}

function setStatus(live) {
    if (live) {
        statusLine.classList.add('live');
        statusEl.textContent = 'live';
        dotEl.style.background = '#10b981';
    } else {
        statusLine.classList.remove('live');
        statusEl.textContent = 'offline';
        dotEl.style.background = '#ef4444';
    }
}

function updateKpis(events) {
    const now = Date.now(), fiveMin = 5*60*1000;
    const recent = events.filter(e => now - new Date(e.timestamp_utc||0) < fiveMin);
    
    document.getElementById('kpi-events').textContent = recent.length;
    document.getElementById('kpi-ips').textContent = new Set(events.map(e=>e.ip).filter(Boolean)).size;
    document.getElementById('kpi-sessions').textContent = new Set(events.map(e=>e.session_id).filter(Boolean)).size;
    document.getElementById('kpi-pw').textContent = events.length ? (events.reduce((a,e)=>a+(e.password_len||0),0)/events.length|0) : 0;
    document.getElementById('kpi-rate').textContent = (recent.length/5).toFixed(1);
}

function setSort(field) {
    if (currentSort.by === field) {
        currentSort.dir = currentSort.dir === 'desc' ? 'asc' : 'desc';
    } else {
        currentSort.by = field;
        currentSort.dir = 'desc';
    }
    load();
}

async function load() {
    try {
        const params = new URLSearchParams({
            limit: 150,
            sort_by: currentSort.by,
            sort_dir: currentSort.dir,
            filter_device: document.getElementById('filterDevice').value,
            filter_pw: document.getElementById('filterPW').value
        });
        
        const token = new URLSearchParams(location.search).get('token');
        if (token) params.set('token', token);
        
        const res = await fetch(`/api/events?${params}`);
        const data = await res.json();
        
        const events = data.events || [];
        const rowCount = events.length;
        
        const isNewData = !firstLoad && rowCount > lastRowCount;
        lastRowCount = rowCount;
        if (firstLoad) firstLoad = false;
        
        rowsEl.innerHTML = events.map((e,i) => `
            <tr class="${isNewData && i<3 ? 'new' : ''}">
                <td>${i+1}</td>
                <td>${new Date(e.timestamp_utc||'').toLocaleTimeString('da-DK')}</td>
                <td>${e.ip||'-'}</td>
                <td>${e.ssid||'-'}</td>
                <td><span class="badge">${e.device_type||''}</span></td>
                <td>${e.os||''}</td>
                <td>${e.browser||''}</td>
                <td class="status-${e.email_provided ? 'yes' : 'no'}">${e.email_provided ? 'Ja' : 'Nej'}</td>
                <td>${e.password_len||0}</td>
            </tr>
        `).join('');
        
        updateKpis(events);
        setStatus(true);
        
    } catch(e) {
        setStatus(false);
        console.error(e);
    }
}

function toggleAuto() {
    auto = !auto;
    const btn = document.getElementById('autoBtn');
    btn.textContent = `Auto: ${auto ? 'ON' : 'OFF'}`;
    btn.className = auto ? 'btn toggle' : 'btn toggle off';
    
    if (timer) clearInterval(timer);
    if (auto) timer = setInterval(load, 5000);
}

function clearFilters() {
    document.getElementById('filterDevice').value = '';
    document.getElementById('filterPW').value = '';
    load();
}

if (localStorage.getItem('darkMode') === 'true') {
    toggleDarkMode();
}

document.getElementById('filterDevice').oninput = () => auto || load();
document.getElementById('filterPW').oninput = () => auto || load();

load();
toggleAuto();
</script>
</body>
</html>"""

        return Response(html, mimetype="text/html")

    return bp
