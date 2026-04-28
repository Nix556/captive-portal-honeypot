from flask import Flask, request, redirect
import json
import time
import os
import logging
from logging.handlers import RotatingFileHandler
from threading import BoundedSemaphore
from collections import deque
from datetime import datetime, timezone

app = Flask(__name__)

# Disable Werkzeug access logs (they include the full URL + query string).
_werkzeug_logger = logging.getLogger("werkzeug")
_werkzeug_logger.setLevel(logging.ERROR)
_werkzeug_logger.propagate = False
_werkzeug_logger.disabled = True

LOG_FILE = os.getenv("HONEYPOT_LOG_FILE", "honeypot.log")

# Defaults are chosen to be safe under abusive load, but adjustable.
STDOUT_ENABLED = os.getenv("HONEYPOT_STDOUT", "0") == "1"
PRETTY_STDOUT = os.getenv("HONEYPOT_PRETTY_STDOUT", "1") == "1"
PRETTY_FILE = os.getenv("HONEYPOT_PRETTY_LOG_FILE", "0") == "1"
BLOCK_CURL = os.getenv("HONEYPOT_BLOCK_CURL", "0") == "1"

MAX_CONCURRENT = int(os.getenv("HONEYPOT_MAX_CONCURRENT", "200") or "200")
RATE_LIMIT_PER_SEC = int(os.getenv("HONEYPOT_RATE_LIMIT_PER_SEC", "50") or "50")

LOG_MAX_BYTES = int(os.getenv("HONEYPOT_LOG_MAX_BYTES", str(10 * 1024 * 1024)))
LOG_BACKUP_COUNT = int(os.getenv("HONEYPOT_LOG_BACKUP_COUNT", "5") or "5")

_semaphore = BoundedSemaphore(MAX_CONCURRENT)
_rate_window_by_ip: dict[str, deque[float]] = {}

_event_logger = logging.getLogger("honeypot")
if not _event_logger.handlers:
    _handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUP_COUNT,
        encoding="utf-8",
        delay=True,
    )
    _handler.setFormatter(logging.Formatter("%(message)s"))
    _event_logger.addHandler(_handler)
_event_logger.setLevel(logging.INFO)
_event_logger.propagate = False


def _normalize_device_type(value):
    if isinstance(value, dict):
        return value.get("type") or "unknown"
    if isinstance(value, str) and value:
        return value
    return "unknown"


# user agent parsing
def parse_user_agent(ua: str):
    device = "unknown"
    os_name = "unknown"
    browser = "unknown"

    # OS detection
    if "iPhone" in ua or "iPad" in ua:
        os_name = "iOS"
    elif "Android" in ua:
        os_name = "Android"
    elif "Windows" in ua:
        os_name = "Windows"
    elif "Mac OS" in ua or "Macintosh" in ua:
        os_name = "MacOS"
    elif "Linux" in ua:
        os_name = "Linux"

    if any(x in ua for x in ["Mobile", "Android", "iPhone"]):
        device = "mobile"
    else:
        device = "desktop"

    if "Edg" in ua:
        browser = "Edge"
    elif "Firefox" in ua:
        browser = "Firefox"
    elif "Chrome" in ua:
        browser = "Chrome"
    elif "Safari" in ua or (
        os_name == "iOS" and "AppleWebKit" in ua and "Chrome" not in ua and "CriOS" not in ua
    ):
        browser = "Safari"

    return device, os_name, browser


# structured logging
def log(data: dict):
    network = data.get("network") or {}
    credentials = data.get("credentials") or {}
    device = data.get("device") or {}

    password_len = credentials.get("password_len")
    try:
        password_len_int = int(password_len) if password_len is not None else 0
    except Exception:
        password_len_int = 0

    enriched = {
        "version": 1,
        "event": data.get("event", "login"),
        "timestamp": {"utc": datetime.now(timezone.utc).isoformat()},
        "session": {"duration_sec": data.get("session_duration_sec", 0)},
        "network": {
            "ip": network.get("ip"),
            "ap": network.get("ap") or None,
            "ssid": network.get("ssid") or None,
        },
        "credentials": {
            "email_provided": bool(credentials.get("email_provided")),
            "password_len": password_len_int,
        },
        "device": {
            "user_agent": device.get("user_agent"),
            "type": _normalize_device_type(device.get("type")),
            "os": device.get("os"),
            "browser": device.get("browser"),
        },
        "meta": {
            "source": "captive-portal",
            "lab_mode": True,
            "controller": None,
            "festival": "Robot & Science Festival Odense",
            "mode": "prod",
        },
    }

    if PRETTY_FILE:
        _event_logger.info(json.dumps(enriched, ensure_ascii=False, indent=2) + "\n")
    else:
        _event_logger.info(json.dumps(enriched, ensure_ascii=False, separators=(",", ":")))


@app.route("/authorize")
def authorize():
    if not _semaphore.acquire(blocking=False):
        return redirect("/success.html")

    try:
        ip = request.remote_addr

        ap_raw = request.args.get("ap", "")
        ssid_raw = request.args.get("ssid", "")

        ap = (ap_raw or "").strip() or None
        ssid = (ssid_raw or "").strip() or None
        start_time = request.args.get("startTime")

        email = request.args.get("email", "")
        password = request.args.get("password", "")

        user_agent = request.headers.get("User-Agent", "")

        if BLOCK_CURL and "curl" in user_agent.lower():
            return redirect("/success.html")

        if RATE_LIMIT_PER_SEC > 0 and ip:
            now = time.time()
            q = _rate_window_by_ip.get(ip)
            if q is None:
                q = deque()
                _rate_window_by_ip[ip] = q
            while q and (now - q[0]) > 1.0:
                q.popleft()
            if len(q) >= RATE_LIMIT_PER_SEC:
                return redirect("/success.html")
            q.append(now)

        # session time
        try:
            session_duration = int((time.time() * 1000 - int(start_time)) / 1000)
        except Exception:
            session_duration = 0

        # UA parse
        device_type, os_name, browser_name = parse_user_agent(user_agent)

        email_clean = (email or "").strip()
        password_clean = (password or "").strip()

        # never store plaintext credentials in prod
        email_provided = bool(email_clean)
        password_len = len(password_clean) if password_clean else 0

        log_entry = {
            "event": "login",
            "session_duration_sec": session_duration,
            "network": {"ip": ip, "ap": ap, "ssid": ssid},
            "credentials": {
                "email_provided": email_provided,
                "password_len": password_len,
            },
            "device": {
                "user_agent": user_agent,
                "type": device_type,
                "os": os_name,
                "browser": browser_name,
            },
        }

        log(log_entry)

        if STDOUT_ENABLED:
            raw_event = {
                "event": "login",
                "session_duration_sec": session_duration,
                "network": {"ip": ip, "ap": ap_raw, "ssid": ssid_raw},
                "credentials": {"email_provided": email_provided, "password_len": password_len},
                "device": {
                    "user_agent": user_agent,
                    "type": device_type,
                    "os": os_name,
                    "browser": browser_name,
                },
            }
            print(
                json.dumps(
                    raw_event,
                    ensure_ascii=False,
                    indent=2 if PRETTY_STDOUT else None,
                    separators=None if PRETTY_STDOUT else (",", ":"),
                )
            )

        return redirect("/success.html")
    finally:
        _semaphore.release()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
