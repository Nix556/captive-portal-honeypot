from flask import Flask, request, redirect
import json
import time
import os
import logging
from datetime import datetime, timezone

app = Flask(__name__)

# Disable Werkzeug access logs (they include the full URL + query string).
_werkzeug_logger = logging.getLogger("werkzeug")
_werkzeug_logger.setLevel(logging.ERROR)
_werkzeug_logger.propagate = False
_werkzeug_logger.disabled = True

LOG_FILE = os.getenv("HONEYPOT_LOG_FILE", "honeypot.log")


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
            "type": device.get("type"),
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

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(enriched, ensure_ascii=False, indent=2) + "\n\n")


@app.route("/authorize")
def authorize():
    ip = request.remote_addr

    ap_raw = request.args.get("ap", "")
    ssid_raw = request.args.get("ssid", "")

    ap = (ap_raw or "").strip() or None
    ssid = (ssid_raw or "").strip() or None
    start_time = request.args.get("startTime")

    email = request.args.get("email", "")
    password = request.args.get("password", "")

    user_agent = request.headers.get("User-Agent", "")

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
    print(json.dumps(raw_event, ensure_ascii=False, indent=2))
    return redirect("/success.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
