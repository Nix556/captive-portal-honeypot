
# Wi‑Fi Honeypot

Awareness honeypot til event (captive portal + fake login). Flask tager imod `/authorize` og logger events til `honeypot.log`.

## Infrastruktur

På en Ubuntu server kører `docker-compose` (se [docker-compose.yml](docker-compose.yml)), som starter vores Ubiquiti UniFi Controller. UniFi Controller’en bruges til at konfigurere captive portal’en.

## Filer

- Dev (logger plaintext): [var/www/captive/app_dev.py](var/www/captive/app_dev.py)
- Prod (event, ingen plaintext): [var/www/captive/app_prod.py](var/www/captive/app_prod.py)
- UniFi Controller (docker): [docker-compose.yml](docker-compose.yml)
- HTML: [var/www/captive/index.html](var/www/captive/index.html), [var/www/captive/login.html](var/www/captive/login.html), [var/www/captive/success.html](var/www/captive/success.html)

## Quickstart

Install:

`python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt`

Run (prod):

`cd var/www/captive && gunicorn -w 2 --threads 8 -b 0.0.0.0:5000 app_prod:app --access-logfile /dev/null`

## Logging

- IP + `ap`/`ssid`, session-tid, User-Agent (grov OS/browser/device-type)
- Dev: logger det brugeren taster
- Prod: logger kun `email_provided` (true/false) + `password_len` (antal tegn)

## Dashboard

- Side: `/dashboard`
- API: `/api/events?limit=200` (returnerer de seneste events fra `honeypot.log`)
- Tilgå: [Åbn dashboard](http://SERVER-IP:5000/dashboard)

Nginx config: [nginx/sites-enabled.default.example](nginx/sites-enabled.default.example)
