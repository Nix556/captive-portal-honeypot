
# Wi‑Fi Honeypot

Awareness honeypot til event (captive portal + fake login). Flask tager imod `/authorize` og logger events til `honeypot.log`.

## Filer

- Dev (logger plaintext): [var/www/captive/app_dev.py](var/www/captive/app_dev.py)
- Prod (event, ingen plaintext): [var/www/captive/app_prod.py](var/www/captive/app_prod.py)
- HTML: [var/www/captive/index.html](var/www/captive/index.html), [var/www/captive/login.html](var/www/captive/login.html), [var/www/captive/success.html](var/www/captive/success.html)

## Kør prod

Kør fra `var/www/captive`.

`gunicorn -w 2 --threads 8 -b 0.0.0.0:5000 app_prod:app --access-logfile /dev/null`

## Logging

- IP + `ap`/`ssid`, session-tid, User-Agent (grov OS/browser/device-type)
- Dev: logger det brugeren taster
- Prod: logger kun `email_provided` (true/false) + `password_len` (antal tegn)
