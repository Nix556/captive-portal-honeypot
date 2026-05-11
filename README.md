# Wi-Fi Honeypot

Awareness honeypot til robot & science festival.

Simulerer et realistisk captive portal flow:
`index.html -> login.html -> /authorize (logger) -> success.html`

## Krav

* Ubuntu server
* Docker + Docker Compose (UniFi Controller)
* Python 3 (venv + pip)
* Gunicorn
* Nginx
* (valgfrit) `.env`

## UniFi Controller

Køres via Docker Compose:

```bash
docker compose up -d
```

## Kør appen

```bash
python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
```
### Dev

```bash
python app_dev.py
```

### Production-ish

```bash
gunicorn -w 2 --threads 8 -b 0.0.0.0:5000 app_prod:app
```

## Dashboard

* `http://<SERVER-IP>/dashboard`
* `http://<SERVER-IP>/dashboard?token=TOKEN`

Nginx config: `nginx/sites-enabled.default.example`

## Notes

* Log: `honeypot.log` (NDJSON)
* Docker starter kun UniFi, ikke Flask
* Prod logger ikke passwords (kun længde + email flag)

## Credits

* Tak til Copilot
* Tak til Mikkel for den flotte log fil :D (Min PC sprang)
