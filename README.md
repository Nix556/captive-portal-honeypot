# Wi‑Fi Honeypot

Awareness honeypot til robot & sceincefestival event.

Realistisk captive portal flow:
`index.html` - `login.html` - `/authorize` (logger event) - `success.html`.

## Requirements

- Ubuntu server
- Docker + Docker Compose (til Ubiquiti UniFi Controller)
- Python 3 + venv + pip (til honeypot Flask app)
- Gunicorn (prod)
- (valgfrit) .env + dotenv til konfiguration
- (valgfrit) Nginx (reverse proxy)

## UniFi Controller

På Ubuntu serveren kører UniFi Controller via Docker Compose:

`docker compose up -d`

Compose fil: [docker-compose.yml](docker-compose.yml)

## Run

Opret og aktiver environment:

`python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt`

### Standard (anbefalet)

`gunicorn -w 2 --threads 8 -b 0.0.0.0:5000 app_prod:app --access-logfile /dev/null`

### Alternativ (kun til lokal udvikling / debugging)

`python app_dev.py`

## Dashboard

- Side: `/dashboard`
- API: `/api/events?limit=200`
- Uden token: `http://<SERVER-IP>/dashboard`
- Med token: `http://<SERVER-IP>/dashboard?token=TOKEN`

Nginx eksempel config: [nginx/sites-enabled.default.example](nginx/sites-enabled.default.example)

## Notes

- Logfilen er `honeypot.log` (NDJSON: en JSON pr. linje)
- `docker-compose.yml` starter kun UniFi Controller (den starter ikke Flask/Gunicorn)
- Prod logger aldrig plaintext credentials (kun `email_provided` + `password_len`)
- Appen forventer at køre bag Nginx (reverse proxy) i prod
