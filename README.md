
# Wi‑Fi Honeypot (Robot og sciencefestival)

Dette projeket er en awareness honeypot som skal bruges til et event i Odense (Robot & Science Festival).
Setup’et ligner et “gratis gæste Wi‑Fi” med captive portal og en fake login side (med tydelig advarsel om ikke at bruge rigtige oplysninger).
Formålet er at vise, hvordan phishing over Wi‑Fi kan se ud.

Strukturen er rimelig simpel HTML siderne ligger samlet, og Flask app’en tager imod `/authorize` og logger det hele til `honeypot.log`.

## Struktur / hvor ting ligger

- Dev Flask (logger plaintext): [var/www/captive/app_dev.py](var/www/captive/app_dev.py)
- Prod Flask (event, ingen plain tekst i logs): [var/www/captive/app_prod.py](var/www/captive/app_prod.py)
- Captive portal sider: [var/www/captive/index.html](var/www/captive/index.html), [var/www/captive/login.html](var/www/captive/login.html), [var/www/captive/success.html](var/www/captive/success.html)

## Hurtigt flow (så jeg selv kan huske det)

- Captive portal = [var/www/captive/index.html](var/www/captive/index.html)
- Videre til login = [var/www/captive/login.html](var/www/captive/login.html)
- Submit = `/authorize` (Flask)
- Flask logger til `honeypot.log` og redirecter til [var/www/captive/success.html](var/www/captive/success.html)

## Hvad logger den?

- Klient-IP + `ap` (BSSID) og `ssid`
- Session-tid (fra index til submit)
- User-Agent + grov OS/browser/device-type
- Dev: Det brugeren taster i felterne (DER ER!!! advarsel på login siden)
- Prod: Kun om navn/email er udfyldt + antal tegn i password

## Prod (til event)

Kør [var/www/captive/app_prod.py](var/www/captive/app_prod.py) til selve eventet.
Den logger **ikke** email/password i plain tekst kun:

- om email feltet er udfyldt (true/false)
- hvor mange tegn der er i passwordet
