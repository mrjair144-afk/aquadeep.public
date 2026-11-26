---
title: Aqua Deep
sdk: docker
app_port: 7860
---
# AQUA DEEP Float Dashboard

## Run locally
```bash
pip install -r requirements.txt
python app.py
```
Open `http://localhost:7860`.

## Data integration
- `GET /api/floats` retrieves recent Argo observations from Ifremer ERDDAP, filtered to the project's Indian Ocean bounding box (latitude -40 to 25, longitude 40 to 100).
- `GET /api/profile/<WMO_ID>` returns the latest available measured pressure, temperature and salinity profile for that float (within the previous 180 days).
- `GET /api/trajectory/<WMO_ID>` returns recorded positions when available.
- Float-list responses are cached for 15 minutes. The browser retries the list every 15 minutes. Argo data delivery itself is not guaranteed to be real-time.
- If the Argo source is unavailable, the map shows an unavailable message instead of substituting fabricated sample floats.
- The monthly SST and official Potential Fishing Zone (PFZ) feeds are not connected in this version; those charts are intentionally left without invented values. The PFZ map layer, alerts, and some sea-condition fallback values remain clearly identified as sample/demo content.

## Project files
- `app.py` — Flask backend and API routes
- `static/index.html` — dashboard UI
- `requirements.txt` — Python dependencies
- `Dockerfile` — deployment configuration

## Hugging Face Space (Docker)
Upload the project files. Configure these variables/secrets in Space settings:
| Name | Purpose |
|---|---|
| `SECRET_KEY` | Long random signing key |
| `ANTHROPIC_API_KEY` | Optional AI chatbot |
| `GOOGLE_CLIENT_ID` | Optional Google sign-in |
| `DATABASE_URL` | Optional Postgres URL (Neon/Supabase) for persistent users, alerts and favourites |
| `ADMIN_EMAILS` | Comma-separated admin email addresses |

## Google sign-in
Create a Web OAuth client in Google Cloud Console. Add your deployed Space URL under Authorized JavaScript origins, then set `GOOGLE_CLIENT_ID`.

## Notes
The Argo API may have upstream delays or temporary outages. For operational marine decisions, use current official INCOIS advisories; this dashboard is an educational data viewer.
