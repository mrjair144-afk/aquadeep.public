---
title: Aqua Deep
sdk: docker
app_port: 7860
---
# AQUA DEEP Float Dashboard

## Run locally
    pip install -r requirements.txt
    python app.py          # http://localhost:7860

## Files
- app.py, requirements.txt, Dockerfile, README.md
- static/index.html (dashboard)
- static/temp.png and static/march-april.png (copy your two images here)

## Hugging Face Space (SDK: Docker)
Upload everything. Settings -> Variables and secrets:
| Name | Purpose |
|---|---|
| SECRET_KEY | any long random string (required) |
| ANTHROPIC_API_KEY | AI chatbot (optional) |
| GOOGLE_CLIENT_ID | Google sign-in button (optional) |
| DATABASE_URL | Postgres URL (Neon/Supabase) so users, alerts and favourites are permanent |
| ADMIN_EMAILS | comma-separated emails that get the Admin tab (post alerts, see users) |

## Google sign-in setup
Google Cloud Console -> APIs & Services -> Credentials -> OAuth client ID (Web).
Add your Space URL (https://<user>-<space>.hf.space) under Authorized JavaScript origins.
Copy the Client ID into GOOGLE_CLIENT_ID.

## Permanent database (free)
Create a project at neon.tech, copy the connection string, set it as DATABASE_URL.
Tables are created automatically.
