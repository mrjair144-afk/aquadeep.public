"""AQUA DEEP backend: Flask + SQLite.
Serves the dashboard and these APIs:
  POST /api/signup   POST /api/login   POST /api/google
  GET  /api/floats   POST /api/chat
"""
import os, time, sqlite3
import requests
from flask import Flask, request, jsonify, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

app = Flask(__name__, static_folder="static", static_url_path="")
SECRET = os.environ.get("SECRET_KEY", "change-me-in-production")
DB = os.environ.get("DB_PATH", "aquadeep.db")
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
ANTHROPIC_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
signer = URLSafeTimedSerializer(SECRET)

# ---------------- database ----------------
# Default: built-in sqlite3 (no extra packages, works everywhere).
# If DATABASE_URL (Postgres: Neon/Supabase) is set, SQLAlchemy is used instead so users are permanent.
class DupEmail(Exception):
    pass

URL = os.environ.get("DATABASE_URL", "")
if URL.startswith("postgres://"):
    URL = URL.replace("postgres://", "postgresql://", 1)
DB_PATH = os.environ.get("DB_PATH", "aquadeep.db")

if URL:
    from sqlalchemy import create_engine, text
    from sqlalchemy.exc import IntegrityError
    engine = create_engine(URL, pool_pre_ping=True)
    with engine.begin() as c:
        c.execute(text("CREATE TABLE IF NOT EXISTS users(id SERIAL PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, pw TEXT)"))

    def get_user(email):
        with engine.connect() as c:
            return c.execute(text("SELECT id,name,email,pw FROM users WHERE email=:e"), {"e": email}).mappings().first()

    def add_user(name, email, pw):
        try:
            with engine.begin() as c:
                return c.execute(text("INSERT INTO users(name,email,pw) VALUES(:n,:e,:p) RETURNING id"),
                                 {"n": name, "e": email, "p": pw}).scalar()
        except DupEmail:
            raise DupEmail()
else:
    with sqlite3.connect(DB_PATH) as c:
        c.execute("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, pw TEXT)")

    def get_user(email):
        c = sqlite3.connect(DB_PATH); c.row_factory = sqlite3.Row
        try:
            return c.execute("SELECT id,name,email,pw FROM users WHERE email=?", (email,)).fetchone()
        finally:
            c.close()

    def add_user(name, email, pw):
        c = sqlite3.connect(DB_PATH)
        try:
            cur = c.execute("INSERT INTO users(name,email,pw) VALUES(?,?,?)", (name, email, pw))
            c.commit()
            return cur.lastrowid
        except sqlite3.IntegrityError:
            raise DupEmail()
        finally:
            c.close()

# ---------------- auth ----------------
def make_token(user_id, name):
    return signer.dumps({"id": user_id, "name": name})

def current_user():
    h = request.headers.get("Authorization", "")
    if not h.startswith("Bearer "):
        return None
    try:
        return signer.loads(h[7:], max_age=7 * 24 * 3600)
    except (BadSignature, SignatureExpired):
        return None

@app.post("/api/signup")
def signup():
    d = request.get_json(force=True)
    name, email, pw = (d.get("name") or "").strip(), (d.get("email") or "").strip().lower(), d.get("password") or ""
    if not name or "@" not in email or len(pw) < 6:
        return jsonify(error="Enter name, valid email and a password of 6+ characters."), 400
    try:
        uid = add_user(name, email, generate_password_hash(pw))
    except DupEmail:
        return jsonify(error="Email already registered."), 409
    return jsonify(token=make_token(uid, name), name=name)

@app.post("/api/login")
def login():
    d = request.get_json(force=True)
    email, pw = (d.get("email") or "").strip().lower(), d.get("password") or ""
    u = get_user(email)
    if not u or not u["pw"] or not check_password_hash(u["pw"], pw):
        return jsonify(error="Wrong email or password."), 401
    return jsonify(token=make_token(u["id"], u["name"]), name=u["name"])

@app.post("/api/google")
def google_login():
    """Frontend sends the Google ID token (credential). We verify it with Google."""
    if not GOOGLE_CLIENT_ID:
        return jsonify(error="GOOGLE_CLIENT_ID is not configured."), 501
    cred = (request.get_json(force=True).get("credential") or "")
    r = requests.get("https://oauth2.googleapis.com/tokeninfo", params={"id_token": cred}, timeout=10)
    info = r.json()
    if r.status_code != 200 or info.get("aud") != GOOGLE_CLIENT_ID:
        return jsonify(error="Google sign-in failed."), 401
    email, name = info["email"].lower(), info.get("name") or info["email"].split("@")[0]
    u = get_user(email)
    if not u:
        uid = add_user(name, email, None)
    else:
        uid, name = u["id"], u["name"]
    return jsonify(token=make_token(uid, name), name=name)

# ---------------- Argo floats ----------------
# Public Argo data via Ifremer ERDDAP. Verify the dataset/variable names if the call fails.
ERDDAP = "https://erddap.ifremer.fr/erddap/tabledap/ArgoFloats.json"
_cache = {"t": 0, "data": None}

SAMPLE = [
    {"id": "2902114", "lat": 15.2, "lon": 68.5, "t": 27.8, "s": 36.1, "d": 1000, "st": "active"},
    {"id": "2902118", "lat": 10.4, "lon": 72.9, "t": 28.4, "s": 35.6, "d": 2000, "st": "deep"},
    {"id": "2902125", "lat": 5.1, "lon": 80.2, "t": 28.9, "s": 34.9, "d": 1500, "st": "active"},
    {"id": "2902131", "lat": -3.5, "lon": 75.0, "t": 27.9, "s": 35.2, "d": 1000, "st": "surfaced"},
    {"id": "2902140", "lat": 14.8, "lon": 87.6, "t": 28.2, "s": 33.4, "d": 1800, "st": "active"},
]

def fetch_argo():
    # last 10 days, Indian Ocean box, surface-most reading per float
    q = ('?platform_number,time,latitude,longitude,pres,temp,psal'
         '&time>=now-10days&latitude>=-40&latitude<=25&longitude>=40&longitude<=100'
         '&pres<=10&orderByMax("platform_number,time")')
    r = requests.get(ERDDAP + q, timeout=25)
    r.raise_for_status()
    t = r.json()["table"]
    cols = t["columnNames"]
    out = []
    for row in t["rows"]:
        x = dict(zip(cols, row))
        if x["latitude"] is None or x["longitude"] is None:
            continue
        out.append({
            "id": str(x["platform_number"]), "lat": round(x["latitude"], 2), "lon": round(x["longitude"], 2),
            "t": round(x["temp"], 1) if x["temp"] is not None else None,
            "s": round(x["psal"], 1) if x["psal"] is not None else None,
            "d": 2000, "st": "active", "time": x["time"],
        })
    return out[:150]

@app.get("/api/floats")
def floats():
    if _cache["data"] and time.time() - _cache["t"] < 3600:
        return jsonify(floats=_cache["data"], source="argo-erddap (cached)")
    try:
        data = fetch_argo()
        if not data:
            raise ValueError("empty")
        _cache.update(t=time.time(), data=data)
        return jsonify(floats=data, source="argo-erddap")
    except Exception as e:
        app.logger.warning("Argo fetch failed: %s", e)
        return jsonify(floats=SAMPLE, source="sample")

# ---------------- chatbot ----------------
LANGS = {"en-IN": "English", "hi-IN": "Hindi", "ta-IN": "Tamil", "te-IN": "Telugu",
         "kn-IN": "Kannada", "ml-IN": "Malayalam", "bn-IN": "Bengali", "mr-IN": "Marathi"}

def fallback_answer(q):
    s = q.lower()
    if any(k in s for k in ("fish", "pfz", "மீன்", "मछली")):
        return "Potential Fishing Zones are strongest where SST is 27-29 °C with high chlorophyll. Check the latest INCOIS PFZ advisory before going to sea."
    if any(k in s for k in ("argo", "float")):
        return "Argo floats drift at ~1000 m, dive to 2000 m, then rise every ~10 days and send temperature and salinity data by satellite."
    return "I can help with Argo floats, sea temperature, depth and fishing zones."

@app.post("/api/chat")
def chat():
    d = request.get_json(force=True)
    q, lang = (d.get("q") or "").strip()[:1000], LANGS.get(d.get("lang"), "English")
    if not q:
        return jsonify(answer="Please type a question."), 400
    if not ANTHROPIC_KEY:
        return jsonify(answer=fallback_answer(q))
    system = (f"You are the Argo Assistant for an INCOIS Argo float dashboard in India. "
              f"Answer in {lang}, in 3-4 short sentences, in simple words for fishermen and students. "
              "Topics: Argo floats, Indian Ocean temperature/salinity, monsoon, fishing zones. "
              "For fishing or safety decisions, tell the user to check official INCOIS advisories. "
              "Do not invent live data; if you don't have it, say so.")
    try:
        r = requests.post("https://api.anthropic.com/v1/messages", timeout=30,
            headers={"x-api-key": ANTHROPIC_KEY, "anthropic-version": "2023-06-01", "content-type": "application/json"},
            json={"model": os.environ.get("CLAUDE_MODEL", "claude-sonnet-4-6"), "max_tokens": 400,
                  "system": system, "messages": [{"role": "user", "content": q}]})
        r.raise_for_status()
        return jsonify(answer=r.json()["content"][0]["text"])
    except Exception as e:
        app.logger.warning("chat failed: %s", e)
        return jsonify(answer=fallback_answer(q))

# ---------------- pages ----------------
@app.get("/")
def index():
    return send_from_directory("static", "index.html")

@app.get("/api/config")
def config():
    return jsonify(google_client_id=GOOGLE_CLIENT_ID)

@app.get("/api/health")
def health():
    return jsonify(ok=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 7860)))