"""AQUA DEEP backend: Flask + SQLite.
Serves the dashboard and these APIs:
  POST /api/signup   POST /api/login   POST /api/google
  GET  /api/floats   POST /api/chat
"""
import os, time, sqlite3
from datetime import datetime, timedelta, timezone
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
    return auth_resp(uid, name, email)

@app.post("/api/login")
def login():
    d = request.get_json(force=True)
    email, pw = (d.get("email") or "").strip().lower(), d.get("password") or ""
    u = get_user(email)
    if not u or not u["pw"] or not check_password_hash(u["pw"], pw):
        return jsonify(error="Wrong email or password."), 401
    return auth_resp(u["id"], u["name"], u["email"])

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
    return auth_resp(uid, name, email)

# ---------------- generic SQL helper (SQLite or Postgres) ----------------
def run(sql, p=None, fetch=False):
    p = p or {}
    if URL:
        with engine.begin() as c:
            r = c.execute(text(sql), p)
            return [dict(x) for x in r.mappings().all()] if fetch else None
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    try:
        cur = c.execute(sql, p)
        rows = [dict(x) for x in cur.fetchall()] if fetch else None
        c.commit()
        return rows
    finally:
        c.close()

_pk = "SERIAL PRIMARY KEY" if URL else "INTEGER PRIMARY KEY AUTOINCREMENT"
run(f"CREATE TABLE IF NOT EXISTS alerts(id {_pk}, level TEXT, title TEXT, body TEXT, created TEXT)")
run("CREATE TABLE IF NOT EXISTS favorites(user_id INTEGER, float_id TEXT, PRIMARY KEY(user_id, float_id))")

# Admins are chosen by email: set ADMIN_EMAILS="you@example.com,other@example.com"
ADMINS = [e.strip().lower() for e in os.environ.get("ADMIN_EMAILS", "").split(",") if e.strip()]

def auth_resp(uid, name, email):
    admin = (email or "").lower() in ADMINS
    token = signer.dumps({"id": uid, "name": name, "admin": admin})
    return jsonify(token=token, name=name, admin=admin)

def admin_only():
    u = current_user()
    return u if (u and u.get("admin")) else None

# ---------------- alerts + admin ----------------
@app.get("/api/alerts")
def alerts_list():
    return jsonify(alerts=run("SELECT id,level,title,body,created FROM alerts ORDER BY id DESC LIMIT 50", fetch=True))

@app.post("/api/alerts")
def alerts_add():
    if not admin_only():
        return jsonify(error="Admin only"), 403
    d = request.get_json(force=True)
    title = (d.get("title") or "").strip()[:200]
    if not title:
        return jsonify(error="Title required"), 400
    level = d.get("level") if d.get("level") in ("info", "warning", "danger") else "info"
    run("INSERT INTO alerts(level,title,body,created) VALUES(:l,:t,:b,:c)",
        {"l": level, "t": title, "b": (d.get("body") or "")[:1000], "c": time.strftime("%Y-%m-%d %H:%M")})
    return jsonify(ok=True)

@app.delete("/api/alerts/<int:aid>")
def alerts_del(aid):
    if not admin_only():
        return jsonify(error="Admin only"), 403
    run("DELETE FROM alerts WHERE id=:i", {"i": aid})
    return jsonify(ok=True)

@app.get("/api/admin/users")
def admin_users():
    if not admin_only():
        return jsonify(error="Admin only"), 403
    return jsonify(users=run("SELECT id,name,email FROM users ORDER BY id", fetch=True))

# ---------------- favourite floats (per user) ----------------
@app.get("/api/favorites")
def fav_list():
    u = current_user()
    if not u:
        return jsonify(error="Login required"), 401
    rows = run("SELECT float_id FROM favorites WHERE user_id=:u", {"u": u["id"]}, fetch=True)
    return jsonify(favorites=[r["float_id"] for r in rows])

@app.post("/api/favorites")
def fav_add():
    u = current_user()
    if not u:
        return jsonify(error="Login required"), 401
    fid = str(request.get_json(force=True).get("float_id") or "")[:20]
    if not fid:
        return jsonify(error="float_id required"), 400
    run("INSERT INTO favorites(user_id,float_id) VALUES(:u,:f) ON CONFLICT DO NOTHING", {"u": u["id"], "f": fid})
    return jsonify(ok=True)

@app.delete("/api/favorites")
def fav_del():
    u = current_user()
    if not u:
        return jsonify(error="Login required"), 401
    run("DELETE FROM favorites WHERE user_id=:u AND float_id=:f", {"u": u["id"], "f": request.args.get("float_id", "")})
    return jsonify(ok=True)

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

def _parse_time(t):
    try:
        return datetime.fromisoformat(str(t).replace("Z", "+00:00"))
    except Exception:
        return None

def fetch_argo():
    """Recent Argo floats (last 10 days, Indian Ocean box) from Ifremer ERDDAP.
    depth = deepest pressure (dbar ~ metres) reached in the window.
    status: surfaced = reported within 24 h, deep = reached >= 1500, else active."""
    base = ('&time>=now-10days&latitude>=-40&latitude<=25&longitude>=40&longitude<=100')
    q1 = ('?platform_number,time,latitude,longitude,pres,temp,psal' + base +
          '&pres<=10&orderByMax("platform_number,time")')
    r = requests.get(ERDDAP + q1, timeout=25)
    r.raise_for_status()
    t = r.json()["table"]
    cols = t["columnNames"]
    depth = {}
    try:
        q2 = '?platform_number,pres' + base + '&orderByMax("platform_number,pres")'
        r2 = requests.get(ERDDAP + q2, timeout=25)
        r2.raise_for_status()
        t2 = r2.json()["table"]
        c2 = t2["columnNames"]
        for row in t2["rows"]:
            x = dict(zip(c2, row))
            if x.get("pres") is not None:
                depth[str(x["platform_number"])] = round(x["pres"])
    except Exception as e:
        app.logger.warning("Argo depth query failed: %s", e)
    now = datetime.now(timezone.utc)
    out = []
    for row in t["rows"]:
        x = dict(zip(cols, row))
        if x["latitude"] is None or x["longitude"] is None:
            continue
        fid = str(x["platform_number"])
        d = depth.get(fid)
        tm = _parse_time(x["time"])
        if tm and tm.tzinfo and (now - tm) <= timedelta(hours=24):
            st = "surfaced"
        elif d and d >= 1500:
            st = "deep"
        else:
            st = "active"
        out.append({
            "id": fid, "lat": round(x["latitude"], 2), "lon": round(x["longitude"], 2),
            "t": round(x["temp"], 1) if x["temp"] is not None else None,
            "s": round(x["psal"], 1) if x["psal"] is not None else None,
            "d": d, "st": st, "time": x["time"],
        })
    return out[:150]

@app.get("/api/floats")
def floats():
    if _cache["data"] and time.time() - _cache["t"] < 3600:
        return jsonify(floats=_cache["data"], source="argo-erddap", updated=_cache.get("updated"))
    try:
        data = fetch_argo()
        if not data:
            raise ValueError("empty")
        updated = max((x.get("time") or "") for x in data) or None
        _cache.update(t=time.time(), data=data, updated=updated)
        return jsonify(floats=data, source="argo-erddap", updated=updated)
    except Exception as e:
        app.logger.warning("Argo fetch failed: %s", e)
        return jsonify(floats=SAMPLE, source="sample", updated=None)

@app.get("/api/trajectory/<fid>")
def trajectory(fid):
    """Past positions of one float (last 90 days) from Argo ERDDAP. Empty list if unavailable."""
    if not fid.isdigit():
        return jsonify(points=[]), 400
    try:
        q = '?time,latitude,longitude&platform_number="%s"&time>=now-90days&orderBy("time")' % fid
        r = requests.get(ERDDAP + q, timeout=25)
        r.raise_for_status()
        pts, seen = [], set()
        for _t, la, lo in r.json()["table"]["rows"]:
            if la is None or lo is None:
                continue
            k = (round(la, 2), round(lo, 2))
            if k not in seen:
                seen.add(k)
                pts.append(list(k))
        return jsonify(points=pts[-120:])
    except Exception as e:
        app.logger.warning("trajectory failed: %s", e)
        return jsonify(points=[])

# ---------------- chatbot ----------------
LANGS = {"en-IN": "English", "hi-IN": "Hindi", "ta-IN": "Tamil", "te-IN": "Telugu",
         "kn-IN": "Kannada", "ml-IN": "Malayalam", "bn-IN": "Bengali", "mr-IN": "Marathi"}

REPLIES = {
    "fish": {
        "en": "Potential Fishing Zones are strongest where SST is 27-29 °C with high chlorophyll. Check the latest INCOIS PFZ advisory before going to sea.",
        "ta": "மீன்பிடி மண்டலங்கள் பொதுவாக கடல் மேற்பரப்பு வெப்பநிலை 27–29 °C மற்றும் குளோரோபில் அதிகமாக உள்ள இடங்களில் சிறப்பாக இருக்கும். கடலுக்குச் செல்லும் முன் INCOIS-ன் சமீபத்திய PFZ அறிவுரையைப் பார்க்கவும்.",
        "hi": "मछली पकड़ने के क्षेत्र आमतौर पर वहाँ अच्छे होते हैं जहाँ समुद्री सतह का तापमान 27–29 °C और क्लोरोफिल अधिक हो। समुद्र में जाने से पहले INCOIS की ताज़ा PFZ सलाह देखें।"},
    "temp": {
        "en": "Indian Ocean surface water is usually 27-29 °C and gets colder with depth. The temperature drops fastest in the thermocline, roughly 50-150 m down. Open the float map to see the latest temperature at each Argo float.",
        "ta": "இந்தியப் பெருங்கடலின் மேற்பரப்பு நீர் பொதுவாக 27–29 °C இருக்கும்; ஆழம் செல்லச் செல்ல குளிர்ச்சியாகும். வெப்பநிலை மிக வேகமாகக் குறையும் அடுக்கு (தெர்மோக்லைன்) சுமார் 50–150 மீ ஆழத்தில் உள்ளது. ஒவ்வொரு ஆர்கோ மிதவையின் சமீபத்திய வெப்பநிலையைப் பார்க்க வரைபடத்தைத் திறக்கவும்.",
        "hi": "हिंद महासागर की सतह का पानी आमतौर पर 27–29 °C होता है और गहराई के साथ ठंडा होता जाता है। तापमान सबसे तेज़ी से थर्मोक्लाइन में गिरता है, जो लगभग 50–150 मीटर गहराई पर होता है। हर आर्गो फ्लोट का ताज़ा तापमान देखने के लिए नक्शा खोलें।"},
    "depth": {
        "en": "Argo floats usually measure down to about 2000 m. Click a float on the map to see its depth.",
        "ta": "ஆர்கோ மிதவைகள் பொதுவாக சுமார் 2000 மீ ஆழம் வரை அளவிடுகின்றன. ஒரு மிதவையின் ஆழத்தைப் பார்க்க வரைபடத்தில் அதைக் கிளிக் செய்யுங்கள்.",
        "hi": "आर्गो फ्लोट आमतौर पर लगभग 2000 मीटर की गहराई तक माप लेते हैं। किसी फ्लोट की गहराई देखने के लिए नक्शे पर उस पर क्लिक करें।"},
    "argo": {
        "en": "Argo floats drift at ~1000 m, dive to 2000 m, then rise every ~10 days and send temperature and salinity data by satellite.",
        "ta": "ஆர்கோ மிதவைகள் சுமார் 1000 மீ ஆழத்தில் மிதந்து, 2000 மீ வரை இறங்கி, சுமார் 10 நாட்களுக்கு ஒருமுறை மேலே வந்து வெப்பநிலை, உப்புத்தன்மை தரவை செயற்கைக்கோள் வழியாக அனுப்புகின்றன.",
        "hi": "आर्गो फ्लोट लगभग 1000 मीटर की गहराई पर बहते हैं, 2000 मीटर तक जाते हैं और लगभग हर 10 दिन में सतह पर आकर तापमान और लवणता का डेटा उपग्रह से भेजते हैं।"},
    "default": {
        "en": "I can help with Argo floats, sea temperature, depth and fishing zones.",
        "ta": "ஆர்கோ மிதவைகள், கடல் வெப்பநிலை, ஆழம், மீன்பிடி மண்டலங்கள் பற்றி நான் உதவ முடியும்.",
        "hi": "मैं आर्गो फ्लोट, समुद्री तापमान, गहराई और मछली क्षेत्र के बारे में मदद कर सकता हूँ।"},
}
KEYS = [
    ("fish", ("fish", "pfz", "மீன்", "मछली")),
    ("temp", ("temp", "sst", "thermocline", "வெப்ப", "तापमान")),
    ("depth", ("depth", "ஆழம்", "गहराई")),
    ("argo", ("argo", "float", "position", "மிதவை", "फ्लोट", "आर्गो")),
]

def script_lang(text):
    """If the question is written in Tamil or Devanagari script, answer in that language."""
    for ch in text:
        if "\u0b80" <= ch <= "\u0bff":
            return "ta"
        if "\u0900" <= ch <= "\u097f":
            return "hi"
    return None

def fallback_answer(q, code="en-IN"):
    """Keyword replies used when no ANTHROPIC_API_KEY is set. Answers in the selected language."""
    lang = script_lang(q) or (code or "en-IN")[:2]
    if lang not in ("ta", "hi"):
        lang = "en"
    s = q.lower()
    for name, words in KEYS:
        if any(w in s for w in words):
            return REPLIES[name][lang]
    return REPLIES["default"][lang]

@app.post("/api/chat")
def chat():
    d = request.get_json(force=True)
    q, lang = (d.get("q") or "").strip()[:1000], LANGS.get(d.get("lang"), "English")
    sl = script_lang(q)
    if sl:
        lang = {"ta": "Tamil", "hi": "Hindi"}[sl]
    if not q:
        return jsonify(answer="Please type a question."), 400
    if not ANTHROPIC_KEY:
        return jsonify(answer=fallback_answer(q, d.get("lang")))
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
        return jsonify(answer=fallback_answer(q, d.get("lang")))

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
