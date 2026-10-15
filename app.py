"""Plateau State Specialist Hospital: Flask application.

Run:  python app.py      then open http://127.0.0.1:5000
"""
import os
import re
import secrets
import shutil
import sqlite3
import time
from datetime import date, datetime, timedelta
from functools import wraps
from urllib.parse import urlparse

from flask import (Flask, abort, flash, g, jsonify, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, "hospital.db")


def organise_files():
    """If every file was downloaded into ONE folder, sort them into templates/ and static/.

    Flask only finds pages in templates/ and CSS, JS and images in static/.
    This makes the first run work even when the files arrive unsorted.
    """
    images = os.path.join("static", "images")
    where = {".html": "templates", ".css": os.path.join("static", "css"), ".js": os.path.join("static", "js"),
             ".png": images, ".webp": images, ".jpg": images, ".jpeg": images}
    for name in os.listdir(BASE_DIR):
        src = os.path.join(BASE_DIR, name)
        folder = where.get(os.path.splitext(name)[1].lower())
        if not folder or not os.path.isfile(src):
            continue
        target = os.path.join(BASE_DIR, folder)
        os.makedirs(target, exist_ok=True)
        if not os.path.exists(os.path.join(target, name)):
            shutil.move(src, os.path.join(target, name))
            print(f"Sorted {name} -> {folder}")
    if not os.path.exists(os.path.join(BASE_DIR, "templates", "base.html")):
        raise SystemExit("base.html was not found. Put all the project files in the same folder as app.py.")
    needed = ["logo.png", "doctor-patient.webp", "doctors-pair.webp", "plateau-team.webp", "doctor-baby.webp"]
    missing = [n for n in needed if not os.path.exists(os.path.join(BASE_DIR, images, n))]
    if missing:
        print("WARNING: these pictures are missing from static/images:", ", ".join(missing))


organise_files()


def _secret_key():
    """Use SECRET_KEY from the environment, else create one and keep it in .secret_key."""
    if os.environ.get("SECRET_KEY"):
        return os.environ["SECRET_KEY"]
    path = os.path.join(BASE_DIR, ".secret_key")
    if not os.path.exists(path):
        with open(path, "w") as fh:
            fh.write(secrets.token_hex(32))
    with open(path) as fh:
        return fh.read().strip()


app = Flask(__name__)
app.config.update(
    SECRET_KEY=_secret_key(),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("HTTPS") == "1",   # set HTTPS=1 when served over https
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),
    MAX_CONTENT_LENGTH=64 * 1024,
)

# ----------------------------------------------------------------- site data
DEPARTMENTS = ["General Medicine", "Internal Medicine", "Pediatrics", "Not sure"]
ANY_DOCTOR = "Any available doctor"
TIMES = ["Morning", "Afternoon"]
# crop = horizontal offset (px) used to cut one doctor out of a shared photo; None = normal photo
DOCTORS = [
    {"name": "Dr. Mike", "department": "General Medicine", "role": "Senior Doctor",
     "credentials": ["MSc", "MBBS"], "image": "doctors-pair.webp", "crop": -47,
     "blurb": "Everyday illness, check-ups and referrals to the right specialist."},
    {"name": "Dr. Racheal", "department": "Internal Medicine", "role": None,
     "credentials": [], "image": "doctors-pair.webp", "crop": -156,
     "blurb": "Diagnosis and long-term care for adults."},
    {"name": "Dr. Daniel", "department": "Pediatrics", "role": None,
     "credentials": [], "image": "doctor-baby.webp", "crop": None,
     "blurb": "Care for babies and children, from check-ups to illness."},
]
DOCTOR_NAMES = [ANY_DOCTOR] + [d["name"] for d in DOCTORS]

# ------------------------------------------------------------------ database
SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL, email TEXT NOT NULL UNIQUE, phone TEXT NOT NULL,
    password_hash TEXT NOT NULL, created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS appointments(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    name TEXT NOT NULL, phone TEXT NOT NULL, email TEXT,
    department TEXT NOT NULL, doctor TEXT NOT NULL,
    visit_date TEXT NOT NULL, visit_time TEXT NOT NULL, reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Requested', created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS messages(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL, email TEXT NOT NULL, kind TEXT NOT NULL,
    message TEXT NOT NULL, created TEXT NOT NULL);
"""


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    with sqlite3.connect(DATABASE) as db:
        db.executescript(SCHEMA)


def now():
    return datetime.utcnow().isoformat(timespec="seconds")


# ------------------------------------------------------------------ security
def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]


def wants_json():
    return request.is_json or request.accept_mimetypes.best == "application/json"


@app.before_request
def prepare_request():
    g.nonce = secrets.token_urlsafe(16)
    if request.method == "POST":
        sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token") or ""
        if not secrets.compare_digest(sent.encode(), session.get("_csrf", "").encode()):
            abort(400, "Your session expired. Refresh the page and try again.")


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; font-src https://fonts.gstatic.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        f"script-src 'self' 'nonce-{g.get('nonce', '')}'; form-action 'self'; "
        "frame-ancestors 'none'; base-uri 'self'")
    return resp


@app.errorhandler(400)
def bad_request(err):
    if wants_json():
        return jsonify(ok=False, message=err.description), 400
    flash(err.description, "err")
    return redirect(request.referrer or url_for("home"))


def safe_next(target, default=None):
    """Only allow redirects to a path on this site (stops open-redirect tricks)."""
    default = default or url_for("home")
    if not target or "\\" in target:
        return default
    p = urlparse(target)
    return target if not p.scheme and not p.netloc and target.startswith("/") and not target.startswith("//") else default


# ---------------------------------------------------------------------- auth
@app.context_processor
def inject_globals():
    uid = session.get("user_id")
    user = None
    if uid:
        user = get_db().execute("SELECT id, name, email, phone FROM users WHERE id = ?", (uid,)).fetchone()
        if user is None:
            session.pop("user_id", None)
    return {"current_user": user, "csrf_token": csrf_token, "nonce": g.get("nonce", ""),
            "book_url": url_for("home") + "#booking-panel"}


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            login = url_for("login", next=request.full_path.rstrip("?") if request.method == "GET" else url_for("home") + "#booking-panel")
            if wants_json():
                return jsonify(ok=False, login=login, message="Please log in to continue."), 401
            flash("Please log in to continue.", "err")
            return redirect(login)
        return view(*args, **kwargs)
    return wrapped


_attempts = {}   # (ip, email) -> [timestamps]; resets when the app restarts


def too_many_attempts(key, limit=5, window=600):
    stamps = [t for t in _attempts.get(key, []) if time.time() - t < window]
    _attempts[key] = stamps
    return len(stamps) >= limit


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
DUMMY_HASH = generate_password_hash("not-a-real-password")


def clean_phone(value):
    digits = re.sub(r"[\s\-()]", "", value or "")
    return digits if re.fullmatch(r"\+?\d{7,15}", digits) else None


@app.route("/register", methods=["GET", "POST"])
def register():
    nxt = request.values.get("next", "")
    if request.method == "POST":
        f = request.form
        name, email, phone = f.get("name", "").strip(), f.get("email", "").strip().lower(), clean_phone(f.get("phone"))
        password, error = f.get("password", ""), None
        if len(name) < 2 or len(name) > 80:
            error = "Please enter your full name."
        elif not EMAIL_RE.match(email) or len(email) > 120:
            error = "Please enter a valid email address."
        elif not phone:
            error = "Please enter a valid phone number."
        elif len(password) < 8:
            error = "Your password must be at least 8 characters."
        elif password != f.get("confirm", ""):
            error = "Passwords do not match."
        elif not f.get("terms"):
            error = "Please agree to the terms to continue."
        if not error:
            try:
                db = get_db()
                cur = db.execute("INSERT INTO users(name, email, phone, password_hash, created) VALUES(?,?,?,?,?)",
                                 (name, email, phone, generate_password_hash(password), now()))
                db.commit()
            except sqlite3.IntegrityError:
                error = "That email is already registered. Try logging in."
            else:
                session.clear()
                session["user_id"] = cur.lastrowid
                flash(f"Welcome, {name}. Your account is ready.", "ok")
                return redirect(safe_next(nxt, url_for("home") + "#booking-panel"))
        flash(error, "err")
        return render_template("register.html", form=f, next=nxt), 400
    return render_template("register.html", form={}, next=nxt)


@app.route("/login", methods=["GET", "POST"])
def login():
    nxt = request.values.get("next", "")
    if request.method == "POST":
        email, password = request.form.get("email", "").strip().lower(), request.form.get("password", "")
        key = (request.remote_addr, email)
        if too_many_attempts(key):
            flash("Too many attempts. Please wait ten minutes and try again.", "err")
            return render_template("login.html", form=request.form, next=nxt), 429
        user = get_db().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        ok = check_password_hash(user["password_hash"] if user else DUMMY_HASH, password)
        if user and ok:
            _attempts.pop(key, None)
            session.clear()
            session["user_id"] = user["id"]
            session.permanent = bool(request.form.get("remember"))
            return redirect(safe_next(nxt, url_for("home") + "#booking-panel"))
        _attempts.setdefault(key, []).append(time.time())
        flash("Incorrect email or password.", "err")
        return render_template("login.html", form=request.form, next=nxt), 401
    if session.get("user_id"):
        return redirect(safe_next(nxt))
    return render_template("login.html", form={}, next=nxt)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "ok")
    return redirect(url_for("home"))


# --------------------------------------------------------------------- pages
@app.route("/")
def home():
    return render_template("index.html", doctors=DOCTORS, departments=DEPARTMENTS,
                           doctor_names=DOCTOR_NAMES, times=TIMES,
                           login_url=url_for("login", next=url_for("home") + "#booking-panel"))


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/appointments")
@login_required
def appointments():
    rows = get_db().execute("SELECT * FROM appointments WHERE user_id = ? ORDER BY visit_date DESC, id DESC",
                            (session["user_id"],)).fetchall()
    return render_template("appointments.html", rows=rows)


@app.template_filter("pretty_date")
def pretty_date(value):
    try:
        return datetime.strptime(value, "%Y-%m-%d").strftime("%a %d %b %Y")
    except (TypeError, ValueError):
        return value


# ------------------------------------------------------------ form endpoints
def respond(ok, message, status=200, redirect_to=None):
    if wants_json():
        return jsonify(ok=ok, message=message), status
    flash(message, "ok" if ok else "err")
    return redirect(redirect_to or request.referrer or url_for("home"))


@app.route("/book", methods=["POST"])
@login_required
def book():
    f = request.form
    name, phone, email = f.get("name", "").strip(), clean_phone(f.get("phone")), f.get("email", "").strip().lower()
    dept, doctor, slot = f.get("department", ""), f.get("doctor", ANY_DOCTOR), f.get("time", "")
    reason = f.get("reason", "").strip()
    try:
        visit = date.fromisoformat(f.get("date", ""))
    except ValueError:
        visit = None
    if len(name) < 2 or not phone:
        return respond(False, "Please enter your name and a valid phone number.", 400)
    if email and not EMAIL_RE.match(email):
        return respond(False, "That email address does not look right.", 400)
    if dept not in DEPARTMENTS or doctor not in DOCTOR_NAMES or slot not in TIMES:
        return respond(False, "Please choose a department, doctor and time from the lists.", 400)
    if not visit or not date.today() <= visit <= date.today() + timedelta(days=180):
        return respond(False, "Please choose a date within the next six months.", 400)
    if not 3 <= len(reason) <= 1000:
        return respond(False, "Please tell us briefly why you are visiting.", 400)
    db = get_db()
    open_count = db.execute("SELECT COUNT(*) FROM appointments WHERE user_id = ? AND status = 'Requested'",
                            (session["user_id"],)).fetchone()[0]
    if open_count >= 5:
        return respond(False, "You already have five open requests. Please wait for us to confirm them.", 429)
    db.execute("""INSERT INTO appointments(user_id, name, phone, email, department, doctor, visit_date,
                  visit_time, reason, created) VALUES(?,?,?,?,?,?,?,?,?,?)""",
               (session["user_id"], name, phone, email or None, dept, doctor, visit.isoformat(), slot, reason, now()))
    db.commit()
    return respond(True, "Thank you. Your request is in. We will confirm your time by phone or email.",
                   redirect_to=url_for("appointments"))


@app.route("/message", methods=["POST"])
def send_message():
    f = request.form
    name, email, kind, text = f.get("name", "").strip(), f.get("email", "").strip().lower(), f.get("type", ""), f.get("message", "").strip()
    if len(name) < 2 or not EMAIL_RE.match(email):
        return respond(False, "Please enter your name and a valid email.", 400, url_for("home") + "#contact")
    if kind not in ("Complaint", "Enquiry", "Feedback", "Compliment") or not 5 <= len(text) <= 2000:
        return respond(False, "Please write your message (at least a few words).", 400, url_for("home") + "#contact")
    key = (request.remote_addr, "message")
    if too_many_attempts(key, limit=3):
        return respond(False, "You have sent several messages. Please try again later.", 429, url_for("home") + "#contact")
    _attempts.setdefault(key, []).append(time.time())
    db = get_db()
    db.execute("INSERT INTO messages(name, email, kind, message, created) VALUES(?,?,?,?,?)", (name, email, kind, text, now()))
    db.commit()
    return respond(True, "Thank you. We have received your message and will follow up.",
                   redirect_to=url_for("home") + "#contact")


init_db()

if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", 5000)),
            debug=os.environ.get("FLASK_DEBUG") == "1")
