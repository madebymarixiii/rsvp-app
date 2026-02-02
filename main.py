import csv
import io
import json
import os
import sqlite3
import time
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, send_file, g, abort, jsonify
)
from flask_login import (
    LoginManager, login_user, login_required, logout_user,
    UserMixin, current_user
)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeSerializer, BadSignature


# =========================
# CONFIG
# =========================
APP_SECRET = os.environ.get("APP_SECRET", "dev-secret-change-me")
DATABASE_URL = os.environ.get("DATABASE_URL")  # Railway Postgres sets this
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")  # platform admin


# =========================
# Safari iframe fix: Token-based RSVP (NO cookies needed)
# =========================
def _tok(secret: str):
    return URLSafeSerializer(secret, salt="rsvp-guest-v1")


def make_token(secret: str, client_id: int, guest_id: int) -> str:
    return _tok(secret).dumps({"cid": int(client_id), "gid": int(guest_id)})


def read_token(secret: str, token: str):
    return _tok(secret).loads(token)


# =========================
# 3 tries lock (session-less), keyed by (slug + ip)
# =========================
_RSVP_TRIES = {}  # key -> {"count":int, "locked_until":float}
LOCK_MINUTES = 5
MAX_TRIES = 3


def _client_ip():
    return (
        (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
        or request.headers.get("X-Real-IP")
        or request.remote_addr
        or "unknown"
    )


def _tries_key(slug: str) -> str:
    return f"{slug}:{_client_ip()}"


def check_lock(slug: str):
    key = _tries_key(slug)
    rec = _RSVP_TRIES.get(key)
    now = time.time()
    if rec and rec.get("locked_until", 0) > now:
        mins = int((rec["locked_until"] - now + 59) // 60)
        return True, mins
    return False, 0


def bump_try(slug: str):
    key = _tries_key(slug)
    rec = _RSVP_TRIES.get(key, {"count": 0, "locked_until": 0})
    rec["count"] += 1
    if rec["count"] >= MAX_TRIES:
        rec["locked_until"] = time.time() + LOCK_MINUTES * 60
        rec["count"] = 0
    _RSVP_TRIES[key] = rec


def attempts_left(slug: str) -> int:
    key = _tries_key(slug)
    rec = _RSVP_TRIES.get(key, {"count": 0, "locked_until": 0})
    if rec.get("locked_until", 0) > time.time():
        return 0
    return max(0, MAX_TRIES - int(rec.get("count", 0)))


def reset_tries(slug: str):
    _RSVP_TRIES.pop(_tries_key(slug), None)


# =========================
# Flask App
# =========================
app = Flask(__name__)
app.secret_key = APP_SECRET

# Trust Railway proxy headers (HTTPS awareness)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Client dashboard/login uses cookies.
# (RSVP is token-based so it still works even if Safari blocks cookies in iframes)
app.config.update(
    SESSION_COOKIE_SAMESITE="None",
    SESSION_COOKIE_SECURE=True,
)

login_manager = LoginManager(app)
login_manager.login_view = "login"


# =========================
# DB Abstraction: SQLite (local) or Postgres (Railway)
# =========================
def using_postgres() -> bool:
    return bool(DATABASE_URL) and DATABASE_URL.startswith("postgres")


def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d


class DBWrapSQLite:
    def __init__(self, conn):
        self.conn = conn

    def execute(self, sql, params=None):
        cur = self.conn.cursor()
        cur.execute(sql, params or ())
        return cur

    def commit(self):
        self.conn.commit()

    def rollback(self):
        self.conn.rollback()

    def close(self):
        self.conn.close()


class CursorWrapPG:
    def __init__(self, cur):
        self.cur = cur

    def fetchone(self):
        row = self.cur.fetchone()
        self.cur.close()
        return row

    def fetchall(self):
        rows = self.cur.fetchall()
        self.cur.close()
        return rows


class DBWrapPG:
    def __init__(self, conn):
        self.conn = conn

    def execute(self, sql, params=None):
        sql = sql.replace("?", "%s")
        cur = self.conn.cursor()
        cur.execute(sql, params or ())
        return CursorWrapPG(cur)

    def commit(self):
        self.conn.commit()

    def rollback(self):
        self.conn.rollback()

    def close(self):
        self.conn.close()


def get_db():
    if "db" in g:
        return g.db

    if using_postgres():
        import psycopg2
        from psycopg2.extras import RealDictCursor
        conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
        g.db = DBWrapPG(conn)
        return g.db

    conn = sqlite3.connect("local.db")
    conn.row_factory = dict_factory
    conn.execute("PRAGMA foreign_keys = ON;")
    g.db = DBWrapSQLite(conn)
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


# =========================
# DB Init
# =========================
def init_db():
    con = get_db()

    if using_postgres():
        con.execute("""
            CREATE TABLE IF NOT EXISTS clients (
                id SERIAL PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                slug TEXT UNIQUE NOT NULL,
                display_name TEXT DEFAULT ''
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS guests (
                id SERIAL PRIMARY KEY,
                client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
                first_name TEXT NOT NULL,
                last_name TEXT NOT NULL,
                seats INTEGER NOT NULL DEFAULT 1,
                UNIQUE(client_id, first_name, last_name)
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS questions (
                id SERIAL PRIMARY KEY,
                client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
                label TEXT NOT NULL,
                field_type TEXT NOT NULL DEFAULT 'text',
                options_json TEXT NOT NULL DEFAULT '[]'
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS rsvps (
                id SERIAL PRIMARY KEY,
                guest_id INTEGER NOT NULL UNIQUE REFERENCES guests(id) ON DELETE CASCADE,
                attending TEXT NOT NULL,
                dietary TEXT DEFAULT '',
                attendee_names_json TEXT NOT NULL DEFAULT '[]',
                answers_json TEXT NOT NULL DEFAULT '{}',
                updated_at TEXT NOT NULL
            )
        """)
        con.commit()
        return

    con.execute("""
        CREATE TABLE IF NOT EXISTS clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            slug TEXT UNIQUE NOT NULL,
            display_name TEXT DEFAULT ''
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS guests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id INTEGER NOT NULL,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            seats INTEGER NOT NULL DEFAULT 1,
            UNIQUE(client_id, first_name, last_name),
            FOREIGN KEY(client_id) REFERENCES clients(id) ON DELETE CASCADE
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS questions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id INTEGER NOT NULL,
            label TEXT NOT NULL,
            field_type TEXT NOT NULL DEFAULT 'text',
            options_json TEXT NOT NULL DEFAULT '[]',
            FOREIGN KEY(client_id) REFERENCES clients(id) ON DELETE CASCADE
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS rsvps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            guest_id INTEGER NOT NULL UNIQUE,
            attending TEXT NOT NULL,
            dietary TEXT DEFAULT '',
            attendee_names_json TEXT NOT NULL DEFAULT '[]',
            answers_json TEXT NOT NULL DEFAULT '{}',
            updated_at TEXT NOT NULL,
            FOREIGN KEY(guest_id) REFERENCES guests(id) ON DELETE CASCADE
        )
    """)
    con.commit()


# =========================
# Helpers
# =========================
def norm(s: str) -> str:
    return " ".join((s or "").strip().lower().split())


def titlecase_name(s: str) -> str:
    s = (s or "").strip()
    return s[:1].upper() + s[1:].lower() if s else ""


def is_embed() -> bool:
    return (request.args.get("embed") or "").strip().lower() in ("1", "true", "yes")


def get_theme() -> str:
    t = (request.args.get("theme") or request.form.get("theme") or "").strip().lower()
    return "dark" if t == "dark" else "light"


def is_admin():
    return bool(session.get("is_admin"))


def require_admin():
    if not is_admin():
        abort(403)


def client_by_slug(slug: str):
    con = get_db()
    return con.execute("SELECT * FROM clients WHERE slug = ?", (slug,)).fetchone()


def guest_lookup(client_id: int, first_name: str, last_name: str):
    con = get_db()
    return con.execute(
        """
        SELECT * FROM guests
        WHERE client_id = ?
          AND lower(trim(first_name)) = ?
          AND lower(trim(last_name))  = ?
        """,
        (client_id, norm(first_name), norm(last_name))
    ).fetchone()


def questions_for_client(client_id: int):
    con = get_db()
    rows = con.execute(
        "SELECT * FROM questions WHERE client_id=? ORDER BY id DESC",
        (client_id,)
    ).fetchall()

    out = []
    for r in rows:
        try:
            opts = json.loads((r.get("options_json") if isinstance(r, dict) else r["options_json"]) or "[]")
        except Exception:
            opts = []
        out.append({
            "id": r["id"],
            "label": r["label"],
            "field_type": r["field_type"],
            "options": opts
        })
    return out


# =========================
# Auth (clients)
# =========================
class User(UserMixin):
    def __init__(self, id_, email):
        self.id = str(id_)
        self.email = email


@login_manager.user_loader
def load_user(uid):
    con = get_db()
    row = con.execute("SELECT id,email FROM clients WHERE id=?", (uid,)).fetchone()
    if not row:
        return None
    return User(row["id"], row["email"])


@app.route("/", methods=["GET", "POST"])
def login():
    init_db()
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        pw = (request.form.get("password") or "").strip()  # ✅ helps mobile keyboards

        con = get_db()
        row = con.execute("SELECT * FROM clients WHERE email=?", (email,)).fetchone()
        if row and check_password_hash(row["password_hash"], pw):
            login_user(User(row["id"], row["email"]))
            return redirect(url_for("dashboard"))

        flash("Invalid login.")
    return render_template("login.html")


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    init_db()
    con = get_db()
    cid = int(current_user.id)

    client = con.execute("SELECT * FROM clients WHERE id=?", (cid,)).fetchone()

    rsvps = con.execute("""
        SELECT
            g.id as guest_id,
            g.first_name,
            g.last_name,
            g.seats,
            r.attending,
            r.dietary,
            r.attendee_names_json,
            r.answers_json,
            r.updated_at
        FROM guests g
        LEFT JOIN rsvps r ON r.guest_id=g.id
        WHERE g.client_id=?
        ORDER BY g.last_name, g.first_name
    """, (cid,)).fetchall()

    qs = questions_for_client(cid)

    guests = con.execute("SELECT id FROM guests WHERE client_id=?", (cid,)).fetchall()
    total = len(guests)
    responded = sum(1 for r in rsvps if r.get("attending") is not None)
    yes = sum(1 for r in rsvps if r.get("attending") == "yes")
    no = sum(1 for r in rsvps if r.get("attending") == "no")

    return render_template(
        "dashboard.html",
        client=client,
        rsvps=rsvps,
        questions=qs,
        stats={"total": total, "responded": responded, "yes": yes, "no": no},
    )


@app.route("/admin/add_guest", methods=["POST"])
@login_required
def admin_add_guest():
    con = get_db()
    cid = int(current_user.id)

    first = norm(request.form.get("first_name", ""))
    last = norm(request.form.get("last_name", ""))
    seats = int(request.form.get("seats", "1") or 1)
    seats = max(1, min(seats, 20))

    if not first or not last:
        flash("First name and last name are required.")
        return redirect(url_for("dashboard"))

    try:
        con.execute(
            "INSERT INTO guests(client_id, first_name, last_name, seats) VALUES(?,?,?,?)",
            (cid, first, last, seats)
        )
        con.commit()
        flash("Guest added.")
    except Exception:
        con.rollback()
        flash("Guest already exists (same first + last).")

    return redirect(url_for("dashboard"))


# ✅ Delete guest (client dashboard)
@app.route("/admin/delete_guest/<int:guest_id>", methods=["POST"])
@login_required
def admin_delete_guest(guest_id):
    init_db()
    con = get_db()
    cid = int(current_user.id)

    row = con.execute(
        "SELECT id, first_name, last_name FROM guests WHERE id=? AND client_id=?",
        (guest_id, cid)
    ).fetchone()

    if not row:
        flash("Guest not found.")
        return redirect(url_for("dashboard"))

    try:
        con.execute("DELETE FROM guests WHERE id=? AND client_id=?", (guest_id, cid))
        con.commit()
        flash(f"Removed guest: {row.get('first_name','')} {row.get('last_name','')}".strip())
    except Exception:
        con.rollback()
        flash("Failed to remove guest.")

    return redirect(url_for("dashboard"))


@app.route("/admin/import_guests", methods=["POST"])
@login_required
def admin_import_guests():
    file = request.files.get("csvfile")
    if not file:
        flash("No CSV uploaded.")
        return redirect(url_for("dashboard"))

    con = get_db()
    cid = int(current_user.id)

    content = file.stream.read().decode("utf-8", errors="ignore")
    reader = csv.DictReader(io.StringIO(content))

    added, skipped = 0, 0
    for row in reader:
        first = norm(row.get("first_name") or row.get("firstname") or row.get("first") or "")
        last = norm(row.get("last_name") or row.get("lastname") or row.get("last") or "")
        if not first or not last:
            skipped += 1
            continue

        try:
            seats = int(row.get("seats") or 1)
        except Exception:
            seats = 1
        seats = max(1, min(seats, 20))

        try:
            con.execute(
                "INSERT INTO guests(client_id, first_name, last_name, seats) VALUES(?,?,?,?)",
                (cid, first, last, seats)
            )
            added += 1
        except Exception:
            con.rollback()
            skipped += 1

    con.commit()
    flash(f"Imported: {added} added, {skipped} skipped.")
    return redirect(url_for("dashboard"))


@app.route("/admin/add_question", methods=["POST"])
@login_required
def admin_add_question():
    con = get_db()
    cid = int(current_user.id)

    label = (request.form.get("label") or "").strip()
    field_type = (request.form.get("field_type") or "text").strip()
    options = (request.form.get("options") or "").strip()

    if not label:
        flash("Question label is required.")
        return redirect(url_for("dashboard"))

    if field_type not in ("text", "textarea", "select"):
        field_type = "text"

    opts = []
    if field_type == "select":
        opts = [o.strip() for o in options.split(",") if o.strip()]
        if not opts:
            flash("Dropdown needs options (comma-separated).")
            return redirect(url_for("dashboard"))

    con.execute(
        "INSERT INTO questions(client_id, label, field_type, options_json) VALUES(?,?,?,?)",
        (cid, label, field_type, json.dumps(opts))
    )
    con.commit()
    flash("Question added.")
    return redirect(url_for("dashboard"))


@app.route("/admin/delete_question/<int:qid>", methods=["POST"])
@login_required
def admin_delete_question(qid):
    con = get_db()
    cid = int(current_user.id)
    con.execute("DELETE FROM questions WHERE id=? AND client_id=?", (qid, cid))
    con.commit()
    flash("Question deleted.")
    return redirect(url_for("dashboard"))


@app.route("/admin/export_guests")
@login_required
def admin_export_guests():
    con = get_db()
    cid = int(current_user.id)

    rows = con.execute(
        "SELECT first_name, last_name, seats FROM guests WHERE client_id=? ORDER BY last_name, first_name",
        (cid,)
    ).fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["first_name", "last_name", "seats"])
    for r in rows:
        writer.writerow([r["first_name"], r["last_name"], r["seats"]])

    mem = io.BytesIO(output.getvalue().encode("utf-8"))
    return send_file(mem, mimetype="text/csv", as_attachment=True, download_name="guests.csv")


@app.route("/admin/export_rsvps")
@login_required
def admin_export_rsvps():
    con = get_db()
    cid = int(current_user.id)

    qs = questions_for_client(cid)
    q_labels = [q["label"] for q in qs]

    rows = con.execute("""
        SELECT
            g.first_name, g.last_name, g.seats,
            r.attending, r.dietary, r.attendee_names_json, r.answers_json,
            r.updated_at
        FROM guests g
        LEFT JOIN rsvps r ON r.guest_id=g.id
        WHERE g.client_id=?
        ORDER BY g.last_name, g.first_name
    """, (cid,)).fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "first_name", "last_name", "reserved_seats",
        "attending", "dietary", "attendee_names",
        *q_labels,
        "updated_at"
    ])

    for r in rows:
        try:
            attendee_names = ", ".join(json.loads(r.get("attendee_names_json") or "[]"))
        except Exception:
            attendee_names = ""
        try:
            answers = json.loads(r.get("answers_json") or "{}")
        except Exception:
            answers = {}

        q_values = [answers.get(lbl, "") for lbl in q_labels]

        writer.writerow([
            r.get("first_name", ""),
            r.get("last_name", ""),
            r.get("seats", ""),
            (r.get("attending") or ""),
            (r.get("dietary") or ""),
            attendee_names,
            *q_values,
            (r.get("updated_at") or "")
        ])

    mem = io.BytesIO(output.getvalue().encode("utf-8"))
    return send_file(mem, mimetype="text/csv", as_attachment=True, download_name="rsvps.csv")


# =========================
# Public RSVP
# =========================

# ✅ First-name autocomplete (masked last initial)
@app.route("/rsvp/<slug>/suggest", methods=["GET"])
def rsvp_suggest(slug):
    init_db()
    con = get_db()

    client = client_by_slug(slug)
    if not client:
        return jsonify({"items": []}), 404

    q = (request.args.get("q") or "").strip()
    qn = norm(q)
    if len(qn) < 2:
        return jsonify({"items": []})

    qn = qn[:30]
    like = f"{qn}%"

    rows = con.execute("""
        SELECT first_name, last_name
        FROM guests
        WHERE client_id = ?
          AND lower(trim(first_name)) LIKE ?
        ORDER BY first_name, last_name
        LIMIT 8
    """, (client["id"], like)).fetchall()

    items = []
    for r in rows:
        fn = titlecase_name(r.get("first_name") or "")
        ln = (r.get("last_name") or "").strip()
        masked = (ln[:1].upper() + ".") if ln else ""
        label = (fn + (" " + masked if masked else "")).strip()
        items.append({"label": label, "first_name": fn})

    return jsonify({"items": items})


@app.route("/rsvp/<slug>", methods=["GET", "POST"])
def rsvp_lookup(slug):
    init_db()
    con = get_db()

    client = client_by_slug(slug)
    if not client:
        return "Wedding not found", 404

    embed = is_embed()
    theme = get_theme()

    locked, mins = check_lock(slug)
    if locked:
        return render_template(
            "rsvp_lookup.html",
            client=client,
            locked=True,
            mins=mins,
            embed=embed,
            theme=theme,
            error=f"Too many attempts. Try again in about {mins} minute(s).",
            first_name="",
            last_name="",
            attempts_left=0
        )

    error = None
    first_name = ""
    last_name = ""

    if request.method == "POST":
        first_name = (request.form.get("first_name") or "").strip()
        last_name = (request.form.get("last_name") or "").strip()

        guest = guest_lookup(client["id"], first_name, last_name)
        if not guest:
            bump_try(slug)
            locked2, mins2 = check_lock(slug)
            left = attempts_left(slug)

            if locked2:
                error = f"Too many attempts. Try again in about {mins2} minute(s)."
            else:
                error = f"Sorry — we can’t find your name. Attempts left: {left}"

            return render_template(
                "rsvp_lookup.html",
                client=client,
                locked=locked2,
                mins=mins2,
                embed=embed,
                theme=theme,
                error=error,
                first_name=first_name,
                last_name=last_name,
                attempts_left=left
            )

        reset_tries(slug)

        t = make_token(APP_SECRET, client["id"], guest["id"])
        return redirect(url_for(
            "rsvp_form",
            slug=slug,
            embed=("1" if embed else None),
            theme=theme,
            t=t
        ))

    return render_template(
        "rsvp_lookup.html",
        client=client,
        locked=False,
        mins=0,
        embed=embed,
        theme=theme,
        error=error,
        first_name=first_name,
        last_name=last_name,
        attempts_left=attempts_left(slug)
    )


@app.route("/rsvp/<slug>/form", methods=["GET", "POST"])
def rsvp_form(slug):
    init_db()
    con = get_db()

    client = client_by_slug(slug)
    if not client:
        return "Wedding not found", 404

    embed = is_embed()
    theme = get_theme()

    token = request.args.get("t") or request.form.get("t")
    if not token:
        return redirect(url_for("rsvp_lookup", slug=slug, embed=("1" if embed else None), theme=theme))

    try:
        data = read_token(APP_SECRET, token)
        cid_from_token = int(data["cid"])
        gid = int(data["gid"])
    except BadSignature:
        return redirect(url_for("rsvp_lookup", slug=slug, embed=("1" if embed else None), theme=theme))

    if cid_from_token != int(client["id"]):
        return redirect(url_for("rsvp_lookup", slug=slug, embed=("1" if embed else None), theme=theme))

    guest = con.execute(
        "SELECT * FROM guests WHERE id=? AND client_id=?",
        (gid, client["id"])
    ).fetchone()

    if not guest:
        return redirect(url_for("rsvp_lookup", slug=slug, embed=("1" if embed else None), theme=theme))

    qs = questions_for_client(client["id"])
    existing = con.execute("SELECT * FROM rsvps WHERE guest_id=?", (guest["id"],)).fetchone()

    existing_attending = existing["attending"] if existing else None
    existing_dietary = existing["dietary"] if existing else ""
    existing_attendees_all = []
    existing_answers = {}

    if existing:
        try:
            existing_attendees_all = json.loads(existing.get("attendee_names_json") or "[]")
        except Exception:
            existing_attendees_all = []
        try:
            existing_answers = json.loads(existing.get("answers_json") or "{}")
        except Exception:
            existing_answers = {}

    # ✅ Only extras should fill the form fields
    existing_attendees_extras = existing_attendees_all[1:] if len(existing_attendees_all) > 1 else []

    seats = int(guest["seats"])
    extra_count = max(0, seats - 1)

    if request.method == "POST":
        attending = request.form.get("attending", "yes")
        if attending not in ("yes", "no"):
            attending = "yes"

        dietary = (request.form.get("dietary") or "").strip()

        # ✅ Seat 1 ALWAYS primary guest (not editable)
        primary_full = f"{guest['first_name']} {guest['last_name']}".strip()

        # ✅ Collect ONLY extra attendees (seat 2..N)
        extras = []
        for i in range(extra_count):
            val = (request.form.get(f"attendee_{i+2}") or "").strip()
            if val:
                extras.append(val)

        attendee_names = [primary_full] + extras

        answers = {}
        for q in qs:
            key = f"q_{q['id']}"
            val = (request.form.get(key) or "").strip()
            answers[q["label"]] = val

        now = datetime.now().isoformat(timespec="seconds")

        con.execute("DELETE FROM rsvps WHERE guest_id=?", (guest["id"],))
        con.execute("""
            INSERT INTO rsvps(
                guest_id, attending, dietary,
                attendee_names_json, answers_json,
                updated_at
            ) VALUES(?,?,?,?,?,?)
        """, (
            guest["id"],
            attending,
            dietary,
            json.dumps(attendee_names),
            json.dumps(answers),
            now
        ))
        con.commit()

        return redirect(url_for(
            "rsvp_form",
            slug=slug,
            embed=("1" if embed else None),
            theme=theme,
            t=token,
            saved="1"
        ))

    saved = (request.args.get("saved") == "1")

    return render_template(
        "rsvp_form.html",
        client=client,
        guest=guest,
        seats=seats,
        extra_count=extra_count,
        questions=qs,
        existing_attending=existing_attending,
        existing_dietary=existing_dietary,
        existing_attendees=existing_attendees_extras,  # ✅ extras only
        existing_answers=existing_answers,
        embed=embed,
        theme=theme,
        saved=saved,
        token=token
    )


# =========================
# Platform Admin (create/manage client dashboards)
# =========================
@app.route("/admin", methods=["GET", "POST"])
def admin_login():
    init_db()
    if request.method == "POST":
        pw = request.form.get("password") or ""
        if pw == ADMIN_PASSWORD:
            session["is_admin"] = True
            return redirect(url_for("admin_clients"))
        flash("Invalid admin password.")
    return render_template("admin_login.html")


@app.route("/admin/logout")
def admin_logout():
    session.pop("is_admin", None)
    return redirect(url_for("admin_login"))


@app.route("/admin/clients", methods=["GET", "POST"])
def admin_clients():
    init_db()
    require_admin()
    con = get_db()

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = (request.form.get("password") or "").strip()
        slug = (request.form.get("slug") or "").strip().lower()
        display_name = (request.form.get("display_name") or "").strip()

        if not email or not password or not slug:
            flash("Email, password, and slug are required.")
            return redirect(url_for("admin_clients"))

        try:
            con.execute(
                "INSERT INTO clients(email, password_hash, slug, display_name) VALUES(?,?,?,?)",
                (email, generate_password_hash(password), slug, display_name)
            )
            con.commit()
            flash("Client created successfully.")
        except Exception:
            con.rollback()
            flash("Email or slug already exists.")

        return redirect(url_for("admin_clients"))

    clients = con.execute(
        "SELECT id, email, slug, display_name FROM clients ORDER BY id DESC"
    ).fetchall()

    return render_template("admin_clients.html", clients=clients)


@app.route("/admin/clients/<int:client_id>/delete", methods=["POST"])
def admin_delete_client(client_id):
    init_db()
    require_admin()
    con = get_db()

    row = con.execute("SELECT id, display_name, email FROM clients WHERE id=?", (client_id,)).fetchone()
    if not row:
        flash("Client not found.")
        return redirect(url_for("admin_clients"))

    try:
        con.execute("DELETE FROM clients WHERE id=?", (client_id,))
        con.commit()
        flash(f"Deleted client: {row.get('display_name') or row.get('email')}")
    except Exception:
        con.rollback()
        flash("Failed to delete client.")

    return redirect(url_for("admin_clients"))


# Run
if __name__ == "__main__":
    with app.app_context():
        init_db()
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=True)
