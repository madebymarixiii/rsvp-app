import csv
import io
import json
import time
import os
import sqlite3
from datetime import datetime
from urllib.parse import urlparse

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, send_file, g, abort
)
from flask_login import (
    LoginManager, login_user, login_required, logout_user,
    UserMixin, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash

# =========================
# CONFIG
# =========================
APP_SECRET = os.environ.get("APP_SECRET", "dev-secret-change-me")
DATABASE_URL = os.environ.get("DATABASE_URL")  # Only on Railway later
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")  # local default ok

MAX_FAILED_TRIES = 3
LOCKOUT_SECONDS = 15 * 60

app = Flask(__name__)
app.secret_key = APP_SECRET
# Allow sessions inside iframe (for Elementor embeds)
app.config.update(
    SESSION_COOKIE_SAMESITE="None",   # required for cross-site iframe
    SESSION_COOKIE_SECURE=True        # required when SameSite=None (HTTPS)
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
        # Postgres for Railway
        import psycopg2
        from psycopg2.extras import RealDictCursor

        conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
        g.db = DBWrapPG(conn)
        return g.db

    # SQLite for local
    conn = sqlite3.connect("local.db")
    conn.row_factory = dict_factory
    g.db = DBWrapSQLite(conn)
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


# =========================
# DB Init (works for SQLite + Postgres)
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
        # safe migrations (postgres)
        con.commit()
        return

    # SQLite schema
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


def is_embed() -> bool:
    return (request.args.get("embed") or "").strip().lower() in ("1", "true", "yes")


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
            opts = json.loads(r["options_json"] or "[]")
        except Exception:
            opts = []
        out.append({"id": r["id"], "label": r["label"], "field_type": r["field_type"], "options": opts})
    return out


# =========================
# RSVP lockout
# =========================
def _fail_key(slug: str) -> str:
    return f"fails:{slug}"


def _lock_key(slug: str) -> str:
    return f"lock:{slug}"


def is_locked(slug: str) -> bool:
    until = session.get(_lock_key(slug))
    return bool(until and time.time() < float(until))


def register_fail(slug: str):
    fails = int(session.get(_fail_key(slug), 0)) + 1
    session[_fail_key(slug)] = fails
    if fails >= MAX_FAILED_TRIES:
        session[_lock_key(slug)] = time.time() + LOCKOUT_SECONDS


def reset_fails(slug: str):
    session.pop(_fail_key(slug), None)
    session.pop(_lock_key(slug), None)


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
        pw = request.form.get("password") or ""

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
            g.first_name, 
            g.last_name, 
            g.seats,
            r.attending, 
            r.dietary, 
            r.attendee_names_json, 
            r.answers_json 
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
        SELECT g.first_name, g.last_name, g.seats,
               r.attending, r.dietary, r.attendee_names_json, r.answers_json,
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
            attendee_names = ", ".join(json.loads(r["attendee_names_json"] or "[]"))
        except Exception:
            attendee_names = ""
        try:
            answers = json.loads(r["answers_json"] or "{}")
        except Exception:
            answers = {}

        q_values = [answers.get(lbl, "") for lbl in q_labels]

        writer.writerow([
            r["first_name"], r["last_name"], r["seats"],
            (r.get("attending") or ""), (r.get("dietary") or ""), attendee_names,
            *q_values,
            (r.get("updated_at") or "")
        ])

    mem = io.BytesIO(output.getvalue().encode("utf-8"))
    return send_file(mem, mimetype="text/csv", as_attachment=True, download_name="rsvps.csv")


# =========================
# Public RSVP
# =========================
@app.route("/rsvp/<slug>", methods=["GET", "POST"])
def rsvp_lookup(slug):
    init_db()
    client = client_by_slug(slug)
    if not client:
        return "Wedding not found", 404

    embed = is_embed()

    if is_locked(slug):
        remaining = int(session.get(_lock_key(slug)) - time.time())
        mins = max(1, remaining // 60)
        return render_template("rsvp_lookup.html", client=client, locked=True, mins=mins, embed=embed)

    if request.method == "POST":
        first = request.form.get("first_name", "")
        last = request.form.get("last_name", "")

        guest = guest_lookup(client["id"], first, last)
        if not guest:
            register_fail(slug)
            left = MAX_FAILED_TRIES - int(session.get(_fail_key(slug), 0))
            if left <= 0:
                flash("Too many attempts. Please try again later.")
                return redirect(url_for("rsvp_lookup", slug=slug, embed=("1" if embed else None)))
            flash(f"Sorry, we couldn't find your invitation. Attempts left: {left}")
            return redirect(url_for("rsvp_lookup", slug=slug, embed=("1" if embed else None)))

        reset_fails(slug)
        session[f"guest:{slug}"] = int(guest["id"])
        return redirect(url_for("rsvp_form", slug=slug, embed=("1" if embed else None)))

    return render_template("rsvp_lookup.html", client=client, locked=False, embed=embed)


@app.route("/rsvp/<slug>/form", methods=["GET", "POST"])
def rsvp_form(slug):
    init_db()
    client = client_by_slug(slug)
    if not client:
        return "Wedding not found", 404

    embed = is_embed()

    guest_id = session.get(f"guest:{slug}")
    if not guest_id:
        return redirect(url_for("rsvp_lookup", slug=slug, embed=("1" if embed else None)))

    con = get_db()
    guest = con.execute(
        "SELECT * FROM guests WHERE id=? AND client_id=?",
        (guest_id, client["id"])
    ).fetchone()

    if not guest:
        session.pop(f"guest:{slug}", None)
        return redirect(url_for("rsvp_lookup", slug=slug, embed=("1" if embed else None)))

    qs = questions_for_client(client["id"])
    existing = con.execute("SELECT * FROM rsvps WHERE guest_id=?", (guest["id"],)).fetchone()

    existing_attending = existing["attending"] if existing else None
    existing_dietary = existing["dietary"] if existing else ""
    existing_attendees = []
    existing_answers = {}

    if existing:
        try:
            existing_attendees = json.loads(existing["attendee_names_json"] or "[]")
        except Exception:
            existing_attendees = []
        try:
            existing_answers = json.loads(existing["answers_json"] or "{}")
        except Exception:
            existing_answers = {}

    seats = int(guest["seats"])
    extra_count = max(0, seats - 1)

    if request.method == "POST":
        contact_first = (request.form.get("contact_first") or guest["first_name"]).strip()
        contact_last = (request.form.get("contact_last") or guest["last_name"]).strip()

        attending = request.form.get("attending", "yes")
        if attending not in ("yes", "no"):
            attending = "yes"

        dietary = (request.form.get("dietary") or "").strip()

        main_full = f"{contact_first} {contact_last}".strip()
        attendee_names = [main_full]

        for i in range(extra_count):
            val = (request.form.get(f"attendee_{i+2}") or "").strip()
            if val:
                attendee_names.append(val)

        answers = {}
        for q in qs:
            key = f"q_{q['id']}"
            val = request.form.get(key) or ""
            answers[q["label"]] = val.strip()

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

        flash("Thank you! Your RSVP has been saved.")
        return redirect(url_for("rsvp_form", slug=slug, embed=("1" if embed else None)))

    return render_template(
        "rsvp_form.html",
        client=client,
        guest=guest,
        seats=seats,
        extra_count=extra_count,
        questions=qs,
        existing_attending=existing_attending,
        existing_dietary=existing_dietary,
        existing_attendees=existing_attendees,
        existing_answers=existing_answers,
        embed=embed
    )


# =========================
# Platform Admin
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
        password = request.form.get("password") or ""
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


if __name__ == "__main__":
    with app.app_context():
        init_db()
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=True)