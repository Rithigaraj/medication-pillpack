import base64
import csv
import io
import json
import math
import os
import secrets
import smtplib
import socket
import sqlite3
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from datetime import date, datetime, timedelta
from email.message import EmailMessage
from functools import wraps
from pathlib import Path

from flask import Flask, abort, flash, g, jsonify, make_response, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash


BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "instance" / "pillpack.sqlite3"
TIME_FORMAT = "%H:%M"


def load_env_file(path):
    """Load simple KEY=VALUE pairs from a local .env file into os.environ."""
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except OSError:
        return
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip("'\"")
        if key:
            os.environ.setdefault(key, value)


load_env_file(BASE_DIR / ".env")

app = Flask(__name__, static_folder=None, template_folder=None)  # templates and assets are embedded below
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "dev-only-change-this-secret-key"),
    DATABASE=str(DATABASE),
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),
    MAIL_SERVER=os.environ.get("MAIL_SERVER", "smtp.gmail.com"),
    MAIL_PORT=int(os.environ.get("MAIL_PORT", "587")),
    MAIL_USERNAME=os.environ.get("MAIL_USERNAME", ""),
    MAIL_PASSWORD=os.environ.get("MAIL_PASSWORD", ""),
    MAIL_USE_TLS=os.environ.get("MAIL_USE_TLS", "1") != "0",
    MAIL_DEFAULT_SENDER=os.environ.get("MAIL_DEFAULT_SENDER", ""),
    OTP_TTL_SECONDS=int(os.environ.get("OTP_TTL_SECONDS", "600")),
    OTP_MAX_ATTEMPTS=int(os.environ.get("OTP_MAX_ATTEMPTS", "5")),
    OTP_RESEND_COOLDOWN_SECONDS=int(os.environ.get("OTP_RESEND_COOLDOWN_SECONDS", "60")),
    OTP_MAX_PER_HOUR=int(os.environ.get("OTP_MAX_PER_HOUR", "3")),
    FIREBASE_PROJECT_ID=os.environ.get("FIREBASE_PROJECT_ID", ""),
    FIREBASE_CREDENTIALS=os.environ.get(
        "FIREBASE_CREDENTIALS", str(BASE_DIR / "instance" / "firebase-service-account.json")
    ),
    FIREBASE_API_KEY=os.environ.get("FIREBASE_API_KEY", ""),
    FIREBASE_AUTH_DOMAIN=os.environ.get("FIREBASE_AUTH_DOMAIN", ""),
    FIREBASE_MESSAGING_SENDER_ID=os.environ.get("FIREBASE_MESSAGING_SENDER_ID", ""),
    FIREBASE_APP_ID=os.environ.get("FIREBASE_APP_ID", ""),
    FIREBASE_VAPID_KEY=os.environ.get("FIREBASE_VAPID_KEY", ""),
    ALERTS_POLL_SECONDS=int(os.environ.get("ALERTS_POLL_SECONDS", "45")),
)


@contextmanager
def connect_db():
    connection = sqlite3.connect(app.config["DATABASE"])
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_db():
    Path(app.config["DATABASE"]).parent.mkdir(parents=True, exist_ok=True)
    with connect_db() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password TEXT NOT NULL,
                age INTEGER,
                role TEXT NOT NULL CHECK (role IN ('user', 'caregiver')),
                caregiver_contact TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS medications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                medicine_name TEXT NOT NULL,
                dosage TEXT NOT NULL,
                medicine_type TEXT NOT NULL DEFAULT 'Tablet',
                time TEXT NOT NULL,
                frequency TEXT NOT NULL,
                start_date TEXT NOT NULL,
                end_date TEXT NOT NULL DEFAULT '',
                food_instruction TEXT NOT NULL DEFAULT 'Any time',
                notes TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS medication_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                medication_id INTEGER NOT NULL REFERENCES medications(id) ON DELETE CASCADE,
                scheduled_time TEXT NOT NULL,
                taken_time TEXT,
                date TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Upcoming'
                    CHECK (status IN ('Upcoming', 'Taken', 'Missed', 'Skipped')),
                UNIQUE (medication_id, date, scheduled_time)
            );
            CREATE TABLE IF NOT EXISTS caregivers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                caregiver_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                elderly_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                UNIQUE (caregiver_id, elderly_user_id)
            );
            CREATE TABLE IF NOT EXISTS user_settings (
                user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                notifications INTEGER NOT NULL DEFAULT 1,
                reminder_sound INTEGER NOT NULL DEFAULT 1,
                reminder_popup INTEGER NOT NULL DEFAULT 1,
                font_size TEXT NOT NULL DEFAULT 'large',
                theme TEXT NOT NULL DEFAULT 'light'
            );
            CREATE TABLE IF NOT EXISTS password_resets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                email TEXT NOT NULL,
                code TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                max_attempts INTEGER NOT NULL DEFAULT 5,
                used INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS push_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS history_user_date ON medication_history(user_id, date);
            CREATE INDEX IF NOT EXISTS password_resets_user ON password_resets(user_id, used, created_at);
            """
        )
        seed_demo_data(db)
        db.execute("UPDATE user_settings SET reminder_sound = 1 WHERE reminder_sound = 0")


def seed_demo_data(db):
    user = db.execute("SELECT id FROM users WHERE email = ?", ("ravi@pillpack.test",)).fetchone()
    if user:
        return

    password = generate_password_hash("demo1234")
    db.execute(
        "INSERT INTO users (name, email, password, age, role, caregiver_contact) VALUES (?, ?, ?, ?, ?, ?)",
        ("Ravi Kumar", "ravi@pillpack.test", password, 72, "user", "anita@pillpack.test"),
    )
    ravi_id = db.execute("SELECT id FROM users WHERE email = ?", ("ravi@pillpack.test",)).fetchone()["id"]
    db.execute(
        "INSERT INTO users (name, email, password, age, role) VALUES (?, ?, ?, ?, ?)",
        ("Anita Kumar", "anita@pillpack.test", password, 46, "caregiver"),
    )
    caregiver_id = db.execute("SELECT id FROM users WHERE email = ?", ("anita@pillpack.test",)).fetchone()["id"]
    db.execute("INSERT INTO caregivers (caregiver_id, elderly_user_id) VALUES (?, ?)", (caregiver_id, ravi_id))
    db.execute("INSERT INTO user_settings (user_id) VALUES (?)", (ravi_id,))
    db.execute("INSERT INTO user_settings (user_id) VALUES (?)", (caregiver_id,))

    today = date.today().isoformat()
    demo_meds = [
        (ravi_id, "Metformin", "500 mg", "Tablet", "08:00", "Twice daily", today, "", "After food", "Take with a full glass of water."),
        (ravi_id, "Vitamin D", "1000 IU", "Capsule", "13:00", "Once daily", today, "", "With food", ""),
        (ravi_id, "Lisinopril", "10 mg", "Tablet", "20:00", "Once daily", today, "", "Before food", ""),
    ]
    db.executemany(
        """INSERT INTO medications
        (user_id, medicine_name, dosage, medicine_type, time, frequency, start_date, end_date, food_instruction, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        demo_meds,
    )


def current_user():
    if "user_id" not in session:
        return None
    if "user" not in g:
        with connect_db() as db:
            g.user = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    return g.user


@app.context_processor
def inject_user():
    user = current_user()
    settings = None
    reminder_doses = []
    if user:
        with connect_db() as db:
            settings = db.execute("SELECT * FROM user_settings WHERE user_id = ?", (user["id"],)).fetchone()
        if user["role"] == "user":
            reminder_doses = get_today_doses(user["id"])
    return {
        "current_user": user,
        "user_settings": settings,
        "reminder_doses": reminder_doses,
        "today_label": datetime.now().strftime("%A, %B %d").replace(" 0", " "),
        "dev_otp": session.get("dev_otp"),
        "dev_otp_email": session.get("dev_otp_email"),
        "smtp_ready": smtp_configured(),
        "firebase_ready": firebase_configured(),
        "firebase_web": firebase_web_config(),
    }


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def role_required(role):
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            if current_user()["role"] != role:
                flash("That page is not available for this account.", "error")
                return redirect(url_for("dashboard"))
            return view(*args, **kwargs)

        return wrapped

    return decorator


GENERIC_RESET_NOTICE = "If an account matches that email, a 6-digit verification code has been sent."


def smtp_configured():
    return bool(
        app.config.get("MAIL_SERVER")
        and app.config.get("MAIL_USERNAME")
        and app.config.get("MAIL_PASSWORD")
        and (app.config.get("MAIL_DEFAULT_SENDER") or app.config.get("MAIL_USERNAME"))
    )


def generate_otp():
    return f"{secrets.randbelow(1_000_000):06d}"


def domain_can_receive_mail(email):
    """False when the recipient's domain has no DNS records (e.g. demo .test domains)."""
    domain = str(email).rpartition("@")[2].lower().rstrip(".")
    if not domain or "." not in domain:
        return False
    try:
        socket.getaddrinfo(domain, None)
        return True
    except socket.gaierror:
        return False


def mask_email(email):
    local, _, domain = str(email).partition("@")
    keep = local[:2] if len(local) > 2 else local[:1]
    return f"{keep}•••@{domain}" if domain else email


def issue_password_otp(db, user):
    """Retire any outstanding codes and issue a fresh one for this user."""
    now = datetime.now()
    expires = now + timedelta(seconds=app.config["OTP_TTL_SECONDS"])
    db.execute("UPDATE password_resets SET used = 1 WHERE user_id = ? AND used = 0", (user["id"],))
    code = generate_otp()
    db.execute(
        """INSERT INTO password_resets (user_id, email, code, created_at, expires_at, max_attempts)
        VALUES (?, ?, ?, ?, ?, ?)""",
        (
            user["id"],
            user["email"],
            generate_password_hash(code),
            now.isoformat(timespec="seconds"),
            expires.isoformat(timespec="seconds"),
            app.config["OTP_MAX_ATTEMPTS"],
        ),
    )
    return code


def otp_send_blocked(db, user_id):
    """True when the user is inside the resend cooldown or hourly quota."""
    now = datetime.now()
    latest = db.execute(
        "SELECT created_at FROM password_resets WHERE user_id = ? AND used = 0 ORDER BY id DESC LIMIT 1",
        (user_id,),
    ).fetchone()
    if latest:
        last_at = datetime.fromisoformat(latest["created_at"])
        if (now - last_at).total_seconds() < app.config["OTP_RESEND_COOLDOWN_SECONDS"]:
            return True
    cutoff = (now - timedelta(hours=1)).isoformat(timespec="seconds")
    sent_hour = db.execute(
        "SELECT COUNT(*) AS n FROM password_resets WHERE user_id = ? AND created_at >= ?",
        (user_id, cutoff),
    ).fetchone()["n"]
    return sent_hour >= app.config["OTP_MAX_PER_HOUR"]


def get_active_otp(db, user_id):
    return db.execute(
        "SELECT * FROM password_resets WHERE user_id = ? AND used = 0 ORDER BY id DESC LIMIT 1",
        (user_id,),
    ).fetchone()


def resend_wait_seconds(db, user_id):
    """Seconds until the next code request is allowed (cooldown or hourly quota)."""
    now = datetime.now()
    cutoff = (now - timedelta(hours=1)).isoformat(timespec="seconds")
    rows = db.execute(
        "SELECT created_at FROM password_resets WHERE user_id = ? AND created_at >= ? ORDER BY id DESC",
        (user_id, cutoff),
    ).fetchall()
    if not rows:
        return 0
    latest = datetime.fromisoformat(rows[0]["created_at"])
    wait = app.config["OTP_RESEND_COOLDOWN_SECONDS"] - (now - latest).total_seconds()
    if len(rows) >= app.config["OTP_MAX_PER_HOUR"]:
        oldest = datetime.fromisoformat(rows[app.config["OTP_MAX_PER_HOUR"] - 1]["created_at"])
        wait = max(wait, (oldest + timedelta(hours=1) - now).total_seconds())
    return max(0, math.ceil(wait))


def render_otp_email(user, code):
    from html import escape

    ttl_minutes = max(1, round(app.config["OTP_TTL_SECONDS"] / 60))
    subject = "Your Smart PillPack verification code"
    text = (
        f"Hello {user['name']},\n\n"
        f"Your Smart PillPack verification code is: {code}\n\n"
        f"Enter it on the verification page to choose a new password. "
        f"This code expires in {ttl_minutes} minutes and can be used {app.config['OTP_MAX_ATTEMPTS']} times.\n\n"
        "If you did not request this, you can safely ignore this email — your password will not change.\n"
        "Never share this code with anyone. Smart PillPack will never ask for it.\n\n"
        "— Smart PillPack\nCare, made clearer\n"
    )
    name = escape(user["name"])
    html = f"""<!doctype html>
<html lang="en">
<body style="margin:0;padding:0;background:#eef4f1;font-family:Arial,Helvetica,sans-serif;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#eef4f1;padding:24px 0;">
    <tr><td align="center">
      <table role="presentation" width="560" cellpadding="0" cellspacing="0" style="max-width:560px;width:100%;background:#ffffff;border-radius:14px;overflow:hidden;border:1px solid #dce8e4;">
        <tr>
          <td style="background:#214e42;padding:22px 32px;">
            <span style="color:#ffffff;font-size:18px;font-weight:bold;letter-spacing:.4px;">+&nbsp;&nbsp;Smart PillPack</span>
          </td>
        </tr>
        <tr>
          <td style="padding:34px 32px 8px;">
            <p style="margin:0 0 8px;color:#66877a;font-size:12px;letter-spacing:1.6px;text-transform:uppercase;">Email verification</p>
            <h1 style="margin:0 0 12px;color:#183a3b;font-size:23px;line-height:1.3;">Hi {name}, here is your code</h1>
            <p style="margin:0 0 26px;color:#667a78;font-size:14px;line-height:1.65;">
              Enter this 6-digit code on the verification page to continue resetting your password.
              It expires in {ttl_minutes} minutes.
            </p>
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
              <tr>
                <td align="center" style="background:#f3f8f6;border:1px dashed #9dc3b2;border-radius:12px;padding:24px 10px;">
                  <span style="font-family:'Courier New',Courier,monospace;font-size:40px;font-weight:bold;letter-spacing:14px;color:#214e42;padding-left:14px;">{code}</span>
                </td>
              </tr>
            </table>
            <p style="margin:24px 0 0;color:#667a78;font-size:13px;line-height:1.65;">
              Didn&rsquo;t request this? Ignore this email and your password stays exactly as it is.
              Never share this code with anyone — Smart PillPack staff will never ask for it.
            </p>
          </td>
        </tr>
        <tr>
          <td style="padding:20px 32px 30px;border-top:1px solid #eef3f0;">
            <p style="margin:0;color:#8a9b98;font-size:12px;line-height:1.7;">
              Smart PillPack &middot; Care, made clearer<br>
              This is an automated security email. Please do not reply.
            </p>
          </td>
        </tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"""
    return subject, text, html


def archive_otp_email(user, code):
    """Write every generated code to the local outbox log for visibility and audit."""
    subject, text, _html = render_otp_email(user, code)
    outbox_dir = BASE_DIR / "instance"
    outbox_dir.mkdir(parents=True, exist_ok=True)
    outbox_file = outbox_dir / "sent_emails.log"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = (
        f"[{timestamp}] RECIPIENT: {user['email']}\n"
        f"SUBJECT: {subject}\n"
        f"CODE: {code}\n"
        f"{'-' * 60}\n"
    )
    try:
        with open(outbox_file, "a", encoding="utf-8") as f:
            f.write(entry)
    except Exception as err:
        app.logger.warning("Could not append to local outbox log: %s", err)
    return outbox_file


def send_otp_email(user, code):
    """Deliver a verification-code email. Returns True only when SMTP send succeeds."""
    subject, text, html = render_otp_email(user, code)
    outbox_file = archive_otp_email(user, code)

    if not smtp_configured():
        app.logger.warning("SMTP not configured. Verification code for %s recorded to %s", user["email"], outbox_file)
        return False

    sender = app.config.get("MAIL_DEFAULT_SENDER") or app.config.get("MAIL_USERNAME")
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = sender
    message["To"] = user["email"]
    message.set_content(text)
    message.add_alternative(html, subtype="html")
    with smtplib.SMTP(app.config["MAIL_SERVER"], app.config["MAIL_PORT"], timeout=15) as smtp:
        if app.config["MAIL_USE_TLS"]:
            smtp.starttls()
        smtp.login(app.config["MAIL_USERNAME"], app.config["MAIL_PASSWORD"])
        smtp.send_message(message)
    app.logger.info("Verification code email sent to %s", user["email"])
    return True


# ---------------------------------------------------------------------------
# Firebase Cloud Messaging (push alerts to caregivers)
# ---------------------------------------------------------------------------

_fcm_state = {"access_token": None, "expires_at": 0.0}


def firebase_configured():
    creds = app.config.get("FIREBASE_CREDENTIALS") or ""
    return bool(app.config.get("FIREBASE_PROJECT_ID") and creds and Path(creds).exists())


def firebase_web_config():
    """Public web SDK config for the browser; empty dict when not set up."""
    config = {
        "apiKey": app.config.get("FIREBASE_API_KEY", ""),
        "authDomain": app.config.get("FIREBASE_AUTH_DOMAIN", ""),
        "messagingSenderId": app.config.get("FIREBASE_MESSAGING_SENDER_ID", ""),
        "appId": app.config.get("FIREBASE_APP_ID", ""),
        "vapidKey": app.config.get("FIREBASE_VAPID_KEY", ""),
    }
    return {key: value for key, value in config.items() if value}


def _load_service_account():
    with open(app.config["FIREBASE_CREDENTIALS"], "r", encoding="utf-8") as handle:
        return json.load(handle)


def _b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _fcm_access_token():
    """Exchange the service-account JWT for an OAuth access token (cached ~55 min)."""
    now = time.time()
    if _fcm_state["access_token"] and now < _fcm_state["expires_at"]:
        return _fcm_state["access_token"]

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    service_account = _load_service_account()
    issued = int(now)
    header = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    claims = _b64url(
        json.dumps(
            {
                "iss": service_account["client_email"],
                "scope": "https://www.googleapis.com/auth/firebase.messaging",
                "aud": service_account["token_uri"],
                "iat": issued,
                "exp": issued + 3600,
            }
        ).encode()
    )
    signing_input = f"{header}.{claims}".encode()
    key = serialization.load_pem_private_key(service_account["private_key"].encode(), password=None)
    signature = _b64url(key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256()))
    assertion = f"{header}.{claims}.{signature}"

    body = urllib.parse.urlencode(
        {"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": assertion}
    ).encode()
    request_obj = urllib.request.Request(
        service_account["token_uri"],
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(request_obj, timeout=15) as response:
        payload = json.load(response)
    _fcm_state["access_token"] = payload["access_token"]
    _fcm_state["expires_at"] = now + max(int(payload.get("expires_in", 3600)) - 60, 60)
    return _fcm_state["access_token"]


def _drop_push_token(token):
    with connect_db() as db:
        db.execute("DELETE FROM push_tokens WHERE token = ?", (token,))


def send_fcm_message(device_token, title, body, link="/caregiver"):
    """Send one FCM v1 push. Returns True when accepted by Google."""
    access_token = _fcm_access_token()
    message = {
        "message": {
            "token": device_token,
            "notification": {"title": title, "body": body},
            "webpush": {
                "notification": {"title": title, "body": body},
                "fcm_options": {"link": link},
            },
        }
    }
    request_obj = urllib.request.Request(
        f"https://fcm.googleapis.com/v1/projects/{app.config['FIREBASE_PROJECT_ID']}/messages:send",
        data=json.dumps(message).encode(),
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json; UTF-8",
        },
    )
    try:
        with urllib.request.urlopen(request_obj, timeout=12):
            return True
    except urllib.error.HTTPError as error:
        detail = error.read().decode(errors="replace")
        if error.code in (404, 400) and any(
            marker in detail for marker in ("UNREGISTERED", "NOT_FOUND", "INVALID_ARGUMENT", "THIRD_PARTY_AUTH_ERROR")
        ):
            _drop_push_token(device_token)
            app.logger.info("Removed stale push token for device")
        app.logger.warning("FCM send failed (%s): %s", error.code, detail[:300])
        return False
    except OSError as error:
        app.logger.warning("FCM send error: %s", error)
        return False


def notify_caregivers_of_missed(patient_id, medicine_name, dosage, scheduled_time):
    """Push an alert to every caregiver device linked to this patient."""
    if not firebase_configured():
        return 0
    with connect_db() as db:
        patient = db.execute("SELECT id, name FROM users WHERE id = ?", (patient_id,)).fetchone()
        tokens = db.execute(
            """SELECT DISTINCT t.token FROM push_tokens t
            JOIN caregivers c ON c.caregiver_id = t.user_id
            WHERE c.elderly_user_id = ?""",
            (patient_id,),
        ).fetchall()
    if not patient or not tokens:
        return 0
    first_name = patient["name"].split()[0]
    title = f"{first_name} missed a dose"
    body = f"{medicine_name} ({dosage}) was due at {clock(scheduled_time)} and is not marked taken yet. Tap to check in."
    sent = 0
    for row in tokens:
        try:
            if send_fcm_message(row["token"], title, body):
                sent += 1
        except Exception as error:
            app.logger.warning("Push notification failed: %s", error)
    return sent


def medication_times(medication):
    return [value.strip() for value in medication["time"].split(",") if value.strip()]


def sync_doses(user_id, day=None):
    day = day or date.today()
    today_text = day.isoformat()
    now = datetime.now()
    newly_missed = []
    with connect_db() as db:
        medications = db.execute(
            "SELECT * FROM medications WHERE user_id = ? AND start_date <= ? AND (end_date = '' OR end_date >= ?)",
            (user_id, today_text, today_text),
        ).fetchall()
        for medication in medications:
            for scheduled_time in medication_times(medication):
                db.execute(
                    """INSERT OR IGNORE INTO medication_history
                    (user_id, medication_id, scheduled_time, date, status)
                    VALUES (?, ?, ?, ?, 'Upcoming')""",
                    (user_id, medication["id"], scheduled_time, today_text),
                )
        due = db.execute(
            """SELECT h.id, h.scheduled_time, m.medicine_name, m.dosage
            FROM medication_history h JOIN medications m ON m.id = h.medication_id
            WHERE h.user_id = ? AND h.date = ? AND h.status = 'Upcoming'""",
            (user_id, today_text),
        ).fetchall()
        for dose in due:
            scheduled = datetime.combine(day, datetime.strptime(dose["scheduled_time"], TIME_FORMAT).time())
            if scheduled + timedelta(minutes=5) < now:
                db.execute("UPDATE medication_history SET status = 'Missed' WHERE id = ?", (dose["id"],))
                newly_missed.append(dict(dose))
    if newly_missed and day == date.today():
        for dose in newly_missed:
            try:
                notify_caregivers_of_missed(user_id, dose["medicine_name"], dose["dosage"], dose["scheduled_time"])
            except Exception as error:
                app.logger.warning("Caregiver alert failed: %s", error)
    return newly_missed


def get_today_doses(user_id):
    sync_doses(user_id)
    with connect_db() as db:
        doses = db.execute(
            """SELECT h.*, m.medicine_name, m.dosage, m.food_instruction, m.notes, m.medicine_type
            FROM medication_history h JOIN medications m ON m.id = h.medication_id
            WHERE h.user_id = ? AND h.date = ? ORDER BY h.scheduled_time, m.medicine_name""",
            (user_id, date.today().isoformat()),
        ).fetchall()
    return [dict(dose) for dose in doses]


def get_next_dose(user_id):
    today = date.today()
    now = datetime.now()
    with connect_db() as db:
        medications = db.execute(
            "SELECT * FROM medications WHERE user_id = ? AND (end_date = '' OR end_date >= ?)",
            (user_id, today.isoformat()),
        ).fetchall()

    next_dose = None
    for medication in medications:
        start_day = max(today, date.fromisoformat(medication["start_date"]))
        end_day = date.fromisoformat(medication["end_date"]) if medication["end_date"] else None
        for offset in range(367):
            scheduled_day = start_day + timedelta(days=offset)
            if end_day and scheduled_day > end_day:
                break
            for scheduled_time in sorted(medication_times(medication)):
                scheduled_at = datetime.combine(
                    scheduled_day, datetime.strptime(scheduled_time, TIME_FORMAT).time()
                )
                if scheduled_at <= now:
                    continue
                candidate = {
                    "medicine_name": medication["medicine_name"],
                    "dosage": medication["dosage"],
                    "food_instruction": medication["food_instruction"],
                    "scheduled_time": scheduled_time,
                    "day_phrase": (
                        "today" if scheduled_day == today else
                        "tomorrow" if scheduled_day == today + timedelta(days=1) else
                        scheduled_day.strftime("%A, %B %d").replace(" 0", " ")
                    ),
                    "scheduled_at": scheduled_at,
                }
                if next_dose is None or scheduled_at < next_dose["scheduled_at"]:
                    next_dose = candidate
                break
            if next_dose and next_dose["scheduled_at"].date() == scheduled_day:
                break
    return next_dose


def get_weekly_adherence(user_id):
    today = date.today()
    first_day = today - timedelta(days=6)
    with connect_db() as db:
        records = db.execute(
            """SELECT date,
            SUM(CASE WHEN status = 'Taken' THEN 1 ELSE 0 END) AS taken,
            COUNT(*) AS total
            FROM medication_history
            WHERE user_id = ? AND date BETWEEN ? AND ?
            AND status IN ('Taken', 'Missed', 'Skipped')
            GROUP BY date""",
            (user_id, first_day.isoformat(), today.isoformat()),
        ).fetchall()

    by_date = {record["date"]: record for record in records}
    days = []
    total_taken = 0
    total_doses = 0
    for offset in range(7):
        day = first_day + timedelta(days=offset)
        record = by_date.get(day.isoformat())
        taken = record["taken"] if record else 0
        total = record["total"] if record else 0
        total_taken += taken
        total_doses += total
        days.append({
            "label": day.strftime("%a"),
            "taken": taken,
            "total": total,
            "adherence": round(taken / total * 100) if total else 0,
        })
    return {
        "days": days,
        "taken": total_taken,
        "total": total_doses,
        "percentage": round(total_taken / total_doses * 100) if total_doses else None,
    }


@app.template_filter("clock")
def clock(value):
    try:
        return datetime.strptime(value, TIME_FORMAT).strftime("%I:%M %p").lstrip("0")
    except (ValueError, TypeError):
        return value


@app.route("/")
def index():
    if current_user():
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        with connect_db() as db:
            user = db.execute("SELECT * FROM users WHERE lower(email) = lower(?)", (email,)).fetchone()
        if user and check_password_hash(user["password"], password):
            session.clear()
            session["user_id"] = user["id"]
            session.permanent = request.form.get("remember") == "on"
            return redirect(url_for("dashboard"))
        flash("Check your email and password, then try again.", "error")
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        role = request.form.get("role", "user")
        age_value = request.form.get("age", "").strip()
        contact = request.form.get("caregiver_contact", "").strip()
        errors = []
        if not name or len(name) > 100:
            errors.append("Enter your full name.")
        if "@" not in email:
            errors.append("Enter a valid email address.")
        if len(password) < 8:
            errors.append("Use a password with at least 8 characters.")
        if password != confirm:
            errors.append("Your passwords do not match.")
        if role not in ("user", "caregiver"):
            errors.append("Choose a valid account type.")
        try:
            age = int(age_value) if age_value else None
            if age is not None and not 1 <= age <= 120:
                raise ValueError
        except ValueError:
            errors.append("Enter an age between 1 and 120.")
            age = None
        if errors:
            for error in errors:
                flash(error, "error")
            return render_template("register.html", form=request.form)
        try:
            with connect_db() as db:
                cursor = db.execute(
                    "INSERT INTO users (name, email, password, age, role, caregiver_contact) VALUES (?, ?, ?, ?, ?, ?)",
                    (name, email, generate_password_hash(password), age, role, contact),
                )
                new_id = cursor.lastrowid
                db.execute("INSERT INTO user_settings (user_id) VALUES (?)", (new_id,))
                if role == "user" and contact:
                    caregiver = db.execute(
                        "SELECT id FROM users WHERE email = ? AND role = 'caregiver'", (contact.lower(),)
                    ).fetchone()
                    if caregiver:
                        db.execute(
                            "INSERT OR IGNORE INTO caregivers (caregiver_id, elderly_user_id) VALUES (?, ?)",
                            (caregiver["id"], new_id),
                        )
            session.clear()
            session["user_id"] = new_id
            return redirect(url_for("dashboard"))
        except sqlite3.IntegrityError:
            flash("An account with that email already exists.", "error")
            return render_template("register.html", form=request.form)
    return render_template("register.html", form={})


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        blocked = False
        with connect_db() as db:
            user = db.execute("SELECT * FROM users WHERE lower(email) = lower(?)", (email,)).fetchone()
            if user:
                blocked = otp_send_blocked(db, user["id"])
                deliverable = smtp_configured() and domain_can_receive_mail(user["email"])
                if blocked:
                    wait = resend_wait_seconds(db, user["id"])
                    wait_text = f"{math.ceil(wait / 60)} minute{'s' if math.ceil(wait / 60) != 1 else ''}" if wait >= 60 else f"{wait} seconds"
                    flash(f"For security, please wait about {wait_text} before requesting another code.", "error")
                else:
                    code = issue_password_otp(db, user)
                    sent = False
                    if deliverable:
                        try:
                            sent = send_otp_email(user, code)
                        except (OSError, smtplib.SMTPException) as error:
                            app.logger.error("Could not send verification code email: %s", error)
                        if not sent:
                            flash("We couldn't send the verification code right now. Please try again in a moment.", "error")
                            return redirect(url_for("forgot_password"))
                    else:
                        archive_otp_email(user, code)
                        session["dev_otp"] = code
                        session["dev_otp_email"] = user["email"]
                session["reset_flow"] = {
                    "user_id": user["id"],
                    "email": user["email"],
                    "verified": False,
                    "sent_at": datetime.now().isoformat(timespec="seconds"),
                }
        if not blocked:
            flash(GENERIC_RESET_NOTICE, "success")
        return redirect(url_for("verify_otp"))
    return render_template("forgot_password.html")


@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    flow = session.get("reset_flow")
    if not flow:
        flash("Enter your email address to receive a verification code.", "error")
        return redirect(url_for("forgot_password"))
    if flow.get("verified"):
        return redirect(url_for("reset_password"))

    masked = mask_email(flow["email"])

    def render_verify(status=200):
        with connect_db() as db:
            wait = resend_wait_seconds(db, flow["user_id"])
        label = f"Resend code in {math.ceil(wait / 60)} min" if wait >= 60 else f"Resend code in {wait}s"
        return render_template(
            "verify_otp.html", masked_email=masked, resend_in=wait, resend_label=label
        ), status

    if request.method == "POST":
        code = "".join(value for value in request.form.getlist("code") if value).strip()
        if not (len(code) == 6 and code.isdigit()):
            flash("Enter the full 6-digit code from your email.", "error")
            return render_verify()

        now = datetime.now()
        with connect_db() as db:
            record = get_active_otp(db, flow["user_id"])
            if not record or datetime.fromisoformat(record["expires_at"]) <= now:
                if record:
                    db.execute("UPDATE password_resets SET used = 1 WHERE id = ?", (record["id"],))
                session.pop("dev_otp", None)
                session.pop("dev_otp_email", None)
                flash("That code has expired. Request a new one to continue.", "error")
                return redirect(url_for("forgot_password"))
            if record["attempts"] >= record["max_attempts"]:
                db.execute("UPDATE password_resets SET used = 1 WHERE id = ?", (record["id"],))
                session.pop("dev_otp", None)
                session.pop("dev_otp_email", None)
                flash("Too many incorrect attempts. Request a new code to continue.", "error")
                return redirect(url_for("forgot_password"))
            if check_password_hash(record["code"], code):
                db.execute("UPDATE password_resets SET used = 1 WHERE id = ?", (record["id"],))
                session["reset_flow"] = {**flow, "verified": True}
                session.pop("dev_otp", None)
                session.pop("dev_otp_email", None)
                return redirect(url_for("reset_password"))
            db.execute("UPDATE password_resets SET attempts = attempts + 1 WHERE id = ?", (record["id"],))
            remaining = max(record["max_attempts"] - record["attempts"] - 1, 0)
        flash(
            "That code is incorrect. " + (f"{remaining} attempt{'s' if remaining != 1 else ''} left." if remaining else ""),
            "error",
        )
        return render_verify()
    return render_verify()


@app.route("/verify-otp/resend", methods=["POST"])
def resend_otp():
    flow = session.get("reset_flow")
    if not flow:
        flash("Enter your email address to receive a verification code.", "error")
        return redirect(url_for("forgot_password"))
    with connect_db() as db:
        user = db.execute("SELECT * FROM users WHERE id = ?", (flow["user_id"],)).fetchone()
        if not user:
            session.clear()
            flash(GENERIC_RESET_NOTICE, "success")
            return redirect(url_for("forgot_password"))
        deliverable = smtp_configured() and domain_can_receive_mail(user["email"])
        if otp_send_blocked(db, user["id"]):
            flash("Please wait a moment before requesting another code.", "error")
            return redirect(url_for("verify_otp"))
        code = issue_password_otp(db, user)
        if deliverable:
            sent = False
            try:
                sent = send_otp_email(user, code)
            except (OSError, smtplib.SMTPException) as error:
                app.logger.error("Could not send verification code email: %s", error)
            if not sent:
                flash("We couldn't send the verification code right now. Please try again in a moment.", "error")
                return redirect(url_for("verify_otp"))
        else:
            archive_otp_email(user, code)
            session["dev_otp"] = code
            session["dev_otp_email"] = user["email"]
        session["reset_flow"] = {**flow, "verified": False}
    flash("A new verification code has been sent.", "success")
    return redirect(url_for("verify_otp"))


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    flow = session.get("reset_flow")
    if not flow:
        flash("Request a verification code to reset your password.", "error")
        return redirect(url_for("forgot_password"))
    if not flow.get("verified"):
        flash("Verify the code we emailed you before choosing a new password.", "error")
        return redirect(url_for("verify_otp"))

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        if len(password) < 8:
            flash("Use a password with at least 8 characters.", "error")
        elif password != confirm:
            flash("Your passwords do not match.", "error")
        else:
            with connect_db() as db:
                db.execute(
                    "UPDATE users SET password = ? WHERE id = ?",
                    (generate_password_hash(password), flow["user_id"]),
                )
                db.execute(
                    "UPDATE password_resets SET used = 1 WHERE user_id = ? AND used = 0",
                    (flow["user_id"],),
                )
            session.pop("reset_flow", None)
            session.pop("dev_otp", None)
            session.pop("dev_otp_email", None)
            flash("Your password has been reset. You can now sign in.", "success")
            return redirect(url_for("login"))
    return render_template("reset_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password_link(token):
    flash(
        "Email reset links have been replaced by secure verification codes. Request a new code to continue.",
        "error",
    )
    return redirect(url_for("forgot_password"))


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    if current_user()["role"] == "caregiver":
        return redirect(url_for("caregiver_dashboard"))
    doses = get_today_doses(current_user()["id"])
    next_dose = get_next_dose(current_user()["id"])
    weekly_adherence = get_weekly_adherence(current_user()["id"])
    with connect_db() as db:
        active_count = db.execute(
            "SELECT COUNT(*) AS count FROM medications WHERE user_id = ? AND start_date <= ? AND (end_date = '' OR end_date >= ?)",
            (current_user()["id"], date.today().isoformat(), date.today().isoformat()),
        ).fetchone()["count"]
    return render_template(
        "dashboard.html", doses=doses, next_dose=next_dose,
        active_count=active_count, weekly_adherence=weekly_adherence
    )


@app.route("/medications")
@role_required("user")
def medications():
    today = date.today().isoformat()
    with connect_db() as db:
        items = db.execute(
            "SELECT * FROM medications WHERE user_id = ? ORDER BY medicine_name",
            (current_user()["id"],),
        ).fetchall()
    return render_template("medications.html", medications=items, today=today)


def save_medication(medication_id=None):
    form = request.form
    name = form.get("medicine_name", "").strip()
    dosage = form.get("dosage", "").strip()
    medicine_type = form.get("medicine_type", "Tablet").strip()
    frequency = form.get("frequency", "Once daily")
    times = request.form.getlist("times") or [form.get("time", "")]
    times = sorted(set(value.strip() for value in times if value.strip()))
    start_date = form.get("start_date", "").strip()
    end_date = form.get("end_date", "").strip()
    food_instruction = form.get("food_instruction", "Any time")
    notes = form.get("notes", "").strip()
    valid_frequencies = {"Once daily", "Twice daily", "Three times daily", "Custom"}
    valid_food = {"Before food", "After food", "With food", "Any time"}
    try:
        date.fromisoformat(start_date)
        if end_date:
            date.fromisoformat(end_date)
        dates_valid = not end_date or end_date >= start_date
    except ValueError:
        dates_valid = False
    times_valid = bool(times) and all(_is_valid_time(value) for value in times)
    frequency_count = {"Once daily": 1, "Twice daily": 2, "Three times daily": 3}.get(frequency)
    if not name or not dosage or not dates_valid or not times_valid or frequency not in valid_frequencies or food_instruction not in valid_food:
        flash("Please check the medicine name, dosage, schedule, and dates.", "error")
        return False
    if frequency_count and len(times) != frequency_count:
        flash(f"Choose {frequency_count} scheduled time{'s' if frequency_count != 1 else ''} for {frequency.lower()}.", "error")
        return False

    values = (name, dosage, medicine_type, ",".join(times), frequency, start_date, end_date, food_instruction, notes)
    with connect_db() as db:
        if medication_id:
            existing = db.execute(
                "SELECT id FROM medications WHERE id = ? AND user_id = ?", (medication_id, current_user()["id"])
            ).fetchone()
            if not existing:
                abort(404)
            db.execute(
                """UPDATE medications SET medicine_name = ?, dosage = ?, medicine_type = ?, time = ?, frequency = ?,
                start_date = ?, end_date = ?, food_instruction = ?, notes = ? WHERE id = ? AND user_id = ?""",
                values + (medication_id, current_user()["id"]),
            )
            db.execute(
                "DELETE FROM medication_history WHERE medication_id = ? AND date = ? AND status = 'Upcoming'",
                (medication_id, date.today().isoformat()),
            )
        else:
            db.execute(
                """INSERT INTO medications
                (medicine_name, dosage, medicine_type, time, frequency, start_date, end_date, food_instruction, notes, user_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                values + (current_user()["id"],),
            )
    return True


def _is_valid_time(value):
    try:
        datetime.strptime(value, TIME_FORMAT)
        return True
    except ValueError:
        return False


@app.route("/medications/new", methods=["GET", "POST"])
@role_required("user")
def add_medication():
    if request.method == "POST" and save_medication():
        flash("Medication added to your schedule.", "success")
        return redirect(url_for("medications"))
    return render_template("medication_form.html", medication=None, form=request.form)


@app.route("/medications/<int:medication_id>/edit", methods=["GET", "POST"])
@role_required("user")
def edit_medication(medication_id):
    with connect_db() as db:
        medication = db.execute(
            "SELECT * FROM medications WHERE id = ? AND user_id = ?", (medication_id, current_user()["id"])
        ).fetchone()
    if not medication:
        abort(404)
    if request.method == "POST" and save_medication(medication_id):
        flash("Medication schedule updated.", "success")
        return redirect(url_for("medications"))
    return render_template("medication_form.html", medication=medication, form=request.form)


@app.route("/medications/<int:medication_id>/delete", methods=["POST"])
@role_required("user")
def delete_medication(medication_id):
    with connect_db() as db:
        db.execute("DELETE FROM medications WHERE id = ? AND user_id = ?", (medication_id, current_user()["id"]))
    flash("Medication removed from your list.", "success")
    return redirect(url_for("medications"))


@app.route("/dose/<int:dose_id>/<action>", methods=["POST"])
@login_required
def update_dose(dose_id, action):
    status = {"taken": "Taken", "skipped": "Skipped", "missed": "Missed"}.get(action)
    if not status:
        abort(404)
    user = current_user()
    with connect_db() as db:
        dose = db.execute(
            "SELECT id, user_id, status, scheduled_time FROM medication_history WHERE id = ? AND date = ?",
            (dose_id, date.today().isoformat()),
        ).fetchone()
        if not dose:
            abort(404)
        if dose["user_id"] == user["id"]:
            if user["role"] != "user":
                abort(403)
        elif user["role"] == "caregiver":
            linked = db.execute(
                "SELECT 1 FROM caregivers WHERE caregiver_id = ? AND elderly_user_id = ?",
                (user["id"], dose["user_id"]),
            ).fetchone()
            if not linked or status == "Missed":
                abort(403)
        else:
            abort(403)
        if dose["status"] == "Upcoming":
            if status == "Missed" and dose["scheduled_time"] >= datetime.now().strftime(TIME_FORMAT):
                abort(400)
            taken_time = datetime.now().strftime(TIME_FORMAT) if status == "Taken" else None
            db.execute(
                "UPDATE medication_history SET status = ?, taken_time = ? WHERE id = ?",
                (status, taken_time, dose_id),
            )
    messages = {
        "Taken": ("Marked as taken. Nice work.", "success"),
        "Skipped": ("Dose marked as skipped.", "success"),
        "Missed": ("A scheduled dose was marked as missed.", "error"),
    }
    message, category = messages[status]
    flash(message, category)
    next_url = request.form.get("next") or ""
    if not next_url.startswith("/") or next_url.startswith("//"):
        next_url = url_for("caregiver_dashboard" if user["role"] == "caregiver" else "dashboard")
    return redirect(next_url)


@app.route("/history")
@role_required("user")
def history():
    period, records = get_history_records(current_user()["id"], request.args.get("period", "today"))
    return render_template("history.html", records=records, period=period)


def get_history_records(user_id, period):
    today = date.today()
    if period == "week":
        start = today - timedelta(days=today.weekday())
    elif period == "month":
        start = today.replace(day=1)
    else:
        period = "today"
        start = today
        sync_doses(user_id)
    with connect_db() as db:
        records = db.execute(
            """SELECT h.*, m.medicine_name, m.dosage FROM medication_history h
            JOIN medications m ON m.id = h.medication_id
            WHERE h.user_id = ? AND h.date BETWEEN ? AND ?
            ORDER BY h.date DESC, h.scheduled_time DESC""",
            (user_id, start.isoformat(), today.isoformat()),
        ).fetchall()
    return period, records


@app.route("/history/export")
@role_required("user")
def export_history():
    period, records = get_history_records(current_user()["id"], request.args.get("period", "today"))
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(("Date", "Medicine", "Dosage", "Scheduled time", "Status", "Taken time"))
    for record in records:
        values = (
            record["date"], record["medicine_name"], record["dosage"],
            record["scheduled_time"], record["status"], record["taken_time"] or "",
        )
        writer.writerow([_csv_safe(value) for value in values])
    response = make_response(output.getvalue())
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = f"attachment; filename=smart-pillpack-{period}-history.csv"
    return response


def _csv_safe(value):
    value = str(value or "")
    return f"'{value}" if value.startswith(("=", "+", "-", "@", "\t", "\r")) else value


@app.route("/caregiver")
@role_required("caregiver")
def caregiver_dashboard():
    with connect_db() as db:
        people = db.execute(
            """SELECT u.* FROM caregivers c JOIN users u ON u.id = c.elderly_user_id
            WHERE c.caregiver_id = ? ORDER BY u.name""",
            (current_user()["id"],),
        ).fetchall()
        selected_id = request.args.get("person", type=int)
        person = next((item for item in people if item["id"] == selected_id), people[0] if people else None)
        if person:
            doses = get_today_doses(person["id"])
        else:
            doses = []
    taken = sum(dose["status"] == "Taken" for dose in doses)
    missed = sum(dose["status"] == "Missed" for dose in doses)
    upcoming = sum(dose["status"] == "Upcoming" for dose in doses)
    completed = taken + missed + sum(dose["status"] == "Skipped" for dose in doses)
    adherence = round(taken / completed * 100) if completed else 0
    alerts = [dose for dose in doses if dose["status"] == "Missed"]
    return render_template(
        "caregiver.html", people=people, person=person, doses=doses, taken=taken,
        missed=missed, upcoming=upcoming, adherence=adherence, alerts=alerts
    )


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        contact = request.form.get("caregiver_contact", "").strip()
        age_value = request.form.get("age", "").strip()
        try:
            age = int(age_value) if age_value else None
            if age is not None and not 1 <= age <= 120:
                raise ValueError
            if not name or "@" not in email:
                raise ValueError
            with connect_db() as db:
                db.execute(
                    "UPDATE users SET name = ?, email = ?, age = ?, caregiver_contact = ? WHERE id = ?",
                    (name, email, age, contact, current_user()["id"]),
                )
                if current_user()["role"] == "user":
                    db.execute("DELETE FROM caregivers WHERE elderly_user_id = ?", (current_user()["id"],))
                    caregiver = db.execute(
                        "SELECT id FROM users WHERE email = ? AND role = 'caregiver'", (contact.lower(),)
                    ).fetchone()
                    if caregiver:
                        db.execute(
                            "INSERT OR IGNORE INTO caregivers (caregiver_id, elderly_user_id) VALUES (?, ?)",
                            (caregiver["id"], current_user()["id"]),
                        )
                g.pop("user", None)
            flash("Your profile has been updated.", "success")
            return redirect(url_for("profile"))
        except (ValueError, sqlite3.IntegrityError):
            flash("Please check your name, email, and age. That email may already be in use.", "error")
    return render_template("profile.html")


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if request.method == "POST":
        font_size = request.form.get("font_size", "large")
        theme = request.form.get("theme", "light")
        if font_size not in {"normal", "large", "larger"} or theme not in {"light", "dark"}:
            abort(400)
        with connect_db() as db:
            db.execute(
                """UPDATE user_settings SET notifications = ?, reminder_sound = ?, reminder_popup = ?,
                font_size = ?, theme = ? WHERE user_id = ?""",
                (
                    int(request.form.get("notifications") == "on"),
                    int(request.form.get("reminder_sound") == "on"),
                    int(request.form.get("reminder_popup") == "on"),
                    font_size,
                    theme,
                    current_user()["id"],
                ),
            )
        flash("Your preferences have been saved.", "success")
        return redirect(url_for("settings"))
    return render_template("settings.html")


def chatbot_respond(user, query):
    text = (query or "").strip()
    low = text.lower()
    user_id = user["id"]

    # 1. Greetings & introductions
    if any(k in low for k in ["hello", "hi", "hey", "good morning", "good evening", "good day", "greetings", "who are you"]):
        return {
            "reply": (
                f"Hello **{user['name'].split()[0]}**! 👋 I'm your Smart PillPack Care Guide.\n\n"
                "I can answer any doubt about your **daily medicine schedule**, **dosage instructions**, "
                "**missed doses**, **caregiver alerts**, or guide you through app features.\n\n"
                "What would you like to check today?"
            ),
            "suggestions": ["⏰ What's my next dose?", "💊 Today's medicines", "⚠️ Missed dose guidance", "📊 My adherence score"]
        }

    # 2. Next dose queries
    if any(k in low for k in ["next dose", "up next", "next medicine", "next pill", "when is my next", "upcoming dose", "what is next", "when do i take"]):
        next_dose = get_next_dose(user_id)
        if next_dose:
            food_note = f" · *{next_dose['food_instruction']}*" if next_dose.get("food_instruction") != "Any time" else ""
            return {
                "reply": (
                    f"⏰ **Next Scheduled Dose**:\n\n"
                    f"**{next_dose['medicine_name']}** ({next_dose['dosage']}){food_note}\n"
                    f"• Scheduled for **{clock(next_dose['scheduled_time'])}**, **{next_dose['day_phrase']}**.\n\n"
                    f"You will get an automated popup reminder and chime right when it's time to take it!"
                ),
                "suggestions": ["💊 Today's medicines", "🔔 How do reminders work?", "📊 My adherence score"]
            }
        else:
            return {
                "reply": "You don't have any upcoming doses scheduled right now! You can view your current plan under **[My medicines](/medications)** or add one via **[Add medicine](/add_medication)**.",
                "suggestions": ["➕ Add medicine", "💊 View my medicines", "⚠️ Missed dose guidance"]
            }

    # 3. Today's schedule / doses
    if any(k in low for k in ["today", "today's", "scheduled today", "medicines today", "doses today", "what to take today", "my schedule", "what am i taking"]):
        doses = get_today_doses(user_id)
        if doses:
            taken_cnt = sum(1 for d in doses if d["status"] == "Taken")
            total_cnt = len(doses)
            lines = [f"📅 **Today's Medication Plan ({taken_cnt}/{total_cnt} Taken)**:\n"]
            for d in doses:
                status_icon = "✅ Taken" if d["status"] == "Taken" else ("⚠️ Missed" if d["status"] == "Missed" else "⏳ Upcoming")
                food_info = f" ({d['food_instruction']})" if d['food_instruction'] != 'Any time' else ""
                lines.append(f"• **{clock(d['scheduled_time'])}** · **{d['medicine_name']}** ({d['dosage']}){food_info} — *{status_icon}*")
            lines.append("\nYou can log doses as taken right on your **[Home Dashboard](/)**.")
            return {
                "reply": "\n".join(lines),
                "suggestions": ["⏰ What's my next dose?", "⚠️ Missed dose guidance", "📊 My adherence score"]
            }
        else:
            return {
                "reply": "You have no doses scheduled for today. To add a new prescription schedule, click **[Add medicine](/add_medication)**.",
                "suggestions": ["➕ Add medicine", "📊 My adherence score"]
            }

    # 4. Missed dose assistance
    if any(k in low for k in ["miss", "missed", "forgot", "skip", "skipped", "forgotten"]):
        return {
            "reply": (
                "⚠️ **What to do if you miss a dose**:\n\n"
                "1. **Never take a double dose** to make up for a missed one. Taking extra medicine at once can be dangerous.\n"
                "2. **Take it as soon as you remember**, UNLESS it is already near your next scheduled dose time.\n"
                "3. If your next dose is coming up soon, skip the missed one and continue your normal timetable.\n"
                "4. **Caregiver Alert**: In Smart PillPack, doses overdue by 5+ minutes automatically update to *Missed* so your caregiver can check in if needed.\n\n"
                "✦ *Tip: If you're ever unsure about a specific medication, contact your physician or pharmacist.*"
            ),
            "suggestions": ["⏰ What's my next dose?", "♡ Who is my caregiver?", "🔔 How do reminders work?"]
        }

    # 5. Adherence and weekly consistency score
    if any(k in low for k in ["adherence", "consistency", "score", "progress", "how am i doing", "weekly"]):
        adherence = get_weekly_adherence(user_id)
        pct = adherence["percentage"]
        taken = adherence["taken"]
        total = adherence["total"]
        if pct is not None:
            sentiment = "Outstanding consistency! 🌟" if pct >= 85 else ("Good progress! Keep it up! 👍" if pct >= 65 else "Let's work on staying on schedule. Need extra alarms? 💪")
            return {
                "reply": (
                    f"📊 **7-Day Medication Adherence**: **{pct}%**\n\n"
                    f"• You completed **{taken} of {total}** recorded doses over the last 7 days.\n"
                    f"• {sentiment}\n\n"
                    f"You can view your daily breakdown chart on your **[Home Dashboard](/)**."
                ),
                "suggestions": ["💊 Today's medicines", "⏰ What's my next dose?", "📑 Download history report"]
            }
        else:
            return {
                "reply": "You don't have enough recorded dose history yet for a weekly score. As you record doses, your adherence tracker updates automatically!",
                "suggestions": ["💊 Today's medicines", "🔔 How do reminders work?"]
            }

    # 6. Specific Medication Lookup from User's Active List
    with connect_db() as db:
        user_meds = db.execute("SELECT * FROM medications WHERE user_id = ?", (user_id,)).fetchall()
        user_meds = [dict(m) for m in user_meds]
    
    for med in user_meds:
        med_name_low = med["medicine_name"].lower()
        if med_name_low in low:
            times_formatted = ", ".join(clock(t) for t in sorted(medication_times(med)))
            notes_str = f"\n• **Instructions**: {med['notes']}" if med["notes"] else ""
            end_str = f" until {med['end_date']}" if med["end_date"] else " (Ongoing)"
            return {
                "reply": (
                    f"💊 **Details for {med['medicine_name']}**:\n\n"
                    f"• **Dosage**: {med['dosage']} ({med['medicine_type']})\n"
                    f"• **Frequency**: {med['frequency']} at **{times_formatted}**\n"
                    f"• **Food Instruction**: *{med['food_instruction']}*\n"
                    f"• **Duration**: Started on {med['start_date']}{end_str}{notes_str}\n\n"
                    f"You can modify this prescription in **[My medicines](/medications)**."
                ),
                "suggestions": ["⏰ What's my next dose?", "⚠️ Missed dose guidance", "💊 Today's medicines"]
            }

    # 7. Caregiver inquiries
    if any(k in low for k in ["caregiver", "anita", "carer", "support person", "family"]):
        contact = user.get("caregiver_contact", "").strip()
        contact_info = f"linked to **{contact}**" if contact else "not linked yet"
        return {
            "reply": (
                f"♡ **Caregiver Connection**:\n\n"
                f"Your account is currently {contact_info}.\n\n"
                f"• When linked, your caregiver can view your schedule and gets real-time alerts if a dose is missed.\n"
                f"• To link or update your caregiver email, head over to your **[Profile](/profile)**.\n"
                f"• This gives your loved ones peace of mind without having to call and ask if you took your medicine!"
            ),
            "suggestions": ["👤 Go to Profile", "⚠️ What if I miss a dose?", "💊 Today's medicines"]
        }

    # 8. Food instructions guidance
    if any(k in low for k in ["food", "meal", "eat", "empty stomach", "with food", "before food", "after food"]):
        return {
            "reply": (
                "🍽️ **Medication Food Instructions Explained**:\n\n"
                "• **With food**: Take during or immediately following a meal. This protects your stomach lining and helps prevent nausea (e.g. Metformin).\n"
                "• **Before food**: Take 30–60 minutes before eating on an empty stomach to optimize drug absorption (e.g. Omeprazole, Levothyroxine).\n"
                "• **After food**: Take 15–30 minutes after completing your meal.\n"
                "• **Any time**: Food does not significantly alter how this medicine works.\n\n"
                "You can see each medicine's specific food rule in **[My medicines](/medications)**."
            ),
            "suggestions": ["💊 Today's medicines", "⏰ What's my next dose?", "⚠️ Missed dose guidance"]
        }

    # 9. Reminders, Alarms & Notifications
    if any(k in low for k in ["reminder", "alarm", "popup", "notification", "sound", "chime", "snooze"]):
        return {
            "reply": (
                "🔔 **How Smart PillPack Reminders Work**:\n\n"
                "• **Live Check**: The app checks your schedule every 15 seconds while open.\n"
                "• **Popup Dialog**: When a dose is due, an on-screen dialog highlights the medicine name, dosage, and food instructions.\n"
                "• **Audio Chime**: An alert sound plays to grab your attention.\n"
                "• **5-Minute Snooze**: Click **'Remind me in 5 minutes'** if you are busy, and the alarm will gently repeat.\n"
                "• **Desktop Notifications**: Turn on browser notifications in **[Settings](/settings)** to get alerts even if the tab is minimized."
            ),
            "suggestions": ["⚙️ Go to Settings", "⏰ What's my next dose?", "💊 Today's medicines"]
        }

    # 10. Adding, Editing or Deleting Medicines
    if any(k in low for k in ["add", "new medicine", "create medicine", "register medicine", "edit", "delete", "remove"]):
        return {
            "reply": (
                "📝 **Managing Your Medication Schedule**:\n\n"
                "• **Add a Medicine**: Click **[＋ Add medicine](/add_medication)** in the sidebar. Fill in the medicine name, dosage, frequency, times, and instructions.\n"
                "• **Edit a Medicine**: Go to **[My medicines](/medications)** and click **Edit** on any card.\n"
                "• **Delete a Medicine**: Go to **[My medicines](/medications)** and click **Delete**.\n"
                "• **Custom Frequency**: Choose between Once daily, Twice daily, Three times daily, or Custom (up to 8 times a day!)."
            ),
            "suggestions": ["➕ Add medicine now", "💊 View my medicines", "📅 Today's schedule"]
        }

    # 11. History & CSV Export
    if any(k in low for k in ["history", "csv", "export", "download", "record", "doctor report"]):
        return {
            "reply": (
                "📑 **Medication History & CSV Export**:\n\n"
                "• Every dose taken, missed, or upcoming is logged with timestamps in **[History](/history)**.\n"
                "• Filter your records by **Today**, **This week**, or **This month**.\n"
                "• Click **'↓ Download CSV'** to generate a spreadsheet report you can share with your doctor or pharmacist!"
            ),
            "suggestions": ["📑 Open History", "📊 My adherence score", "💊 Today's medicines"]
        }

    # 12. App Settings & Personalization
    if any(k in low for k in ["theme", "dark mode", "light mode", "font", "text size", "settings"]):
        return {
            "reply": (
                "⚙️ **Personalization & Settings**:\n\n"
                "In **[Settings](/settings)**, you can:\n"
                "• Toggle between **Light Theme** and **Dark Theme**\n"
                "• Adjust text size between **Normal**, **Large**, and **Larger** for comfortable reading\n"
                "• Enable or mute the reminder chime\n"
                "• Toggle reminder popups on or off"
            ),
            "suggestions": ["⚙️ Go to Settings", "📊 My adherence score", "💊 Today's medicines"]
        }

    # 13. Conversational / General Fallback
    return {
        "reply": (
            "I'm here to help with any doubts about your care! You can ask me:\n\n"
            "• *'What is my next dose?'* or *'What medicines do I take today?'*\n"
            "• *'What should I do if I miss a dose?'*\n"
            "• *'How do reminders and snooze work?'*\n"
            "• *'How do I add a new medicine?'*\n"
            "• *'Who is my linked caregiver?'*\n"
            "• Or ask about any specific medicine on your plan!\n\n"
            "✦ *Note: Always consult your physician or pharmacist for medical diagnosis or prescription advice.*"
        ),
        "suggestions": ["⏰ What's my next dose?", "💊 Today's medicines", "⚠️ Missed dose guidance", "📊 My adherence score"]
    }


@app.route("/api/chat", methods=["POST"])
@login_required
def api_chat():
    user = current_user()
    data = request.get_json(silent=True) or request.form
    message = data.get("message", "").strip() if data else ""
    if not message:
        return jsonify({"error": "Message is required"}), 400
    response_data = chatbot_respond(user, message)
    return jsonify(response_data)


@app.route("/api/push-token", methods=["POST"])
@login_required
def register_push_token():
    data = request.get_json(silent=True) or {}
    token = str(data.get("token", "")).strip()
    if not token or len(token) > 4096:
        return jsonify({"error": "A device token is required"}), 400
    with connect_db() as db:
        db.execute(
            "INSERT OR REPLACE INTO push_tokens (user_id, token, created_at) VALUES (?, ?, ?)",
            (current_user()["id"], token, datetime.now().isoformat(timespec="seconds")),
        )
    return jsonify({"ok": True})


@app.route("/api/push-token", methods=["DELETE"])
@login_required
def unregister_push_token():
    data = request.get_json(silent=True) or {}
    token = str(data.get("token", "")).strip()
    with connect_db() as db:
        db.execute(
            "DELETE FROM push_tokens WHERE user_id = ? AND token = ?",
            (current_user()["id"], token),
        )
    return jsonify({"ok": True})


@app.route("/api/caregiver/doses")
@role_required("caregiver")
def api_caregiver_doses():
    selected_id = request.args.get("person", type=int)
    with connect_db() as db:
        linked = db.execute(
            "SELECT elderly_user_id FROM caregivers WHERE caregiver_id = ?",
            (current_user()["id"],),
        ).fetchall()
        if not any(row["elderly_user_id"] == selected_id for row in linked):
            return jsonify({"error": "Not linked to this person"}), 403
        sync_doses(selected_id)
        doses = get_today_doses(selected_id)
    return jsonify(
        {
            "doses": [
                {
                    "id": dose["id"],
                    "scheduled_time": dose["scheduled_time"],
                    "medicine_name": dose["medicine_name"],
                    "dosage": dose["dosage"],
                    "status": dose["status"],
                }
                for dose in doses
            ]
        }
    )


@app.errorhandler(404)
def not_found(_error):
    return render_template("404.html"), 404


init_db()


# =============================================================================
# Embedded UI: templates and static assets (single-file build)
# =============================================================================
from jinja2 import DictLoader  # noqa: E402
from flask import Response  # noqa: E402

TEMPLATES = {
    '404.html': r'''{% extends 'base.html' %}
{% block title %}Page not found | Smart PillPack{% endblock %}
{% block content %}<div class="empty-state empty-state-wide"><span class="empty-icon">?</span><h1>We couldn’t find that page</h1><p>It may have moved, or the link may be out of date.</p><a class="button button-primary" href="{{ url_for('dashboard') if current_user else url_for('login') }}">Go back</a></div>{% endblock %}
''',
    'base.html': r'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="theme-color" content="#f3f8f6">
  <title>{% block title %}Smart PillPack{% endblock %}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Manrope:wght@600;700;800&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="{{ url_for('static', filename='css/app.css') }}">
  {% if not current_user %}
  <script type="importmap">{"imports":{"three":"https://cdn.jsdelivr.net/npm/three@0.160.0/build/three.module.js","three/addons/":"https://cdn.jsdelivr.net/npm/three@0.160.0/examples/jsm/"}}</script>
  {% endif %}
</head>
<body class="{% if user_settings and user_settings['theme'] == 'dark' %}theme-dark{% endif %} font-{{ user_settings['font_size'] if user_settings else 'large' }}">
  {% if current_user %}
  <div class="app-shell">
    <aside class="sidebar" aria-label="Main navigation">
      <a class="brand" href="{{ url_for('dashboard') }}">
        <span class="brand-mark" aria-hidden="true">+</span>
        <span><strong>Smart PillPack</strong><small>Care, made clearer</small></span>
      </a>
      <nav class="side-nav">
        {% if current_user['role'] == 'user' %}
          <a class="nav-link {% if request.endpoint == 'dashboard' %}active{% endif %}" href="{{ url_for('dashboard') }}"><span aria-hidden="true">⌂</span>Home</a>
          <a class="nav-link {% if request.endpoint == 'medications' %}active{% endif %}" href="{{ url_for('medications') }}"><span aria-hidden="true">▤</span>My medicines</a>
          <a class="nav-link {% if request.endpoint in ['add_medication', 'edit_medication'] %}active{% endif %}" href="{{ url_for('add_medication') }}"><span aria-hidden="true">＋</span>Add medicine</a>
          <a class="nav-link {% if request.endpoint == 'history' %}active{% endif %}" href="{{ url_for('history') }}"><span aria-hidden="true">◷</span>History</a>
          <a class="nav-link {% if request.endpoint == 'profile' %}active{% endif %}" href="{{ url_for('profile') }}#caregiver-contact"><span aria-hidden="true">♡</span>Caregiver</a>
        {% else %}
          <a class="nav-link {% if request.endpoint == 'caregiver_dashboard' %}active{% endif %}" href="{{ url_for('caregiver_dashboard') }}"><span aria-hidden="true">⌂</span>Care overview</a>
        {% endif %}
        <a class="nav-link {% if request.endpoint == 'profile' %}active{% endif %}" href="{{ url_for('profile') }}"><span aria-hidden="true">◉</span>Profile</a>
        <a class="nav-link {% if request.endpoint == 'settings' %}active{% endif %}" href="{{ url_for('settings') }}"><span aria-hidden="true">⚙</span>Settings</a>
      </nav>
      <div class="sidebar-bottom">
        <div class="support-note"><span class="support-dot"></span><span>Here for your daily care</span></div>
        <form action="{{ url_for('logout') }}" method="post"><button class="nav-link logout-link" type="submit"><span aria-hidden="true">↪</span>Log out</button></form>
      </div>
    </aside>
    <div class="main-column">
      <header class="topbar">
        <div class="topbar-date">{{ today_label if today_label is defined else '' }}</div>
        <a class="profile-chip" href="{{ url_for('profile') }}" aria-label="Open profile for {{ current_user['name'] }}">
          <span class="avatar">{{ current_user['name'][0]|upper }}</span>
          <span class="profile-chip-name"><strong>{{ current_user['name'] }}</strong><small>{{ 'Caregiver' if current_user['role'] == 'caregiver' else 'My profile' }}</small></span>
        </a>
      </header>
      <main class="page-content">
        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}<div class="flash-list" role="status">{% for category, message in messages %}<div class="flash flash-{{ category }}">{{ message }}</div>{% endfor %}</div>{% endif %}
        {% endwith %}
        {% block content %}{% endblock %}
      </main>
    </div>
  </div>
  {% else %}
    <main class="auth-layout">
      <section class="auth-brand-panel">
        <div class="swarm" id="swarm" aria-hidden="true"></div>
        <a class="brand brand-light" href="{{ url_for('login') }}"><span class="brand-mark" aria-hidden="true">+</span><span><strong>Smart PillPack</strong><small>Care, made clearer</small></span></a>
        <div class="auth-message">
          <div class="eyebrow"><span class="pulse-dot"></span>Medication care, made simple</div>
          <h1>One less thing<br>to keep in mind.</h1>
          <p>A calm, clear way to stay on top of your daily medicines and keep the people who care about you in the loop.</p>
          <div class="auth-trust"><span aria-hidden="true">✓</span> Your schedule, your pace. Always within reach.</div>
        </div>
        <div class="brand-ornament ornament-one"></div><div class="brand-ornament ornament-two"></div>
        <span class="auth-panel-foot">Thoughtful support for everyday health</span><span class="swarm-caption" aria-hidden="true">Hendekeract · 2048 vertices of an 11-D hypercube</span>
      </section>
      <section class="auth-form-panel">
        <div class="auth-form-wrap">
          {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}<div class="flash-list" role="status">{% for category, message in messages %}<div class="flash flash-{{ category }}">{{ message }}</div>{% endfor %}</div>{% endif %}
          {% endwith %}
          {% block auth_content %}{% endblock %}
        </div>
      </section>
    </main>
  {% endif %}
  {% if current_user and current_user['role'] == 'user' %}
  <div class="dose-list-global" id="global-dose-list" hidden data-popup-enabled="{{ 1 if not user_settings or user_settings['reminder_popup'] else 0 }}" data-notifications-enabled="{{ 1 if not user_settings or user_settings['notifications'] else 0 }}" data-sound-enabled="{{ 1 if not user_settings or user_settings['reminder_sound'] else 0 }}">
    {% for dose in reminder_doses %}
    <article data-reminder-dose data-dose-id="{{ dose['id'] }}" data-time="{{ dose['scheduled_time'] }}" data-name="{{ dose['medicine_name'] }}" data-dosage="{{ dose['dosage'] }}" data-status="{{ dose['status'] }}"></article>
    {% endfor %}
  </div>
  <dialog class="reminder-dialog" id="reminder-dialog" aria-labelledby="reminder-title">
    <div class="reminder-emblem" aria-hidden="true">◷</div><span class="eyebrow">MEDICINE REMINDER</span><h2 id="reminder-title">It’s time to take your medicine.</h2>
    <p class="reminder-medicine" id="reminder-medicine"></p><p class="reminder-schedule" id="reminder-schedule"></p>
    <div class="reminder-actions"><form id="reminder-taken-form" method="post"><input type="hidden" name="next" value="{{ request.path }}"><button class="button button-primary button-full" type="submit">I’ve taken it</button></form><button class="button button-outline button-full" type="button" id="remind-later">Remind me in 5 minutes</button></div>
  </dialog>
  <div class="chatbot-container" id="chatbot-container" aria-label="Smart PillPack AI Assistant">
    <button class="chatbot-launcher" id="chatbot-launcher" type="button" aria-label="Open medication assistant chatbot" aria-expanded="false" title="Ask Smart PillPack Assistant">
      <span class="chatbot-icon-closed" aria-hidden="true">
        <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path>
          <path d="M12 7v6"></path>
          <path d="M9 10h6"></path>
        </svg>
      </span>
      <span class="chatbot-icon-open" aria-hidden="true">
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round">
          <line x1="18" y1="6" x2="6" y2="18"></line>
          <line x1="6" y1="6" x2="18" y2="18"></line>
        </svg>
      </span>
      <span class="chatbot-pulse-dot" aria-hidden="true"></span>
    </button>
    <div class="chatbot-tooltip" id="chatbot-tooltip">Need help with medicines? Ask me!</div>

    <div class="chatbot-window" id="chatbot-window" hidden role="dialog" aria-modal="false" aria-labelledby="chatbot-heading">
      <header class="chatbot-header">
        <div class="chatbot-header-profile">
          <span class="chatbot-avatar" aria-hidden="true">💊</span>
          <div>
            <h3 id="chatbot-heading">Care Assistant</h3>
            <span class="chatbot-badge"><span class="badge-dot"></span> Active · 24/7 Medication Guide</span>
          </div>
        </div>
        <div class="chatbot-header-actions">
          <button type="button" class="chatbot-btn-icon" id="chatbot-reset-btn" title="Clear & restart chat" aria-label="Restart chat">↺</button>
          <button type="button" class="chatbot-btn-icon chatbot-btn-close" id="chatbot-close-btn" title="Close chat (Esc)" aria-label="Close chat">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
              <line x1="18" y1="6" x2="6" y2="18"></line>
              <line x1="6" y1="6" x2="18" y2="18"></line>
            </svg>
          </button>
        </div>
      </header>

      <div class="chatbot-messages" id="chatbot-messages" role="log" aria-live="polite">
        <div class="chat-msg chat-msg-bot">
          <div class="msg-avatar" aria-hidden="true">✦</div>
          <div class="msg-bubble">
            <p>Hello <strong>{{ current_user['name'].split(' ')[0] }}</strong>! I'm your Smart PillPack care guide.</p>
            <p>I can help with your daily schedule, explain dosages, guide you on missed doses, or help you use any feature.</p>
          </div>
        </div>
        <div class="chatbot-suggestions" id="chatbot-suggestions">
          <span class="suggestions-heading">Common questions:</span>
          <button type="button" class="chip-btn" data-query="What is my next scheduled dose?">⏰ Next dose</button>
          <button type="button" class="chip-btn" data-query="What medicines do I have scheduled today?">💊 Today's medicines</button>
          <button type="button" class="chip-btn" data-query="What should I do if I miss a dose?">⚠️ Missed dose guidance</button>
          <button type="button" class="chip-btn" data-query="How is my medication adherence this week?">📊 Adherence score</button>
          <button type="button" class="chip-btn" data-query="How do reminder alarms work?">🔔 Reminders & snooze</button>
          <button type="button" class="chip-btn" data-query="How do I add a new medicine?">➕ Add medicine</button>
        </div>
      </div>

      <form class="chatbot-input-bar" id="chatbot-form">
        <input type="text" id="chatbot-input" placeholder="Ask a doubt about your medicines..." autocomplete="off" maxlength="300" required>
        <button type="submit" id="chatbot-send-btn" aria-label="Send message">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
            <line x1="22" y1="2" x2="11" y2="13"></line>
            <polygon points="22 2 15 22 11 13 2 9 22 2"></polygon>
          </svg>
        </button>
      </form>
      <div class="chatbot-disclaimer">✦ PillPack AI · For emergencies, consult your healthcare provider.</div>
    </div>
  </div>
  {% endif %}
  {% block dialogs %}{% endblock %}
  <script>window.__FIREBASE_WEB_CONFIG__ = {{ (firebase_web or {})|tojson }};</script>
  <script src="{{ url_for('static', filename='js/app.js') }}" defer></script>
  {% if not current_user %}<script type="module" src="{{ url_for('static', filename='js/swarm.js') }}"></script>{% endif %}
</body>
</html>
''',
    'caregiver.html': r'''{% extends 'base.html' %}
{% block title %}Care overview | Smart PillPack{% endblock %}
{% block content %}
<section class="welcome-row"><div><span class="eyebrow">CAREGIVER OVERVIEW</span><h1>Care, at a glance.</h1><p>Today’s medicine schedule and check-in for your loved one.</p></div>{% if people|length > 1 %}<form><label class="select-compact">Viewing<select name="person" onchange="this.form.submit()">{% for person_option in people %}<option value="{{ person_option['id'] }}" {% if person and person['id'] == person_option['id'] %}selected{% endif %}>{{ person_option['name'] }}</option>{% endfor %}</select></label></form>{% endif %}</section>
{% if person %}<section class="care-person-banner"><span class="avatar avatar-large">{{ person['name'][0]|upper }}</span><div><span class="eyebrow">TODAY’S PLAN FOR</span><h2>{{ person['name'] }}</h2><p>{{ person['age'] or 'Age not added' }}{% if person['age'] %} years old{% endif %} <span class="dot-separator">·</span> {{ person['caregiver_contact'] or 'No alternate contact added' }}</p></div><span class="care-date">{{ doses|length }} scheduled doses</span></section>
<section class="overview-grid caregiver-metrics"><article class="overview-card overview-card-green"><span class="overview-icon">✓</span><div><span class="metric-label">Adherence</span><strong>{{ adherence }}<small>%</small></strong><span class="metric-caption">completed doses today</span></div></article><article class="overview-card overview-card-blue"><span class="overview-icon">✓</span><div><span class="metric-label">Taken</span><strong>{{ taken }}</strong><span class="metric-caption">doses recorded</span></div></article><article class="overview-card overview-card-peach"><span class="overview-icon">!</span><div><span class="metric-label">Missed</span><strong>{{ missed }}</strong><span class="metric-caption">need a check-in</span></div></article><article class="overview-card overview-card-lilac"><span class="overview-icon">◷</span><div><span class="metric-label">Upcoming</span><strong>{{ upcoming }}</strong><span class="metric-caption">still scheduled today</span></div></article></section>
<section class="care-content-grid"><div class="section-panel"><div class="section-heading"><div><span class="eyebrow">TODAY</span><h2>Medication schedule</h2></div></div><div class="care-dose-list" id="care-dose-list" data-person="{{ person['id'] }}">{% for dose in doses %}<div class="care-dose-row"><span class="care-dose-time">{{ dose['scheduled_time']|clock }}</span><div class="care-dose-name"><strong>{{ dose['medicine_name'] }}</strong><small>{{ dose['dosage'] }}</small></div><span class="status-pill status-pill-{{ dose['status']|lower }}"><span></span>{{ dose['status'] }}</span>{% if dose['status'] in ['Upcoming', 'Missed'] %}<form method="post" action="{{ url_for('update_dose', dose_id=dose['id'], action='taken') }}" class="care-take-form"><input type="hidden" name="next" value="{{ url_for('caregiver_dashboard', person=person['id']) }}"><button class="button button-take button-small" type="submit">Mark taken</button></form>{% endif %}</div>{% else %}<p class="empty-inline">No medicines are scheduled for today.</p>{% endfor %}</div></div>
<aside class="alert-panel"><div class="alert-heading"><span class="alert-icon">!</span><div><span class="eyebrow">CHECK-IN</span><h2>Missed dose alerts</h2></div></div>{% for dose in alerts %}<article class="missed-alert"><strong>{{ person['name'] }} hasn’t marked {{ dose['medicine_name'] }} as taken.</strong><p>{{ dose['dosage'] }} · scheduled for {{ dose['scheduled_time']|clock }}</p></article>{% else %}<div class="all-clear"><span aria-hidden="true">✓</span><strong>All clear for now</strong><p>Missed doses will appear here.</p></div>{% endfor %}</aside></section>
<section class="section-panel push-panel"><div class="section-heading"><div><span class="eyebrow">ALERTS</span><h2>Push alerts</h2></div></div><p class="push-copy">Get a notification on this device the moment {{ person['name'].split()[0] }} misses a dose, so you can check in — even when this page is closed.</p>{% if firebase_ready and firebase_web.get('vapidKey') %}<button class="button button-outline" id="enable-push" type="button">Enable missed-dose alerts</button><small class="field-help" id="push-status">Alerts are sent to every device where you enable them.</small>{% else %}<small class="field-help">Push alerts are not configured on this server yet. Add a Firebase project and credentials to turn them on.</small>{% endif %}</section>
{% else %}<div class="empty-state empty-state-wide"><span class="empty-icon">♡</span><h2>No linked care profiles yet</h2><p>Ask the person you support to add your caregiver email on their profile.</p><a class="button button-outline" href="{{ url_for('profile') }}">View your profile</a></div>{% endif %}
{% endblock %}
''',
    'dashboard.html': r'''{% extends 'base.html' %}
{% block title %}Today | Smart PillPack{% endblock %}
{% block content %}
<section class="welcome-row">
  <div><span class="eyebrow">{{ now_label if now_label is defined else 'YOUR DAILY OVERVIEW' }}</span><h1>Good day, {{ current_user['name'].split(' ')[0] }} <span class="wave-mark" aria-hidden="true">✦</span></h1><p>Here’s your medication plan for today.</p></div>
  <a class="button button-primary" href="{{ url_for('add_medication') }}"><span class="button-icon" aria-hidden="true">＋</span> Add medicine</a>
</section>
<section class="overview-grid" aria-label="Today's overview">
  <article class="overview-card overview-card-green"><span class="overview-icon" aria-hidden="true">▤</span><div><span class="metric-label">On your list</span><strong>{{ active_count }}</strong><span class="metric-caption">active medicines</span></div></article>
  <article class="overview-card overview-card-blue"><span class="overview-icon" aria-hidden="true">◷</span><div><span class="metric-label">Still to come</span><strong>{{ doses|selectattr('status', 'equalto', 'Upcoming')|list|length }}</strong><span class="metric-caption">doses today</span></div></article>
  <article class="overview-card overview-card-peach"><span class="overview-icon" aria-hidden="true">✓</span><div><span class="metric-label">Done today</span><strong>{{ doses|selectattr('status', 'equalto', 'Taken')|list|length }}</strong><span class="metric-caption">doses taken</span></div></article>
</section>
<section class="dashboard-grid">
  <div class="section-panel medication-panel">
    <div class="section-heading"><div><span class="eyebrow">YOUR PLAN</span><h2>Today’s medicines</h2></div><a class="text-link" href="{{ url_for('medications') }}">View all <span aria-hidden="true">→</span></a></div>
    {% if doses %}<div class="dose-list" id="dose-list" data-popup-enabled="{{ 1 if not user_settings or user_settings['reminder_popup'] else 0 }}" data-notifications-enabled="{{ 1 if not user_settings or user_settings['notifications'] else 0 }}" data-sound-enabled="{{ 1 if user_settings and user_settings['reminder_sound'] else 0 }}">
      {% for dose in doses %}
      <article class="dose-card status-{{ dose['status']|lower }}" data-reminder-dose data-dose-id="{{ dose['id'] }}" data-time="{{ dose['scheduled_time'] }}" data-name="{{ dose['medicine_name'] }}" data-dosage="{{ dose['dosage'] }}" data-status="{{ dose['status'] }}">
        <div class="dose-time"><strong>{{ dose['scheduled_time']|clock }}</strong><span class="time-dot"></span></div>
        <div class="dose-main"><h3>{{ dose['medicine_name'] }}</h3><p>{{ dose['dosage'] }} <span class="dot-separator">·</span> {{ dose['food_instruction'] }}</p>{% if dose['notes'] %}<small>{{ dose['notes'] }}</small>{% endif %}</div>
        <div class="dose-action"><span class="status-pill status-pill-{{ dose['status']|lower }}"><span></span>{{ dose['status'] }}</span>
          {% if dose['status'] == 'Upcoming' %}<form method="post" action="{{ url_for('update_dose', dose_id=dose['id'], action='taken') }}"><input type="hidden" name="next" value="{{ url_for('dashboard') }}"><button class="button button-take" type="submit">Mark taken</button></form>
          {% elif dose['status'] == 'Taken' %}<span class="taken-time">Taken {{ dose['taken_time']|clock if dose['taken_time'] else '' }}</span>{% endif %}
        </div>
      </article>
      {% endfor %}
    </div>{% else %}<div class="empty-state"><span class="empty-icon">＋</span><h3>Your plan starts here</h3><p>Add a medicine and its schedule to see it here.</p><a class="button button-primary" href="{{ url_for('add_medication') }}">Add your first medicine</a></div>{% endif %}
  </div>
  <aside class="next-panel">
    <div class="next-panel-top"><span class="eyebrow">UP NEXT</span><span class="next-spark" aria-hidden="true">✳</span></div>
    {% if next_dose %}<div class="next-time">{{ next_dose['scheduled_time']|clock }}</div><span class="next-day-label">{{ next_dose['day_phrase'] }}</span><h2>{{ next_dose['medicine_name'] }}</h2><p>{{ next_dose['dosage'] }}{% if next_dose['food_instruction'] != 'Any time' %} · {{ next_dose['food_instruction'] }}{% endif %}</p><div class="next-divider"></div><p class="next-note"><span aria-hidden="true">◷</span> Your next medicine is {{ next_dose['medicine_name'] }} at {{ next_dose['scheduled_time']|clock }}, {{ next_dose['day_phrase'] }}.</p>
    {% else %}<div class="next-time next-time-done">✓</div><h2>No upcoming schedule</h2><p>There are no active medicines on your plan.</p><div class="next-divider"></div><p class="next-note">Add a medicine whenever you’re ready.</p>{% endif %}
    <a class="button button-outline button-full" href="{{ url_for('history') }}">See medication history</a>
  </aside>
</section>
<section class="weekly-panel section-panel" aria-labelledby="weekly-heading">
  <div class="weekly-heading-row"><div><span class="eyebrow">LAST 7 DAYS</span><h2 id="weekly-heading">Your consistency</h2></div>{% if weekly_adherence['percentage'] is not none %}<div class="weekly-score"><strong>{{ weekly_adherence['percentage'] }}%</strong><span>of recorded doses taken</span></div>{% endif %}</div>
  {% if weekly_adherence['total'] %}
  <div class="week-chart" role="group" aria-label="Daily adherence for the last seven days">
    {% for day in weekly_adherence['days'] %}<div class="week-day-column"><div class="week-bar-track" role="img" aria-label="{{ day['label'] }}: {{ day['taken'] }} of {{ day['total'] }} doses taken"><span class="week-bar" style="height: {{ day['adherence'] }}%"></span></div><span class="week-day-label">{{ day['label'] }}</span><span class="week-count">{{ day['taken'] }}/{{ day['total'] if day['total'] else '—' }}</span></div>{% endfor %}
  </div>
  <p class="weekly-caption">You took {{ weekly_adherence['taken'] }} of {{ weekly_adherence['total'] }} recorded doses this week.</p>
  {% else %}<div class="weekly-empty"><span aria-hidden="true">◷</span><p>Your weekly progress will appear as you record doses.</p></div>{% endif %}
</section>
{% endblock %}
''',
    'forgot_password.html': r'''{% extends 'base.html' %}
{% block title %}Account help | Smart PillPack{% endblock %}
{% block auth_content %}
<div class="auth-heading"><span class="eyebrow">ACCOUNT HELP</span><h2>Reset your password</h2><p>Enter the email address on your account. We&rsquo;ll send a 6-digit verification code to confirm it&rsquo;s you.</p></div>
<form class="form-stack" method="post">
  <label>Email address<input type="email" name="email" placeholder="you@example.com" required autofocus></label>
  <button class="button button-primary button-full" type="submit">Send verification code <span aria-hidden="true">→</span></button>
</form>
<p class="auth-switch"><a class="text-link" href="{{ url_for('login') }}">← Back to sign in</a></p>
<div class="demo-hint"><span aria-hidden="true">🔒</span><span>The code expires in 10 minutes and can be used once. Check your inbox and spam folder — it arrives within a minute. Demo addresses (like <code>ravi@pillpack.test</code>) can&rsquo;t receive email, so their code is shown on the next screen instead.</span></div>
{% endblock %}
''',
    'history.html': r'''{% extends 'base.html' %}
{% block title %}Medication history | Smart PillPack{% endblock %}
{% block content %}
<section class="page-heading"><div><span class="eyebrow">YOUR RECORD</span><h1>Medication history</h1><p>A clear record of scheduled and completed doses.</p></div><a class="button button-outline" href="{{ url_for('export_history', period=period) }}"><span aria-hidden="true">↓</span> Download CSV</a></section>
<div class="filter-row"><div class="segmented-control" role="group" aria-label="Filter history period"><a class="segment {% if period == 'today' %}selected{% endif %}" href="{{ url_for('history', period='today') }}">Today</a><a class="segment {% if period == 'week' %}selected{% endif %}" href="{{ url_for('history', period='week') }}">This week</a><a class="segment {% if period == 'month' %}selected{% endif %}" href="{{ url_for('history', period='month') }}">This month</a></div><span class="record-count">{{ records|length }} {{ 'record' if records|length == 1 else 'records' }}</span></div>
<section class="section-panel history-panel"><div class="history-table-wrap"><table class="history-table"><thead><tr><th>Date</th><th>Medicine</th><th>Scheduled</th><th>Status</th><th>Taken time</th></tr></thead><tbody>{% for record in records %}<tr><td data-label="Date">{{ record['date'] }}</td><td data-label="Medicine"><strong>{{ record['medicine_name'] }}</strong><small>{{ record['dosage'] }}</small></td><td data-label="Scheduled">{{ record['scheduled_time']|clock }}</td><td data-label="Status"><span class="status-pill status-pill-{{ record['status']|lower }}"><span></span>{{ record['status'] }}</span></td><td data-label="Taken time">{{ record['taken_time']|clock if record['taken_time'] else '—' }}</td></tr>{% else %}<tr><td class="table-empty" colspan="5">No medication records for this period.</td></tr>{% endfor %}</tbody></table></div></section>
{% endblock %}
''',
    'login.html': r'''{% extends 'base.html' %}
{% block title %}Sign in | Smart PillPack{% endblock %}
{% block auth_content %}
<div class="auth-heading"><span class="eyebrow">WELCOME BACK</span><h2>Sign in</h2><p>Your care routine is right where you left it.</p></div>
<form class="form-stack" method="post" action="{{ url_for('login') }}">
  <label>Email address<input type="email" name="email" id="login-email" autocomplete="username" placeholder="you@example.com" required autofocus></label>
  <label>Password<input type="password" name="password" id="login-password" autocomplete="current-password" placeholder="Enter your password" minlength="8" required></label>
  <div class="form-row form-row-between"><label class="check-label"><input type="checkbox" name="remember"> <span>Remember me</span></label><a class="text-link" href="{{ url_for('forgot_password') }}">Forgot password?</a></div>
  <fieldset class="role-choice"><legend>I am signing in as</legend><label class="choice-card"><input type="radio" name="role" id="role-user" value="user" checked><span class="choice-icon">◎</span><span><strong>Me</strong><small>Person taking medicine</small></span></label><label class="choice-card"><input type="radio" name="role" id="role-caregiver" value="caregiver"><span class="choice-icon">♡</span><span><strong>Caregiver</strong><small>Supporting someone</small></span></label></fieldset>
  <button class="button button-primary button-full" type="submit">Sign in <span aria-hidden="true">→</span></button>
</form>
<p class="auth-switch">New to Smart PillPack? <a class="text-link" href="{{ url_for('register') }}">Create an account</a></p>
<div class="demo-hint">
  <div class="demo-hint-title"><span aria-hidden="true">✳</span><span>Quick Demo Access (1-Click Fill):</span></div>
  <div class="demo-btn-group">
    <button type="button" class="demo-chip-btn" id="demo-fill-ravi" data-email="ravi@pillpack.test" data-role="user">
      <span>👤 <strong>Patient:</strong> ravi@pillpack.test</span>
      <span class="chip-badge">Fill</span>
    </button>
    <button type="button" class="demo-chip-btn" id="demo-fill-anita" data-email="anita@pillpack.test" data-role="caregiver">
      <span>♡ <strong>Caregiver:</strong> anita@pillpack.test</span>
      <span class="chip-badge">Fill</span>
    </button>
  </div>
  <small class="demo-pass-note">Password: <strong>demo1234</strong> · Auto-fills email, password & role</small>
</div>
{% endblock %}
''',
    'medication_form.html': r'''{% extends 'base.html' %}
{% set is_edit = medication is not none %}
{% set saved_times = (medication['time'].split(',') if medication else []) %}
{% block title %}{{ 'Edit' if is_edit else 'Add' }} medicine | Smart PillPack{% endblock %}
{% block content %}
<section class="page-heading"><div><span class="eyebrow">YOUR CARE PLAN</span><h1>{{ 'Edit medicine' if is_edit else 'Add a medicine' }}</h1><p>Enter the details just as they appear on your prescription.</p></div><a class="button button-outline" href="{{ url_for('medications') }}">Cancel</a></section>
<form class="edit-form section-panel" method="post">
  <div class="form-section-title"><span class="form-section-number">1</span><div><h2>Medicine details</h2><p>Name and strength help you recognize each dose.</p></div></div>
  <div class="form-grid"><label class="span-2">Medicine name<input name="medicine_name" value="{{ form.get('medicine_name', medication['medicine_name'] if medication else '') }}" placeholder="For example, Metformin" maxlength="100" required autofocus></label><label>Dosage<input name="dosage" value="{{ form.get('dosage', medication['dosage'] if medication else '') }}" placeholder="For example, 500 mg" required></label><label>Medicine type<select name="medicine_type">{% for item in ['Tablet', 'Capsule', 'Liquid', 'Other'] %}<option value="{{ item }}" {% if form.get('medicine_type', medication['medicine_type'] if medication else 'Tablet') == item %}selected{% endif %}>{{ item }}</option>{% endfor %}</select></label></div>
  <div class="form-section-title form-section-spaced"><span class="form-section-number">2</span><div><h2>When to take it</h2><p>Set each time you normally take this medicine.</p></div></div>
  <div class="form-grid"><label>Frequency<select name="frequency" id="frequency-select">{% for item in ['Once daily', 'Twice daily', 'Three times daily', 'Custom'] %}<option value="{{ item }}" {% if form.get('frequency', medication['frequency'] if medication else 'Once daily') == item %}selected{% endif %}>{{ item }}</option>{% endfor %}</select></label><div class="time-fields" id="time-fields"><span class="field-label">Scheduled time(s)</span>
    {% set entered_times = form.getlist('times') %}
    {% for index in range(3) %}<label class="time-input-wrap" data-time-slot="{{ index }}" {% if index > 0 and (form.get('frequency', medication['frequency'] if medication else 'Once daily') not in ['Twice daily', 'Three times daily', 'Custom']) %}hidden{% endif %}>{{ ['First time', 'Second time', 'Third time'][index] }}<input type="time" name="times" value="{{ entered_times[index] if entered_times|length > index else (saved_times[index] if saved_times|length > index else '') }}" {% if index == 0 %}required{% endif %}></label>{% endfor %}
    <button class="text-button" type="button" id="add-time-button" {% if form.get('frequency', medication['frequency'] if medication else 'Once daily') != 'Custom' %}hidden{% endif %}>＋ Add another time</button>
  </div><label>Start date<input type="date" name="start_date" value="{{ form.get('start_date', medication['start_date'] if medication else '') }}" required></label><label>End date <span class="optional">(optional)</span><input type="date" name="end_date" value="{{ form.get('end_date', medication['end_date'] if medication else '') }}"></label><label>Food instruction<select name="food_instruction">{% for item in ['Any time', 'Before food', 'After food', 'With food'] %}<option value="{{ item }}" {% if form.get('food_instruction', medication['food_instruction'] if medication else 'Any time') == item %}selected{% endif %}>{{ item }}</option>{% endfor %}</select></label><label class="span-2">Additional instructions <span class="optional">(optional)</span><textarea name="notes" rows="3" placeholder="Anything helpful to remember">{{ form.get('notes', medication['notes'] if medication else '') }}</textarea></label></div>
  <div class="form-footer"><span class="form-footnote">You can update this schedule any time.</span><div><a class="button button-outline" href="{{ url_for('medications') }}">Cancel</a><button class="button button-primary" type="submit">{{ 'Save changes' if is_edit else 'Save medicine' }}</button></div></div>
</form>
{% endblock %}
''',
    'medications.html': r'''{% extends 'base.html' %}
{% block title %}My medicines | Smart PillPack{% endblock %}
{% block content %}
<section class="page-heading"><div><span class="eyebrow">YOUR CARE PLAN</span><h1>My medicines</h1><p>Keep your current medicine schedule up to date.</p></div><a class="button button-primary" href="{{ url_for('add_medication') }}"><span aria-hidden="true">＋</span> Add medicine</a></section>
{% if medications %}<div class="medicine-library">{% for medication in medications %}
<article class="library-card"><div class="medicine-symbol" aria-hidden="true">✚</div><div class="library-main"><div class="library-title-row"><div><h2>{{ medication['medicine_name'] }}</h2><p>{{ medication['dosage'] }} <span class="dot-separator">·</span> {{ medication['medicine_type'] }}</p></div><span class="status-pill {% if medication['end_date'] and medication['end_date'] < today %}status-pill-missed{% else %}status-pill-upcoming{% endif %}"><span></span>{% if medication['end_date'] and medication['end_date'] < today %}Ended{% else %}Active{% endif %}</span></div><div class="medicine-details"><div><span class="detail-label">SCHEDULE</span><strong>{% for time in medication['time'].split(',') %}{{ time|clock }}{% if not loop.last %}<span class="dot-separator"> · </span>{% endif %}{% endfor %}</strong><small>{{ medication['frequency'] }}</small></div><div><span class="detail-label">FOOD</span><strong>{{ medication['food_instruction'] }}</strong><small>{{ medication['notes'] or 'No extra instructions' }}</small></div><div><span class="detail-label">DATES</span><strong>{{ medication['start_date']|replace('-', '/') }}{% if medication['end_date'] %} – {{ medication['end_date']|replace('-', '/') }}{% else %} onward{% endif %}</strong><small>Daily schedule</small></div></div></div><div class="library-actions"><a class="button button-small button-outline" href="{{ url_for('edit_medication', medication_id=medication['id']) }}">Edit</a><form method="post" action="{{ url_for('delete_medication', medication_id=medication['id']) }}" data-confirm="Remove {{ medication['medicine_name'] }} from your list?"><button class="button button-small button-danger-outline" type="submit">Delete</button></form></div></article>
{% endfor %}</div>{% else %}<div class="empty-state empty-state-wide"><span class="empty-icon">＋</span><h2>No medicines added yet</h2><p>Add your first schedule to build your daily plan.</p><a class="button button-primary" href="{{ url_for('add_medication') }}">Add a medicine</a></div>{% endif %}
{% endblock %}
''',
    'profile.html': r'''{% extends 'base.html' %}
{% block title %}Profile | Smart PillPack{% endblock %}
{% block content %}
<section class="page-heading"><div><span class="eyebrow">YOUR ACCOUNT</span><h1>Profile</h1><p>Keep your personal and care contact details current.</p></div></section>
<form class="section-panel profile-form form-stack" method="post"><div class="profile-intro"><span class="avatar avatar-large">{{ current_user['name'][0]|upper }}</span><div><h2>{{ current_user['name'] }}</h2><p>{{ 'Caregiver account' if current_user['role'] == 'caregiver' else 'Personal account' }}</p></div></div><div class="form-grid"><label>Full name<input name="name" value="{{ current_user['name'] }}" maxlength="100" required></label><label>Email address<input type="email" name="email" value="{{ current_user['email'] }}" required></label><label>Age<input type="number" name="age" min="1" max="120" value="{{ current_user['age'] or '' }}" placeholder="Not added"></label><label>Role<input value="{{ 'Caregiver' if current_user['role'] == 'caregiver' else 'Elderly person / User' }}" disabled></label><label class="span-2" id="caregiver-contact">Emergency / caregiver contact<input name="caregiver_contact" value="{{ current_user['caregiver_contact'] }}" placeholder="Email or phone number"><small class="field-help">For a caregiver account, this is your emergency contact. For a user account, entering a registered caregiver’s email links their overview.</small></label></div><div class="form-footer"><span class="form-footnote">Your sign-in password is not changed here.</span><button class="button button-primary" type="submit">Save profile</button></div></form>
{% endblock %}
''',
    'register.html': r'''{% extends 'base.html' %}
{% block title %}Create account | Smart PillPack{% endblock %}
{% block auth_content %}
<div class="auth-heading"><span class="eyebrow">GET STARTED</span><h2>Create your account</h2><p>A few details to make your care personal.</p></div>
<form class="form-stack" method="post" action="{{ url_for('register') }}">
  <label>Full name<input name="name" autocomplete="name" value="{{ form.get('name', '') }}" placeholder="Your full name" maxlength="100" required></label>
  <div class="form-row"><label>Email address<input type="email" name="email" autocomplete="email" value="{{ form.get('email', '') }}" placeholder="you@example.com" required></label><label>Age <span class="optional">(optional)</span><input type="number" name="age" min="1" max="120" value="{{ form.get('age', '') }}" placeholder="Age"></label></div>
  <div class="form-row"><label>Password<input type="password" name="password" autocomplete="new-password" minlength="8" placeholder="At least 8 characters" required></label><label>Confirm password<input type="password" name="confirm_password" autocomplete="new-password" minlength="8" placeholder="Enter it again" required></label></div>
  <label>Account type<select name="role"><option value="user" {% if form.get('role', 'user') == 'user' %}selected{% endif %}>Elderly person / User</option><option value="caregiver" {% if form.get('role') == 'caregiver' %}selected{% endif %}>Caregiver</option></select></label>
  <label>Caregiver contact <span class="optional">(optional email or phone)</span><input name="caregiver_contact" value="{{ form.get('caregiver_contact', '') }}" placeholder="A trusted person's contact"></label>
  <button class="button button-primary button-full" type="submit">Create account <span aria-hidden="true">→</span></button>
</form>
<p class="auth-switch">Already have an account? <a class="text-link" href="{{ url_for('login') }}">Sign in</a></p>
{% endblock %}
''',
    'reset_password.html': r'''{% extends 'base.html' %}
{% block title %}Reset password | Smart PillPack{% endblock %}
{% block auth_content %}
<div class="auth-heading"><span class="eyebrow">CODE VERIFIED</span><h2>Choose a new password</h2><p>Your email is verified. Use at least 8 characters for your new sign-in password.</p></div>
<form class="form-stack" method="post">
  <label>New password<input type="password" name="password" autocomplete="new-password" minlength="8" required autofocus></label>
  <label>Confirm password<input type="password" name="confirm_password" autocomplete="new-password" minlength="8" required></label>
  <button class="button button-primary button-full" type="submit">Reset password <span aria-hidden="true">→</span></button>
</form>
<p class="auth-switch"><a class="text-link" href="{{ url_for('login') }}">Back to sign in</a></p>
{% endblock %}
''',
    'settings.html': r'''{% extends 'base.html' %}
{% block title %}Settings | Smart PillPack{% endblock %}
{% block content %}
<section class="page-heading"><div><span class="eyebrow">MAKE IT YOURS</span><h1>Settings</h1><p>Choose the reminders and display that work best for you.</p></div></section>
<form class="settings-form" method="post"><section class="section-panel settings-section"><div class="settings-section-heading"><span class="settings-icon">◷</span><div><h2>Reminders</h2><p>Control how you hear about a scheduled dose.</p></div></div><label class="setting-row"><span><strong>Browser notifications</strong><small>Show a notification when a dose is due.</small></span><input class="switch" type="checkbox" name="notifications" {% if user_settings['notifications'] %}checked{% endif %}></label><button class="text-button browser-notification-button" type="button" id="enable-notifications">Enable browser notifications</button><label class="setting-row"><span><strong>Reminder popup</strong><small>Show a large reminder while the dashboard is open.</small></span><input class="switch" type="checkbox" name="reminder_popup" {% if user_settings['reminder_popup'] %}checked{% endif %}></label><label class="setting-row"><span><strong>Reminder sound</strong><small>Play a gentle tone with the popup.</small></span><input class="switch" type="checkbox" name="reminder_sound" {% if user_settings['reminder_sound'] %}checked{% endif %}></label></section>
<section class="section-panel settings-section"><div class="settings-section-heading"><span class="settings-icon">◐</span><div><h2>Display</h2><p>Adjust the screen for your comfort.</p></div></div><fieldset class="setting-row setting-choice"><legend><strong>Text size</strong><small>Choose a comfortable reading size.</small></legend><div class="segmented-control"><label class="segment"><input type="radio" name="font_size" value="normal" {% if user_settings['font_size'] == 'normal' %}checked{% endif %}>Normal</label><label class="segment"><input type="radio" name="font_size" value="large" {% if user_settings['font_size'] == 'large' %}checked{% endif %}>Large</label><label class="segment"><input type="radio" name="font_size" value="larger" {% if user_settings['font_size'] == 'larger' %}checked{% endif %}>Larger</label></div></fieldset><fieldset class="setting-row setting-choice"><legend><strong>Color theme</strong><small>Pick the display with the clearest contrast for you.</small></legend><div class="segmented-control"><label class="segment"><input type="radio" name="theme" value="light" {% if user_settings['theme'] == 'light' %}checked{% endif %}>Light</label><label class="segment"><input type="radio" name="theme" value="dark" {% if user_settings['theme'] == 'dark' %}checked{% endif %}>Dark</label></div></fieldset></section>
<div class="settings-footer"><a class="button button-outline" href="{{ url_for('dashboard') }}">Cancel</a><button class="button button-primary" type="submit">Save settings</button></div></form>
{% endblock %}
''',
    'verify_otp.html': r'''{% extends 'base.html' %}
{% block title %}Enter verification code | Smart PillPack{% endblock %}
{% block auth_content %}
<div class="auth-heading"><span class="eyebrow">VERIFY YOUR EMAIL</span><h2>Enter the 6-digit code</h2><p>We sent it to <strong>{{ masked_email }}</strong>. The code expires in 10 minutes.</p></div>
{% if dev_otp %}
<div class="dev-reset-card" role="alert">
  <div class="dev-reset-header"><span aria-hidden="true">✉️</span> <strong>Verification code (shown here)</strong></div>
  <p>Code for <strong>{{ dev_otp_email }}</strong>. This address can&rsquo;t receive email, so the code is shown here:</p>
  <div class="dev-otp-code" aria-label="Verification code">{{ dev_otp }}</div>
  <small class="dev-reset-note">Archived to <code>instance/sent_emails.log</code></small>
</div>
{% endif %}
<form class="form-stack otp-form" method="post" id="otp-form" autocomplete="one-time-code">
  <fieldset class="otp-fieldset">
    <legend class="otp-legend">Verification code</legend>
    <div class="otp-boxes">
      {% for index in range(6) %}<input class="otp-box" type="text" inputmode="numeric" pattern="[0-9]*" maxlength="1" name="code" aria-label="Digit {{ index + 1 }}" {% if index == 0 and not dev_otp %}autofocus{% endif %} required>{% endfor %}
    </div>
  </fieldset>
  <button class="button button-primary button-full" type="submit">Verify code <span aria-hidden="true">→</span></button>
</form>
<div class="otp-resend">
  <form method="post" action="{{ url_for('resend_otp') }}">
    <button class="text-button" type="submit" id="resend-button" {% if resend_in > 0 %}disabled{% endif %}>{% if resend_in > 0 %}{{ resend_label }}{% else %}Resend code{% endif %}</button>
  </form>
  <a class="text-link" href="{{ url_for('forgot_password') }}">Use a different email</a>
</div>
<p class="auth-switch"><a class="text-link" href="{{ url_for('login') }}">← Back to sign in</a></p>
<script>
(function () {
  var boxes = Array.prototype.slice.call(document.querySelectorAll('.otp-box'));
  var form = document.getElementById('otp-form');
  var resendButton = document.getElementById('resend-button');
  var remaining = {{ resend_in|int }};
  var filled = function () { return boxes.every(function (box) { return box.value.length === 1; }); };

  boxes.forEach(function (box, index) {
    box.addEventListener('input', function () {
      box.value = box.value.replace(/\D/g, '').slice(0, 1);
      if (box.value && index < boxes.length - 1) boxes[index + 1].focus();
      if (filled()) form.requestSubmit();
    });
    box.addEventListener('keydown', function (event) {
      if (event.key === 'Backspace' && !box.value && index > 0) {
        boxes[index - 1].focus();
        boxes[index - 1].value = '';
        event.preventDefault();
      }
      if (event.key === 'ArrowLeft' && index > 0) boxes[index - 1].focus();
      if (event.key === 'ArrowRight' && index < boxes.length - 1) boxes[index + 1].focus();
    });
    box.addEventListener('paste', function (event) {
      var text = ((event.clipboardData || window.clipboardData).getData('text') || '').replace(/\D/g, '');
      if (!text) return;
      event.preventDefault();
      boxes.forEach(function (target, position) { target.value = text[position] || ''; });
      boxes[Math.min(text.length, boxes.length) - 1].focus();
      if (filled()) form.requestSubmit();
    });
  });

  function formatWait(seconds) {
    if (seconds >= 60) {
      var minutes = Math.ceil(seconds / 60);
      return 'Resend code in ' + minutes + ' min';
    }
    return 'Resend code in ' + seconds + 's';
  }
  if (remaining > 0) {
    var timer = setInterval(function () {
      remaining -= 1;
      if (remaining <= 0) {
        clearInterval(timer);
        resendButton.disabled = false;
        resendButton.textContent = 'Resend code';
      } else {
        resendButton.textContent = formatWait(remaining);
      }
    }, 1000);
  }
})();
</script>
{% endblock %}
''',
}

STATIC_ASSETS = {
    'css/app.css': r''':root {
  color-scheme: light;
  --ink: #183a3b;
  --muted: #667a78;
  --quiet: #8a9b98;
  --line: #dce8e4;
  --paper: #ffffff;
  --canvas: #f4f8f6;
  --mint: #e7f4ee;
  --green: #23765f;
  --green-dark: #175b49;
  --blue: #e9f2f8;
  --blue-ink: #3d6e87;
  --peach: #fbefe5;
  --peach-ink: #a25e37;
  --lilac: #f0edf8;
  --red: #a54646;
  --shadow: 0 12px 34px rgba(30, 73, 65, .055);
  font-family: "DM Sans", "Segoe UI", sans-serif;
  font-size: 16px;
}

* { box-sizing: border-box; }
body { margin: 0; min-width: 320px; color: var(--ink); background: var(--canvas); font-size: 1rem; line-height: 1.5; }
button, input, select, textarea { font: inherit; }
a { color: inherit; }
button, a, input, select, textarea { -webkit-tap-highlight-color: transparent; }
button:focus-visible, a:focus-visible, input:focus-visible, select:focus-visible, textarea:focus-visible { outline: 3px solid #76b8a5; outline-offset: 3px; }
h1, h2, h3, p { margin-top: 0; }
h1, h2, h3, .brand strong { font-family: "Manrope", "DM Sans", sans-serif; letter-spacing: 0; }
h1 { margin-bottom: 8px; font-size: 2rem; line-height: 1.2; font-weight: 800; }
h2 { margin-bottom: 8px; font-size: 1.25rem; line-height: 1.3; }
h3 { margin-bottom: 5px; font-size: 1.05rem; line-height: 1.3; }
p { color: var(--muted); }
.app-shell { min-height: 100vh; }
.sidebar { position: fixed; inset: 0 auto 0 0; z-index: 10; display: flex; width: 252px; flex-direction: column; padding: 28px 18px 20px; border-right: 1px solid var(--line); background: #fbfdfc; }
.brand { display: flex; align-items: center; gap: 11px; margin: 0 8px 47px; color: var(--ink); text-decoration: none; }
.brand-mark { display: grid; width: 42px; height: 42px; flex: 0 0 auto; place-items: center; border-radius: 14px; background: var(--green); color: white; font: 700 1.8rem/1 "DM Sans", sans-serif; box-shadow: 0 6px 14px rgba(35, 118, 95, .18); }
.brand strong { display: block; font-size: 1rem; line-height: 1.3; }
.brand small { display: block; margin-top: 2px; color: var(--muted); font-size: .76rem; }
.side-nav { display: grid; gap: 6px; }
.nav-link { display: flex; min-height: 48px; align-items: center; gap: 13px; padding: 9px 13px; border: 0; border-radius: 8px; background: transparent; color: #536866; font-size: .96rem; font-weight: 600; text-align: left; text-decoration: none; cursor: pointer; transition: background .16s ease, color .16s ease; }
.nav-link > span { display: grid; width: 22px; place-items: center; color: #7d9690; font-size: 1.18rem; }
.nav-link:hover { background: #eef5f1; color: var(--green-dark); }
.nav-link.active { background: #e9f4ef; color: var(--green-dark); }
.nav-link.active > span { color: var(--green); }
.sidebar-bottom { margin-top: auto; }
.support-note { display: flex; align-items: center; gap: 9px; margin: 0 10px 14px; padding: 13px 0; border-top: 1px solid var(--line); color: var(--muted); font-size: .81rem; }
.support-dot, .pulse-dot { width: 8px; height: 8px; flex: 0 0 auto; border-radius: 50%; background: #59a882; }
.sidebar-bottom form { margin: 0; }
.logout-link { width: 100%; }
.main-column { min-height: 100vh; margin-left: 252px; }
.topbar { display: flex; height: 78px; align-items: center; justify-content: flex-end; gap: 24px; padding: 0 clamp(24px, 4vw, 58px); border-bottom: 1px solid rgba(220, 232, 228, .8); background: rgba(255, 255, 255, .64); }
.topbar-date { margin-right: auto; color: var(--muted); font-size: .91rem; }
.profile-chip { display: flex; align-items: center; gap: 10px; text-decoration: none; }
.avatar { display: grid; width: 40px; height: 40px; flex: 0 0 auto; place-items: center; border: 1px solid #cfe4d9; border-radius: 50%; background: #e6f2eb; color: var(--green-dark); font-family: "Manrope", sans-serif; font-weight: 800; }
.avatar-large { width: 58px; height: 58px; font-size: 1.3rem; }
.profile-chip-name strong, .profile-chip-name small { display: block; }
.profile-chip-name strong { font-size: .88rem; }
.profile-chip-name small { color: var(--muted); font-size: .77rem; }
.page-content { width: min(1440px, 100%); margin: 0 auto; padding: 42px clamp(24px, 4vw, 58px) 64px; }
.welcome-row, .page-heading { display: flex; align-items: center; justify-content: space-between; gap: 24px; margin-bottom: 28px; }
.welcome-row p, .page-heading p { margin-bottom: 0; font-size: 1rem; }
.eyebrow { display: block; margin-bottom: 7px; color: #64837a; font-size: .73rem; font-weight: 700; letter-spacing: .08em; }
.wave-mark { color: #79a98b; font-size: 1.2rem; vertical-align: 10%; }
.button { display: inline-flex; min-height: 48px; align-items: center; justify-content: center; gap: 8px; padding: 11px 17px; border: 1px solid transparent; border-radius: 8px; font-weight: 700; line-height: 1.2; text-decoration: none; cursor: pointer; transition: background .15s ease, border-color .15s ease, transform .15s ease; }
.button:hover { transform: translateY(-1px); }
.button-primary { background: var(--green); color: white; }
.button-primary:hover { background: var(--green-dark); }
.button-outline { border-color: #cdded8; background: white; color: var(--green-dark); }
.button-outline:hover { border-color: #8eafa2; background: #f5faf7; }
.button-full { width: 100%; }
.button-small { min-height: 40px; padding: 8px 13px; font-size: .88rem; }
.button-danger-outline { border-color: #ebcfcb; background: white; color: var(--red); }
.button-danger-outline:hover { background: #fff6f4; }
.button-icon { font-size: 1.25rem; line-height: .8; }
.overview-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 16px; margin-bottom: 25px; }
.overview-card { display: flex; min-height: 125px; align-items: center; gap: 16px; padding: 21px 22px; border: 1px solid rgba(220, 232, 228, .75); border-radius: 8px; background: var(--paper); box-shadow: var(--shadow); }
.overview-card-green { background: #eff7f2; }
.overview-card-blue { background: #f0f6f9; }
.overview-card-peach { background: #fcf4ec; }
.overview-card-lilac { background: #f2f0f8; }
.overview-icon { display: grid; width: 48px; height: 48px; flex: 0 0 auto; place-items: center; border-radius: 15px; background: rgba(255, 255, 255, .78); color: var(--green); font-size: 1.4rem; font-weight: 700; }
.overview-card-blue .overview-icon { color: var(--blue-ink); }
.overview-card-peach .overview-icon { color: var(--peach-ink); }
.overview-card-lilac .overview-icon { color: #695c8e; }
.metric-label, .metric-caption { display: block; color: var(--muted); }
.metric-label { margin-bottom: 1px; font-size: .84rem; }
.overview-card strong { display: block; color: var(--ink); font: 800 1.7rem/1.2 "Manrope", sans-serif; }
.overview-card strong small { font-size: 1rem; }
.metric-caption { margin-top: 1px; font-size: .78rem; }
.dashboard-grid { display: grid; grid-template-columns: minmax(0, 1.8fr) minmax(260px, .82fr); align-items: start; gap: 20px; }
.section-panel { border: 1px solid var(--line); border-radius: 8px; background: var(--paper); box-shadow: var(--shadow); }
.medication-panel { padding: 23px 24px 12px; }
.section-heading { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 12px; }
.section-heading h2 { margin-bottom: 0; }
.section-heading .eyebrow { margin-bottom: 3px; }
.text-link { color: var(--green-dark); font-size: .9rem; font-weight: 700; text-decoration: none; }
.text-link:hover { text-decoration: underline; text-underline-offset: 3px; }
.dose-list { display: grid; }
.dose-card { display: grid; grid-template-columns: 94px minmax(0, 1fr) auto; align-items: center; gap: 15px; min-height: 108px; padding: 17px 0; border-top: 1px solid #e8efec; }
.dose-time { display: flex; align-items: center; gap: 9px; color: #45615c; font-size: .84rem; font-weight: 700; white-space: nowrap; }
.time-dot { width: 7px; height: 7px; border-radius: 50%; background: #72a990; }
.status-missed .time-dot { background: #c57563; }
.status-taken .time-dot { background: #4b9873; }
.dose-main h3 { margin: 0 0 2px; font-size: 1.02rem; }
.dose-main p { margin: 0; font-size: .88rem; }
.dose-main small { display: block; margin-top: 3px; color: var(--quiet); font-size: .8rem; }
.dot-separator { margin: 0 4px; color: #9bb0aa; }
.dose-action { display: flex; min-width: 112px; flex-direction: column; align-items: flex-end; gap: 8px; }
.status-pill { display: inline-flex; align-items: center; gap: 6px; white-space: nowrap; color: #627570; font-size: .78rem; font-weight: 700; }
.status-pill > span { width: 7px; height: 7px; border-radius: 50%; background: #87a39a; }
.status-pill-upcoming > span, .status-pill-active > span { background: #5f9e7c; }
.status-pill-taken > span { background: #39815f; }
.status-pill-missed > span { background: #bb6557; }
.status-pill-skipped > span { background: #8b7ba9; }
.button-take { min-height: 39px; padding: 8px 12px; border-radius: 7px; background: #e8f4ed; color: #21634d; font-size: .83rem; }
.button-take:hover { background: #d9eddf; }
.dose-action form { margin: 0; }
.taken-time { color: var(--muted); font-size: .78rem; }
.next-panel { position: relative; overflow: hidden; padding: 23px 23px 22px; border: 1px solid #d8e6e1; border-radius: 8px; background: #eaf4ef; }
.next-panel::after { position: absolute; top: -54px; right: -54px; width: 150px; height: 150px; border: 1px solid rgba(61, 129, 101, .12); border-radius: 50%; content: ""; box-shadow: 0 0 0 17px rgba(61, 129, 101, .035), 0 0 0 34px rgba(61, 129, 101, .025); }
.next-panel-top { display: flex; align-items: center; justify-content: space-between; }
.next-spark { color: #65a284; font-size: 1.4rem; }
.next-time { margin: 19px 0 2px; color: var(--green); font: 800 2.25rem/1.2 "Manrope", sans-serif; }
.next-day-label { display: inline-block; margin: 2px 0 7px; color: #55796a; font-size: .81rem; font-weight: 700; text-transform: capitalize; }
.next-time-done { display: grid; width: 48px; height: 48px; place-items: center; border-radius: 50%; background: #d8ecdf; font-size: 1.4rem; }
.next-panel h2 { margin-bottom: 4px; font-size: 1.3rem; }
.next-panel > p { margin-bottom: 0; font-size: .9rem; }
.next-divider { height: 1px; margin: 20px 0 15px; background: #d3e4dc; }
.next-panel .next-note { display: flex; gap: 8px; min-height: 38px; align-items: flex-start; margin-bottom: 15px; color: #58766a; font-size: .83rem; }
.next-note span { font-size: 1rem; }
.weekly-panel { margin-top: 20px; padding: 22px 24px 16px; }
.weekly-heading-row { display: flex; align-items: center; justify-content: space-between; gap: 16px; }
.weekly-heading-row .eyebrow { margin-bottom: 3px; }
.weekly-heading-row h2 { margin-bottom: 0; }
.weekly-score { display: flex; align-items: baseline; gap: 8px; }
.weekly-score strong { color: var(--green); font: 800 1.5rem/1 "Manrope", sans-serif; }
.weekly-score span, .weekly-caption { color: var(--muted); font-size: .82rem; }
.week-chart { display: grid; height: 160px; grid-template-columns: repeat(7, minmax(0, 1fr)); gap: 14px; margin-top: 14px; padding: 0 5px; }
.week-day-column { display: grid; min-width: 0; grid-template-rows: 1fr auto auto; justify-items: center; gap: 5px; }
.week-bar-track { display: flex; width: min(34px, 70%); height: 100%; align-items: flex-end; overflow: hidden; border-radius: 6px; background: #eef4f1; }
.week-bar { display: block; width: 100%; min-height: 3px; border-radius: 6px 6px 2px 2px; background: #5c9d7b; }
.week-day-label { color: var(--muted); font-size: .75rem; font-weight: 700; }
.week-count { color: var(--quiet); font-size: .7rem; }
.weekly-caption { margin: 8px 0 0; text-align: center; }
.weekly-empty { display: flex; min-height: 93px; align-items: center; gap: 11px; color: #6a897b; }
.weekly-empty > span { display: grid; width: 35px; height: 35px; flex: 0 0 auto; place-items: center; border-radius: 11px; background: #edf5f0; }
.weekly-empty p { margin: 0; font-size: .86rem; }
.empty-state { display: flex; min-height: 320px; flex-direction: column; align-items: center; justify-content: center; padding: 25px; text-align: center; }
.empty-state-wide { min-height: 370px; border: 1px dashed #cbdcd5; border-radius: 8px; background: rgba(255, 255, 255, .65); }
.empty-state h2, .empty-state h3 { margin-bottom: 6px; }
.empty-state p { max-width: 390px; margin-bottom: 18px; }
.empty-icon { display: grid; width: 54px; height: 54px; margin-bottom: 15px; place-items: center; border-radius: 17px; background: #e8f3ed; color: var(--green); font-size: 1.7rem; }
.page-heading { margin-bottom: 28px; }
.page-heading h1 { margin-bottom: 7px; }
.page-heading > .button { flex: 0 0 auto; }
.medicine-library { display: grid; gap: 13px; }
.library-card { display: grid; grid-template-columns: 52px minmax(0, 1fr) auto; gap: 17px; align-items: start; padding: 21px 22px; border: 1px solid var(--line); border-radius: 8px; background: var(--paper); box-shadow: var(--shadow); }
.medicine-symbol { display: grid; width: 48px; height: 48px; place-items: center; border-radius: 15px; background: #edf5f0; color: var(--green); font-size: 1.35rem; }
.library-title-row { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; }
.library-title-row h2 { margin: 0 0 3px; font-size: 1.15rem; }
.library-title-row p { margin: 0; font-size: .9rem; }
.medicine-details { display: grid; grid-template-columns: 1fr 1.3fr 1.2fr; gap: 18px; margin-top: 19px; padding-top: 15px; border-top: 1px solid #e8efec; }
.medicine-details > div { min-width: 0; }
.detail-label { display: block; margin-bottom: 4px; color: var(--quiet); font-size: .69rem; font-weight: 700; letter-spacing: .06em; }
.medicine-details strong, .medicine-details small { display: block; overflow-wrap: anywhere; }
.medicine-details strong { font-size: .86rem; }
.medicine-details small { margin-top: 2px; color: var(--muted); font-size: .78rem; }
.library-actions { display: flex; gap: 7px; }
.library-actions form { margin: 0; }
.filter-row { display: flex; align-items: center; justify-content: space-between; margin: 0 0 16px; }
.segmented-control { display: inline-flex; flex-wrap: wrap; gap: 3px; padding: 4px; border: 1px solid #dce7e2; border-radius: 8px; background: #eef4f1; }
.segment { display: inline-flex; min-height: 38px; align-items: center; justify-content: center; padding: 7px 14px; border-radius: 6px; color: #647872; font-size: .86rem; font-weight: 600; text-decoration: none; cursor: pointer; }
.segment.selected { background: white; color: var(--green-dark); box-shadow: 0 1px 4px rgba(38, 76, 65, .1); }
.record-count { color: var(--muted); font-size: .86rem; }
.history-panel { overflow: hidden; }
.history-table { width: 100%; border-collapse: collapse; text-align: left; }
.history-table th { padding: 14px 17px; border-bottom: 1px solid var(--line); background: #f6faf8; color: #6d817b; font-size: .72rem; font-weight: 700; letter-spacing: .055em; text-transform: uppercase; }
.history-table td { padding: 15px 17px; border-bottom: 1px solid #edf2ef; color: #526762; font-size: .9rem; }
.history-table tbody tr:last-child td { border-bottom: 0; }
.history-table td strong, .history-table td small { display: block; }
.history-table td strong { color: var(--ink); }
.history-table td small { color: var(--muted); font-size: .8rem; }
.table-empty { padding: 35px !important; color: var(--muted) !important; text-align: center; }
.edit-form { padding: 27px clamp(20px, 4vw, 40px) 0; }
.form-section-title { display: flex; align-items: flex-start; gap: 12px; margin-bottom: 18px; }
.form-section-title h2 { margin: 0 0 3px; font-size: 1.08rem; }
.form-section-title p { margin: 0; font-size: .86rem; }
.form-section-number { display: grid; width: 30px; height: 30px; flex: 0 0 auto; place-items: center; border-radius: 10px; background: #e7f3ec; color: var(--green); font-weight: 800; }
.form-section-spaced { margin-top: 30px; padding-top: 25px; border-top: 1px solid var(--line); }
.form-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 17px 20px; padding-left: 42px; }
.form-grid label, .form-stack > label, .form-row > label, .time-input-wrap { display: flex; min-width: 0; flex-direction: column; gap: 7px; color: #344e4a; font-size: .88rem; font-weight: 700; }
.form-grid input, .form-grid select, .form-grid textarea, .form-stack input:not([type=checkbox]):not([type=radio]), .form-stack select, .form-row input, .select-compact select { width: 100%; min-height: 48px; padding: 10px 12px; border: 1px solid #cfddd7; border-radius: 7px; background: white; color: var(--ink); font-weight: 500; }
input::placeholder, textarea::placeholder { color: #98a9a4; }
.form-grid textarea { min-height: 90px; resize: vertical; }
.span-2 { grid-column: span 2; }
.time-fields { display: grid; grid-column: span 2; grid-template-columns: repeat(3, minmax(0, 1fr)); align-items: end; gap: 10px; }
.field-label { grid-column: 1 / -1; margin-bottom: -5px; color: #344e4a; font-size: .88rem; font-weight: 700; }
.time-input-wrap { font-size: .78rem; }
.time-input-wrap[hidden] { display: none; }
.time-input-wrap input { padding: 8px !important; }
.text-button { width: fit-content; padding: 6px 0; border: 0; background: transparent; color: var(--green-dark); font-size: .86rem; font-weight: 700; text-align: left; cursor: pointer; }
.text-button:hover { text-decoration: underline; text-underline-offset: 3px; }
.form-footer { display: flex; align-items: center; justify-content: space-between; gap: 15px; margin: 28px calc(clamp(20px, 4vw, 40px) * -1) 0; padding: 18px clamp(20px, 4vw, 40px); border-top: 1px solid var(--line); background: #fbfdfc; }
.form-footer > div { display: flex; gap: 9px; }
.form-footnote, .optional { color: var(--quiet); font-size: .79rem; font-weight: 400; }
.profile-form { max-width: 850px; padding: 25px clamp(20px, 4vw, 38px) 0; }
.profile-intro { display: flex; align-items: center; gap: 15px; margin-bottom: 25px; padding-bottom: 20px; border-bottom: 1px solid var(--line); }
.profile-intro h2 { margin: 0 0 2px; }
.profile-intro p { margin: 0; font-size: .88rem; }
.field-help { color: var(--muted); font-size: .78rem; font-weight: 400; line-height: 1.4; }
.settings-form { display: grid; max-width: 850px; gap: 15px; }
.settings-section { padding: 22px 26px; }
.settings-section-heading { display: flex; align-items: center; gap: 12px; margin-bottom: 13px; }
.settings-section-heading h2 { margin: 0 0 2px; }
.settings-section-heading p { margin: 0; font-size: .86rem; }
.settings-icon { display: grid; width: 42px; height: 42px; place-items: center; border-radius: 13px; background: #eaf4ef; color: var(--green); font-size: 1.25rem; }
.setting-row { display: flex; min-height: 66px; align-items: center; justify-content: space-between; gap: 20px; padding: 12px 0; border-top: 1px solid #eaf0ed; }
.setting-row > span strong, .setting-row > span small, .setting-row legend strong, .setting-row legend small { display: block; }
.setting-row > span strong, .setting-row legend strong { color: var(--ink); font-size: .9rem; }
.setting-row > span small, .setting-row legend small { margin-top: 2px; color: var(--muted); font-size: .8rem; }
.setting-row legend { float: left; width: 100%; margin-bottom: 9px; }
.setting-choice { display: block; }
.setting-choice .segmented-control { clear: both; }
.setting-choice .segment { position: relative; }
.setting-choice .segment input { position: absolute; width: 1px; height: 1px; opacity: 0; }
.setting-choice .segment:has(input:checked) { background: white; color: var(--green-dark); box-shadow: 0 1px 4px rgba(38, 76, 65, .1); }
.setting-choice .segment:has(input:focus-visible) { outline: 3px solid #76b8a5; outline-offset: 2px; }
.switch { position: relative; width: 48px; height: 28px; flex: 0 0 auto; appearance: none; border: 0; border-radius: 99px; background: #bdcbc5; cursor: pointer; transition: background .18s ease; }
.switch::after { position: absolute; top: 4px; left: 4px; width: 20px; height: 20px; border-radius: 50%; background: white; content: ""; box-shadow: 0 1px 4px rgba(0, 0, 0, .15); transition: transform .18s ease; }
.switch:checked { background: #39876b; }
.switch:checked::after { transform: translateX(20px); }
.browser-notification-button { margin: 0 0 5px; }
.settings-footer { display: flex; justify-content: flex-end; gap: 9px; }
.care-person-banner { display: flex; align-items: center; gap: 15px; margin-bottom: 20px; padding: 18px 22px; border: 1px solid var(--line); border-radius: 8px; background: white; }
.care-person-banner h2 { margin: 0 0 2px; }
.care-person-banner p { margin: 0; font-size: .87rem; }
.care-date { margin-left: auto; color: var(--muted); font-size: .86rem; }
.caregiver-metrics { grid-template-columns: repeat(4, minmax(0, 1fr)); margin-bottom: 20px; }
.care-content-grid { display: grid; grid-template-columns: minmax(0, 1.45fr) minmax(270px, .75fr); gap: 18px; }
.care-content-grid > .section-panel { padding: 21px 23px 8px; }
.care-dose-list { margin-top: 12px; }
.care-dose-row { display: flex; min-height: 67px; align-items: center; gap: 16px; border-top: 1px solid #eaf0ed; }
.care-take-form { margin: 0 0 0 auto; }
.push-panel { padding: 21px 23px; margin-top: 20px; }
.push-panel .push-copy { max-width: 560px; margin: 4px 0 14px; color: var(--muted, #5c6d66); }
.push-panel .button { display: inline-flex; }
.push-panel .field-help { display: block; margin-top: 10px; }
.push-panel #enable-push[disabled] { opacity: .7; cursor: default; }
.care-dose-time { width: 74px; flex: 0 0 auto; color: #57716a; font-size: .84rem; font-weight: 700; }
.care-dose-name { min-width: 0; flex: 1; }
.care-dose-name strong, .care-dose-name small { display: block; }
.care-dose-name strong { font-size: .9rem; }
.care-dose-name small { color: var(--muted); font-size: .78rem; }
.alert-panel { padding: 21px; border: 1px solid #eadbd2; border-radius: 8px; background: #fffaf6; }
.alert-heading { display: flex; align-items: center; gap: 11px; margin-bottom: 14px; }
.alert-heading h2 { margin: 0; font-size: 1.08rem; }
.alert-heading .eyebrow { margin-bottom: 1px; color: #9b785f; }
.alert-icon { display: grid; width: 40px; height: 40px; place-items: center; border-radius: 13px; background: #fae9dd; color: #a66642; font-weight: 800; }
.missed-alert { padding: 14px 0; border-top: 1px solid #f0e3db; }
.missed-alert strong { display: block; color: #674a3b; font-size: .91rem; line-height: 1.45; }
.missed-alert p { margin: 5px 0 0; color: #927969; font-size: .82rem; }
.all-clear { display: flex; min-height: 128px; flex-direction: column; align-items: center; justify-content: center; border-top: 1px solid #f0e3db; text-align: center; }
.all-clear > span { display: grid; width: 34px; height: 34px; margin-bottom: 7px; place-items: center; border-radius: 50%; background: #e7f3e8; color: #43845f; }
.all-clear strong { color: #516c57; font-size: .9rem; }
.all-clear p, .empty-inline { margin: 3px 0 0; font-size: .8rem; }
.select-compact { display: flex; align-items: center; gap: 8px; color: var(--muted); font-size: .86rem; }
.select-compact select { width: auto; min-height: 42px; }
.flash-list { display: grid; gap: 8px; margin-bottom: 17px; }
.flash { padding: 11px 14px; border: 1px solid #d4e6dc; border-radius: 7px; background: #edf7f0; color: #32634d; font-size: .9rem; }
.flash-error { border-color: #ebd2ce; background: #fff3f1; color: #974d45; }
.flash-success { border-color: #d4e6dc; background: #edf7f0; color: #32634d; }
.reminder-dialog { width: min(460px, calc(100% - 32px)); padding: 34px; border: 1px solid #d4e5dc; border-radius: 12px; background: var(--paper); color: var(--ink); box-shadow: 0 22px 80px rgba(20, 54, 45, .25); text-align: center; }
.reminder-dialog::backdrop { background: rgba(20, 44, 40, .5); backdrop-filter: blur(3px); }
.reminder-emblem { display: grid; width: 60px; height: 60px; margin: 0 auto 14px; place-items: center; border-radius: 19px; background: #e5f2e9; color: var(--green); font-size: 1.8rem; }
.reminder-dialog .eyebrow { margin-bottom: 8px; }
.reminder-dialog h2 { font-size: 1.4rem; }
.reminder-medicine { margin: 13px 0 2px; color: var(--ink); font-size: 1.1rem; font-weight: 700; }
.reminder-schedule { margin-bottom: 20px; font-size: .9rem; }
.reminder-actions { display: grid; gap: 9px; }
.reminder-actions form { margin: 0; }
.auth-layout { display: grid; min-height: 100vh; grid-template-columns: minmax(360px, .92fr) minmax(470px, 1.08fr); background: white; }
.auth-brand-panel { position: relative; display: flex; min-height: 100vh; flex-direction: column; overflow: hidden; padding: 39px clamp(32px, 5vw, 74px); background: #e8f3ec; }
.brand-light { position: relative; z-index: 2; margin: 0; }
.auth-message { position: relative; z-index: 2; width: min(475px, 100%); margin: auto 0; padding: 48px 0 58px; }
.auth-message .eyebrow { display: flex; align-items: center; gap: 9px; color: #4c8067; font-size: .75rem; }
.auth-message h1 { margin: 17px 0 16px; color: #214e42; font-size: clamp(2.3rem, 4vw, 3.55rem); line-height: 1.08; }
.auth-message p { max-width: 410px; color: #5b776a; font-size: 1.05rem; line-height: 1.7; }
.auth-trust { display: flex; align-items: center; gap: 9px; margin-top: 26px; color: #45735d; font-size: .88rem; font-weight: 600; }
.auth-trust span { display: grid; width: 22px; height: 22px; place-items: center; border-radius: 50%; background: #d4ead9; }
.auth-panel-foot { position: relative; z-index: 2; color: #718a7d; font-size: .78rem; }
.brand-ornament { position: absolute; z-index: 1; width: 290px; height: 290px; border: 1px solid rgba(73, 137, 101, .12); border-radius: 45% 55% 60% 40%; transform: rotate(34deg); }
.ornament-one { right: -90px; bottom: 13%; box-shadow: 0 0 0 26px rgba(255, 255, 255, .16), 0 0 0 54px rgba(255, 255, 255, .1); }
.ornament-two { right: 24%; bottom: -218px; width: 360px; height: 360px; transform: rotate(-18deg); }
.auth-form-panel { display: grid; place-items: center; padding: 50px 32px; }
.auth-form-wrap { width: min(440px, 100%); }
.auth-heading { margin-bottom: 25px; }
.auth-heading .eyebrow { color: #66877a; }
.auth-heading h2 { margin: 0 0 7px; font-size: 1.9rem; }
.auth-heading p { margin: 0; }
.form-stack { display: grid; gap: 16px; }
.form-stack label { font-size: .91rem; }
.form-stack input:not([type=checkbox]):not([type=radio]), .form-stack select { min-height: 51px; }
.form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.form-row-between { align-items: center; }
.form-row-between .check-label { display: flex; flex-direction: row; align-items: center; gap: 7px; color: var(--muted); font-size: .86rem; font-weight: 500; }
.check-label input { width: 18px; height: 18px; accent-color: var(--green); }
.role-choice { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin: 1px 0 0; padding: 0; border: 0; }
.role-choice legend { margin-bottom: 8px; color: #344e4a; font-size: .9rem; font-weight: 700; }
.choice-card { display: flex; min-height: 72px; align-items: center; gap: 9px; padding: 10px; border: 1px solid #d5e2dc; border-radius: 8px; background: white; cursor: pointer; }
.choice-card:has(input:checked) { border-color: #67a286; background: #f1f8f4; box-shadow: 0 0 0 1px #67a286; }
.choice-card input { width: 17px; height: 17px; accent-color: var(--green); }
.choice-icon { display: grid; width: 32px; height: 32px; flex: 0 0 auto; place-items: center; border-radius: 10px; background: #eaf4ed; color: var(--green); font-size: 1.1rem; }
.choice-card strong, .choice-card small { display: block; }
.choice-card strong { font-size: .85rem; }
.choice-card small { color: var(--muted); font-size: .7rem; }
.auth-switch { margin: 22px 0 0; color: var(--muted); font-size: .9rem; text-align: center; }
.auth-switch .text-link { margin-left: 3px; }
.demo-hint { display: flex; gap: 10px; margin-top: 24px; padding: 13px; border: 1px solid #e2ebe6; border-radius: 7px; background: #f7faf8; color: #6a7e77; font-size: .76rem; line-height: 1.6; }
.demo-hint > span:first-child { color: #5e9678; font-size: 1rem; }
.demo-hint strong { color: #38584d; font-weight: 600; }

body.font-normal { font-size: 15px; }
body.font-large { font-size: 17px; }
body.font-larger { font-size: 19px; }
body.font-larger .nav-link, body.font-larger input, body.font-larger select, body.font-larger textarea { font-size: 1rem; }
.theme-dark { color-scheme: dark; --ink: #e3efea; --muted: #a8b9b2; --quiet: #8b9f97; --line: #344943; --paper: #1d2d29; --canvas: #15231f; --mint: #263d34; --green: #71bc97; --green-dark: #a5d7bc; --blue: #263b43; --blue-ink: #aed3e5; --peach: #47362d; --peach-ink: #f1b995; --lilac: #39334b; --red: #f0a29a; --shadow: 0 12px 34px rgba(0, 0, 0, .12); }
.theme-dark .sidebar, .theme-dark .topbar, .theme-dark .form-footer { background: #1a2925; }
.theme-dark .nav-link { color: #bdccc5; }
.theme-dark .nav-link:hover, .theme-dark .nav-link.active { background: #293f36; color: #b7e1ca; }
.theme-dark .overview-card-green, .theme-dark .overview-card-blue, .theme-dark .overview-card-peach, .theme-dark .overview-card-lilac, .theme-dark .next-panel { background: #263a33; }
.theme-dark .overview-card-blue { background: #293941; }
.theme-dark .overview-card-peach { background: #41342d; }
.theme-dark .overview-card-lilac { background: #353144; }
.theme-dark .overview-icon, .theme-dark .button-outline, .theme-dark .button-danger-outline, .theme-dark .choice-card, .theme-dark .form-grid input, .theme-dark .form-grid select, .theme-dark .form-grid textarea, .theme-dark .form-stack input:not([type=checkbox]):not([type=radio]), .theme-dark .form-stack select, .theme-dark .form-row input, .theme-dark .select-compact select, .theme-dark .history-table th { background: #263a34; color: var(--ink); }
.theme-dark .button-take { background: #2b4639; color: #b4dfc6; }
.theme-dark .history-table td { color: #bdccc5; }
.theme-dark .next-panel::after { border-color: rgba(141, 196, 160, .12); }
.theme-dark .alert-panel { border-color: #584337; background: #302923; }
.theme-dark .week-bar-track { background: #304139; }
.theme-dark .weekly-empty > span { background: #2b4036; }
.theme-dark .missed-alert strong { color: #f0cdb6; }
.theme-dark .missed-alert p { color: #c1a18c; }
.theme-dark .auth-layout { background: #15231f; }
.theme-dark .auth-brand-panel { background: #20392f; }
.theme-dark .auth-message h1 { color: #d9efe0; }
.theme-dark .auth-message p, .theme-dark .auth-trust { color: #b0cfbc; }
.theme-dark .reminder-dialog { background: var(--paper); color: var(--ink); }
.theme-dark .empty-state-wide { background: rgba(29, 45, 41, .65); }

@media (max-width: 1100px) {
  .sidebar { width: 220px; }
  .main-column { margin-left: 220px; }
  .page-content { padding-right: 28px; padding-left: 28px; }
  .dashboard-grid { grid-template-columns: minmax(0, 1.5fr) minmax(235px, .8fr); gap: 14px; }
  .overview-card { padding: 18px 15px; }
  .overview-grid { gap: 11px; }
  .medicine-details { gap: 12px; }
  .caregiver-metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
@media (max-width: 820px) {
  .sidebar { inset: auto 0 0; width: auto; height: 72px; flex-direction: row; justify-content: center; padding: 7px 12px max(7px, env(safe-area-inset-bottom)); border-top: 1px solid var(--line); border-right: 0; background: rgba(255, 255, 255, .97); }
  .sidebar > .brand, .sidebar-bottom { display: none; }
  .side-nav { width: 100%; max-width: 100%; flex-direction: row; gap: 3px; overflow-x: auto; scrollbar-width: thin; }
  .nav-link { min-width: 64px; min-height: 56px; flex: 1 0 64px; flex-direction: column; justify-content: center; gap: 1px; padding: 3px 1px; border-radius: 7px; font-size: .68rem; line-height: 1.2; text-align: center; white-space: nowrap; }
  .nav-link > span { height: 23px; font-size: 1.15rem; }
  .main-column { margin-left: 0; padding-bottom: calc(72px + env(safe-area-inset-bottom)); }
  .topbar { height: 64px; padding: 0 22px; }
  .page-content { padding: 30px 22px 42px; }
  .dashboard-grid { grid-template-columns: 1fr; }
  .next-panel { display: grid; grid-template-columns: 1fr auto; column-gap: 20px; }
  .next-panel-top, .next-panel h2, .next-panel > p, .next-panel .next-divider, .next-panel .next-note { grid-column: 1; }
  .next-panel > .button { grid-column: 2; grid-row: 2 / span 4; align-self: center; }
  .auth-layout { grid-template-columns: minmax(300px, .8fr) minmax(390px, 1fr); }
  .auth-brand-panel { padding-right: 30px; padding-left: 32px; }
  .auth-form-panel { padding-right: 25px; padding-left: 25px; }
}
@media (max-width: 620px) {
  h1 { font-size: 1.72rem; }
  .topbar { height: 60px; }
  .topbar-date { display: none; }
  .profile-chip { margin-left: auto; }
  .profile-chip-name strong { font-size: .82rem; }
  .page-content { padding: 25px 16px 32px; }
  .welcome-row, .page-heading { align-items: flex-start; margin-bottom: 22px; }
  .welcome-row { flex-direction: column; }
  .welcome-row > .button { min-height: 45px; }
  .page-heading > .button { min-height: 43px; padding: 9px 11px; font-size: .85rem; }
  .page-heading p, .welcome-row p { font-size: .9rem; }
  .overview-grid { grid-template-columns: 1fr 1fr; gap: 9px; }
  .overview-card { min-height: 102px; gap: 10px; padding: 13px 11px; }
  .overview-card:first-child { grid-column: span 2; }
  .overview-icon { width: 39px; height: 39px; border-radius: 12px; font-size: 1.15rem; }
  .metric-label { font-size: .75rem; }
  .overview-card strong { font-size: 1.45rem; }
  .metric-caption { font-size: .7rem; }
  .medication-panel { padding: 18px 14px 9px; }
  .section-heading h2 { font-size: 1.08rem; }
  .dose-card { grid-template-columns: 1fr auto; gap: 6px 9px; padding: 15px 0; }
  .dose-time { grid-column: 1; grid-row: 1; gap: 7px; font-size: .78rem; }
  .dose-main { grid-column: 1; grid-row: 2; }
  .dose-main h3 { font-size: .98rem; }
  .dose-main p { font-size: .8rem; }
  .dose-action { grid-column: 2; grid-row: 1 / span 2; min-width: 100px; }
  .button-take { min-height: 37px; padding: 7px 9px; font-size: .77rem; }
  .status-pill { font-size: .73rem; }
  .next-panel { grid-template-columns: 1fr; padding: 19px; }
  .next-panel > .button { grid-column: 1; grid-row: auto; }
  .next-panel .next-divider { margin: 14px 0 11px; }
  .library-card { grid-template-columns: 40px minmax(0, 1fr); gap: 12px; padding: 16px; }
  .medicine-symbol { width: 40px; height: 40px; border-radius: 12px; font-size: 1.1rem; }
  .library-main { min-width: 0; }
  .library-title-row { flex-wrap: wrap; }
  .library-title-row h2 { font-size: 1.03rem; }
  .medicine-details { grid-column: 1 / -1; grid-template-columns: 1fr 1fr; gap: 13px; margin-top: 14px; padding-top: 13px; }
  .library-actions { grid-column: 1 / -1; justify-content: flex-end; }
  .filter-row { align-items: flex-start; gap: 10px; }
  .segment { min-height: 37px; padding: 7px 9px; font-size: .77rem; }
  .record-count { padding-top: 10px; font-size: .78rem; }
  .weekly-panel { padding: 18px 15px 14px; }
  .week-chart { height: 138px; gap: 5px; padding: 0; }
  .weekly-score { align-items: flex-end; flex-direction: column; gap: 2px; text-align: right; }
  .weekly-score span { max-width: 110px; font-size: .7rem; }
  .page-heading:has(> .button) { align-items: flex-start; }
  .page-heading:has(> .button) > .button { flex: 0 0 auto; }
  .history-table thead { display: none; }
  .history-table, .history-table tbody, .history-table tr, .history-table td { display: block; width: 100%; }
  .history-table tr { padding: 11px 14px; border-bottom: 1px solid var(--line); }
  .history-table tbody tr:last-child { border-bottom: 0; }
  .history-table td { display: grid; grid-template-columns: 112px 1fr; gap: 8px; padding: 5px 0; border: 0; font-size: .84rem; }
  .history-table td::before { color: var(--quiet); content: attr(data-label); font-size: .73rem; font-weight: 700; text-transform: uppercase; }
  .history-table .table-empty { display: block; text-align: center; }
  .history-table .table-empty::before { content: none; }
  .edit-form { padding: 20px 16px 0; }
  .form-grid { grid-template-columns: 1fr; gap: 14px; padding-left: 0; }
  .span-2, .time-fields { grid-column: auto; }
  .time-fields { grid-template-columns: 1fr 1fr; }
  .field-label { grid-column: 1 / -1; }
  .form-section-spaced { margin-top: 24px; padding-top: 20px; }
  .form-footer { align-items: flex-start; flex-direction: column; margin: 23px -16px 0; padding: 15px 16px; }
  .form-footer > div { width: 100%; justify-content: flex-end; }
  .form-footer .button { min-height: 44px; }
  .profile-form { padding: 20px 16px 0; }
  .profile-form .form-footer { margin-right: -16px; margin-left: -16px; }
  .settings-section { padding: 18px 16px; }
  .setting-row { gap: 10px; }
  .setting-row > span strong { font-size: .84rem; }
  .setting-row > span small { max-width: 265px; font-size: .74rem; }
  .care-person-banner { align-items: flex-start; padding: 15px; }
  .care-person-banner .avatar { width: 46px; height: 46px; }
  .care-person-banner h2 { font-size: 1.05rem; }
  .care-person-banner p { font-size: .77rem; }
  .care-date { display: none; }
  .caregiver-metrics { grid-template-columns: 1fr 1fr; }
  .care-content-grid { grid-template-columns: 1fr; }
  .care-content-grid > .section-panel { padding: 18px 15px 8px; }
  .care-dose-row { gap: 9px; }
  .care-dose-time { width: 64px; font-size: .75rem; }
  .care-dose-name strong { font-size: .83rem; }
  .care-dose-row .status-pill { font-size: .69rem; }
  .select-compact { flex-direction: column; align-items: flex-start; }
  .auth-layout { display: block; }
  .auth-brand-panel { min-height: auto; padding: 19px 22px; }
  .auth-brand-panel > .brand { margin: 0; }
  .auth-message, .auth-panel-foot, .brand-ornament { display: none; }
  .auth-form-panel { display: block; padding: 30px 22px 45px; }
  .auth-heading h2 { font-size: 1.65rem; }
  .form-row { grid-template-columns: 1fr; gap: 14px; }
  .role-choice { gap: 7px; }
  .choice-card { gap: 6px; padding: 7px; }
  .choice-card small { font-size: .65rem; }
  .choice-icon { width: 28px; height: 28px; }
  .demo-hint { font-size: .72rem; }
  .reminder-dialog { padding: 25px 20px; }
  body.font-larger .nav-link { font-size: .63rem; }
}

/* 3D hendekeract backdrop on the sign-in panel in high-contrast live 3D */
.swarm { position: absolute; inset: 0; z-index: 0; background: #020806; }
.swarm canvas { display: block; width: 100%; height: 100%; }
.swarm-caption { display: none; }
.auth-brand-panel.swarm-on { background: radial-gradient(circle at 45% 45%, #05140f 0%, #010604 100%); position: relative; }
.auth-brand-panel.swarm-on::after { content: ""; position: absolute; inset: 0; z-index: 1; pointer-events: none; background: radial-gradient(ellipse at 40% 50%, rgba(2, 8, 6, .25) 0%, rgba(2, 8, 6, .78) 100%); }
.auth-brand-panel.swarm-on .brand-ornament { display: none; }
.auth-brand-panel.swarm-on .brand { position: relative; z-index: 3; color: #ffffff; }
.auth-brand-panel.swarm-on .brand strong { color: #ffffff; text-shadow: 0 2px 10px rgba(0,0,0,0.5); }
.auth-brand-panel.swarm-on .brand small { color: #7fe6ba; font-weight: 500; }
.auth-brand-panel.swarm-on .brand-mark { background: linear-gradient(135deg, #00ff88, #00d2ff); color: #020c08; box-shadow: 0 0 20px rgba(0, 255, 136, 0.6); }
.auth-brand-panel.swarm-on .auth-message {
  position: relative;
  z-index: 3;
  background: rgba(3, 14, 10, 0.58);
  backdrop-filter: blur(18px);
  -webkit-backdrop-filter: blur(18px);
  border: 1px solid rgba(127, 230, 186, 0.22);
  border-radius: 22px;
  padding: 38px 32px;
  box-shadow: 0 24px 60px rgba(0, 0, 0, 0.65), inset 0 1px 1px rgba(255, 255, 255, 0.15);
}
.auth-brand-panel.swarm-on .auth-message .eyebrow { color: #00ff9d; font-weight: 700; letter-spacing: .08em; text-shadow: 0 0 14px rgba(0, 255, 157, .5); }
.auth-brand-panel.swarm-on .auth-message .pulse-dot { background: #00ff9d; box-shadow: 0 0 12px #00ff9d; }
.auth-brand-panel.swarm-on .auth-message h1 { color: #ffffff; font-weight: 800; text-shadow: 0 4px 24px rgba(0, 0, 0, .85), 0 0 35px rgba(0, 255, 136, .28); }
.auth-brand-panel.swarm-on .auth-message p { color: #d4ece1; font-size: 1.04rem; line-height: 1.68; }
.auth-brand-panel.swarm-on .auth-trust { color: #8ee5bc; font-weight: 600; }
.auth-brand-panel.swarm-on .auth-trust span { background: rgba(0, 255, 136, .22); color: #00ff9d; border: 1px solid rgba(0, 255, 136, .35); }
.auth-brand-panel.swarm-on .auth-panel-foot { position: relative; z-index: 3; color: #8da79a; }
.auth-brand-panel.swarm-on .swarm-caption {
  position: absolute;
  right: clamp(20px, 3vw, 36px);
  bottom: 35px;
  z-index: 3;
  display: inline-flex;
  align-items: center;
  gap: 7px;
  padding: 7px 15px;
  background: rgba(3, 14, 10, 0.72);
  backdrop-filter: blur(10px);
  -webkit-backdrop-filter: blur(10px);
  border: 1px solid rgba(0, 255, 157, 0.25);
  border-radius: 999px;
  color: #a0e8c7;
  font-size: .73rem;
  font-weight: 600;
  letter-spacing: .02em;
  box-shadow: 0 8px 24px rgba(0,0,0,0.45);
}
@media (max-width: 760px) { .auth-brand-panel.swarm-on .swarm-caption { display: none; } }

/* =========================================================================
   Chatbot Widget Styling
   ========================================================================= */
.chatbot-container {
  position: fixed;
  right: 26px;
  bottom: 26px;
  z-index: 1000;
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  pointer-events: none;
}
.chatbot-launcher,
.chatbot-window {
  pointer-events: auto;
}
.chatbot-launcher {
  position: relative;
  width: 58px;
  height: 58px;
  border-radius: 50%;
  background: linear-gradient(135deg, #1b4b3e 0%, #0d2820 100%);
  border: 2px solid rgba(255, 255, 255, 0.25);
  color: #ffffff;
  display: flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  box-shadow: 0 10px 28px rgba(13, 40, 32, 0.42), 0 2px 6px rgba(0, 0, 0, 0.15);
  transition: transform 0.22s cubic-bezier(0.34, 1.56, 0.64, 1), box-shadow 0.22s ease, background 0.25s ease;
  user-select: none;
}
.chatbot-launcher:hover {
  transform: translateY(-3px) scale(1.05);
  box-shadow: 0 14px 34px rgba(13, 40, 32, 0.55), 0 3px 8px rgba(0, 0, 0, 0.2);
}
.chatbot-launcher:active {
  transform: translateY(0) scale(0.97);
}
.chatbot-icon-closed,
.chatbot-icon-open {
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  display: flex;
  align-items: center;
  justify-content: center;
  width: 26px;
  height: 26px;
  pointer-events: none;
  transition: opacity 0.2s cubic-bezier(0.4, 0, 0.2, 1), transform 0.25s cubic-bezier(0.34, 1.56, 0.64, 1);
}
.chatbot-icon-closed {
  opacity: 1;
  transform: translate(-50%, -50%) rotate(0deg) scale(1);
  visibility: visible;
}
.chatbot-icon-open {
  opacity: 0;
  transform: translate(-50%, -50%) rotate(-90deg) scale(0.4);
  visibility: hidden;
}
.chatbot-container.chat-active .chatbot-icon-closed {
  opacity: 0;
  transform: translate(-50%, -50%) rotate(90deg) scale(0.4);
  visibility: hidden;
}
.chatbot-container.chat-active .chatbot-icon-open {
  opacity: 1;
  transform: translate(-50%, -50%) rotate(0deg) scale(1);
  visibility: visible;
}
.chatbot-container.chat-active .chatbot-launcher {
  background: linear-gradient(135deg, #1f2e29 0%, #111a17 100%);
  border-color: rgba(255, 255, 255, 0.35);
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
}
.chatbot-pulse-dot {
  position: absolute;
  top: 2px;
  right: 2px;
  width: 12px;
  height: 12px;
  border-radius: 50%;
  background: #00ff88;
  border: 2px solid #ffffff;
  box-shadow: 0 0 8px #00ff88;
  animation: pulseBeacon 2s infinite ease-in-out;
  pointer-events: none;
  transition: opacity 0.2s ease, transform 0.2s ease;
}
.chatbot-container.chat-active .chatbot-pulse-dot {
  opacity: 0;
  transform: scale(0);
  display: none !important;
}
@keyframes pulseBeacon {
  0% { transform: scale(0.9); opacity: 0.9; }
  50% { transform: scale(1.2); opacity: 1; box-shadow: 0 0 14px #00ff88; }
  100% { transform: scale(0.9); opacity: 0.9; }
}
.chatbot-tooltip {
  position: absolute;
  right: 68px;
  bottom: 12px;
  background: var(--paper);
  color: var(--ink);
  border: 1px solid var(--line);
  padding: 8px 14px;
  border-radius: 12px;
  font-size: 0.8rem;
  font-weight: 600;
  white-space: nowrap;
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.12);
  pointer-events: none;
  transition: opacity 0.3s ease, transform 0.3s ease;
  animation: tooltipFloat 3s infinite ease-in-out;
}
.chatbot-container.chat-active .chatbot-tooltip {
  opacity: 0;
  display: none !important;
}
@keyframes tooltipFloat {
  0%, 100% { transform: translateX(0); }
  50% { transform: translateX(-4px); }
}
.chatbot-window {
  position: absolute;
  right: 0;
  bottom: 72px;
  width: 395px;
  max-width: calc(100vw - 32px);
  height: 550px;
  max-height: calc(100vh - 110px);
  background: var(--paper);
  border: 1px solid var(--line);
  border-radius: 20px;
  box-shadow: 0 24px 60px rgba(10, 30, 22, 0.28), 0 6px 18px rgba(0, 0, 0, 0.1);
  display: flex;
  flex-direction: column;
  overflow: hidden;
  transform-origin: bottom right;
  z-index: 1001;
}
.chatbot-window[hidden] {
  display: none !important;
}
.chatbot-window:not([hidden]) {
  animation: chatPopup 0.26s cubic-bezier(0.16, 1, 0.3, 1) forwards;
}
@keyframes chatPopup {
  from { opacity: 0; transform: translateY(16px) scale(0.96); }
  to { opacity: 1; transform: translateY(0) scale(1); }
}
.chatbot-header {
  padding: 14px 18px;
  background: linear-gradient(135deg, #184437 0%, #102d24 100%);
  color: #ffffff;
  display: flex;
  align-items: center;
  justify-content: space-between;
  border-bottom: 1px solid rgba(255, 255, 255, 0.1);
  user-select: none;
}
.chatbot-header-profile {
  display: flex;
  align-items: center;
  gap: 12px;
}
.chatbot-avatar {
  width: 38px;
  height: 38px;
  border-radius: 11px;
  background: rgba(255, 255, 255, 0.16);
  display: grid;
  place-items: center;
  font-size: 1.2rem;
  border: 1px solid rgba(255, 255, 255, 0.2);
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.15);
}
.chatbot-header-profile h3 {
  margin: 0;
  font-size: 0.98rem;
  font-weight: 700;
  color: #ffffff;
  line-height: 1.25;
}
.chatbot-badge {
  display: flex;
  align-items: center;
  gap: 5px;
  font-size: 0.72rem;
  color: #8de3ba;
  font-weight: 500;
}
.badge-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: #00ff88;
  display: inline-block;
  box-shadow: 0 0 6px #00ff88;
}
.chatbot-header-actions {
  display: flex;
  align-items: center;
  gap: 6px;
}
.chatbot-btn-icon {
  background: rgba(255, 255, 255, 0.12);
  border: 1px solid rgba(255, 255, 255, 0.15);
  color: #e5f6ee;
  width: 32px;
  height: 32px;
  border-radius: 9px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-size: 0.95rem;
  cursor: pointer;
  transition: all 0.18s cubic-bezier(0.4, 0, 0.2, 1);
  padding: 0;
}
.chatbot-btn-icon:hover {
  background: rgba(255, 255, 255, 0.24);
  color: #ffffff;
  transform: scale(1.05);
}
.chatbot-btn-icon:active {
  transform: scale(0.95);
}
.chatbot-btn-close:hover {
  background: rgba(239, 68, 68, 0.28) !important;
  border-color: rgba(239, 68, 68, 0.5) !important;
  color: #ffb4b4 !important;
}
.chatbot-messages {
  flex: 1;
  overflow-y: auto;
  padding: 16px;
  display: flex;
  flex-direction: column;
  gap: 12px;
  background: var(--canvas);
}
.chat-msg {
  display: flex;
  gap: 8px;
  max-width: 90%;
}
.chat-msg-bot {
  align-self: flex-start;
}
.chat-msg-user {
  align-self: flex-end;
  flex-direction: row-reverse;
}
.msg-avatar {
  width: 26px;
  height: 26px;
  border-radius: 50%;
  background: #245749;
  color: #ffffff;
  display: grid;
  place-items: center;
  font-size: 0.72rem;
  font-weight: 700;
  flex-shrink: 0;
  margin-top: 2px;
}
.chat-msg-user .msg-avatar {
  background: #396a58;
}
.msg-bubble {
  padding: 11px 14px;
  font-size: 0.86rem;
  line-height: 1.56;
  border-radius: 16px;
}
.chat-msg-bot .msg-bubble {
  background: var(--paper);
  color: var(--ink);
  border: 1px solid var(--line);
  border-top-left-radius: 4px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.04);
}
.chat-msg-user .msg-bubble {
  background: #214e42;
  color: #ffffff;
  border-top-right-radius: 4px;
  box-shadow: 0 2px 8px rgba(33, 78, 66, 0.25);
}
.msg-bubble p {
  margin: 0 0 6px;
}
.msg-bubble p:last-child {
  margin-bottom: 0;
}
.msg-bubble strong {
  color: inherit;
  font-weight: 700;
}
.msg-bubble em {
  font-style: italic;
}
.chat-link {
  color: #2e7a5c;
  font-weight: 700;
  text-decoration: underline;
  text-underline-offset: 2px;
}
.chat-list {
  margin: 6px 0;
  padding-left: 18px;
}
.chat-bullet {
  margin-bottom: 4px;
}
.chatbot-suggestions {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-top: 6px;
}
.suggestions-heading {
  width: 100%;
  font-size: 0.74rem;
  font-weight: 700;
  color: var(--quiet);
  text-transform: uppercase;
  letter-spacing: 0.04em;
  margin-bottom: 2px;
}
.chip-btn {
  background: #eef6f2;
  color: #214e42;
  border: 1px solid #c9e2d5;
  border-radius: 999px;
  padding: 6px 11px;
  font-size: 0.76rem;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.16s ease;
  line-height: 1.2;
}
.chip-btn:hover {
  background: #214e42;
  color: #ffffff;
  border-color: #214e42;
  transform: translateY(-1px);
}
.chat-typing .typing-dots {
  display: flex;
  align-items: center;
  gap: 4px;
  padding: 4px 2px;
}
.typing-dots span {
  width: 6px;
  height: 6px;
  background: var(--quiet);
  border-radius: 50%;
  animation: typingBounce 1.2s infinite ease-in-out;
}
.typing-dots span:nth-child(2) { animation-delay: 0.2s; }
.typing-dots span:nth-child(3) { animation-delay: 0.4s; }
@keyframes typingBounce {
  0%, 80%, 100% { transform: translateY(0); opacity: 0.4; }
  40% { transform: translateY(-5px); opacity: 1; }
}
.chatbot-input-bar {
  padding: 10px 14px;
  background: var(--paper);
  border-top: 1px solid var(--line);
  display: flex;
  align-items: center;
  gap: 8px;
}
.chatbot-input-bar input {
  flex: 1;
  min-height: 40px !important;
  padding: 8px 14px !important;
  border: 1px solid var(--line) !important;
  border-radius: 999px !important;
  background: var(--canvas) !important;
  color: var(--ink) !important;
  font-size: 0.86rem !important;
  outline: none;
  transition: border-color 0.18s ease;
}
.chatbot-input-bar input:focus {
  border-color: var(--green) !important;
  box-shadow: 0 0 0 2px rgba(113, 188, 151, 0.25) !important;
}
.chatbot-input-bar button {
  width: 38px;
  height: 38px;
  border-radius: 50%;
  background: #214e42;
  color: #ffffff;
  border: 0;
  display: grid;
  place-items: center;
  cursor: pointer;
  flex-shrink: 0;
  transition: background 0.18s ease, transform 0.15s ease;
}
.chatbot-input-bar button:hover {
  background: #17382f;
  transform: scale(1.05);
}
.chatbot-input-bar button:active {
  transform: scale(0.95);
}
.chatbot-disclaimer {
  padding: 6px 14px 9px;
  background: var(--paper);
  font-size: 0.68rem;
  color: var(--quiet);
  text-align: center;
}

/* Dark theme overrides for Chatbot */
.theme-dark .chatbot-window {
  background: #1a2925;
  border-color: #344943;
}
.theme-dark .chatbot-messages {
  background: #14221e;
}
.theme-dark .chat-msg-bot .msg-bubble {
  background: #1e312c;
  color: #e3efea;
  border-color: #334b42;
}
.theme-dark .chat-msg-user .msg-bubble {
  background: #2b5446;
  color: #ffffff;
}
.theme-dark .chat-link {
  color: #71bc97;
}
.theme-dark .chip-btn {
  background: #22372f;
  color: #9fe0be;
  border-color: #324e43;
}
.theme-dark .chip-btn:hover {
  background: #71bc97;
  color: #12211c;
  border-color: #71bc97;
}
.theme-dark .chatbot-tooltip {
  background: #1e312c;
  color: #e3efea;
  border-color: #334b42;
}
.theme-dark .chatbot-input-bar {
  background: #1a2925;
  border-color: #344943;
}
.theme-dark .chatbot-input-bar input {
  background: #14221e !important;
  color: #e3efea !important;
  border-color: #344943 !important;
}
.theme-dark .chatbot-input-bar button {
  background: #3a6857;
}
.theme-dark .chatbot-input-bar button:hover {
  background: #71bc97;
  color: #12211c;
}
.theme-dark .chatbot-disclaimer {
  background: #1a2925;
}

/* Dev Reset Notification & Demo Quick Fill */
.dev-reset-card {
  background: #f0fdf4;
  border: 1.5px solid #86efac;
  border-radius: 14px;
  padding: 16px;
  margin-bottom: 18px;
  color: #14532d;
  box-shadow: 0 4px 14px rgba(22, 101, 52, 0.08);
}
.theme-dark .dev-reset-card {
  background: #142820;
  border-color: #2e664a;
  color: #bbf7d0;
}
.dev-reset-header {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 0.95rem;
  font-weight: 700;
  margin-bottom: 6px;
}
.dev-reset-card p {
  margin: 0 0 12px;
  font-size: 0.85rem;
  line-height: 1.45;
}
.dev-reset-note {
  display: block;
  font-size: 0.74rem;
  margin-top: 8px;
  opacity: 0.85;
}
.dev-reset-card code {
  background: rgba(0, 0, 0, 0.06);
  padding: 2px 6px;
  border-radius: 4px;
  font-size: 0.8rem;
}
.theme-dark .dev-reset-card code {
  background: rgba(255, 255, 255, 0.1);
}
.dev-otp-code {
  font-family: 'Courier New', Courier, monospace;
  font-size: 2rem;
  font-weight: 700;
  letter-spacing: 0.55rem;
  text-align: center;
  padding: 10px 6px 10px calc(6px + 0.55rem);
  background: rgba(255, 255, 255, 0.7);
  border: 1px dashed #86efac;
  border-radius: 10px;
}
.theme-dark .dev-otp-code {
  background: rgba(255, 255, 255, 0.06);
}
.otp-fieldset { margin: 0; padding: 0; border: 0; min-width: 0; }
.otp-legend { margin-bottom: 8px; padding: 0; color: #344e4a; font-size: .91rem; font-weight: 700; }
.otp-boxes { display: flex; gap: 8px; }
.otp-box {
  flex: 1 1 0;
  min-width: 0;
  height: 58px;
  padding: 0;
  text-align: center;
  font-family: 'Manrope', Arial, sans-serif;
  font-size: 1.45rem;
  font-weight: 800;
  letter-spacing: 0.04rem;
}
.otp-box:focus { outline: none; border-color: #67a286; box-shadow: 0 0 0 3px rgba(103, 162, 134, 0.18); }
.otp-resend { display: flex; align-items: center; justify-content: space-between; gap: 10px; }
.otp-resend form { margin: 0; }
.otp-resend .text-button:disabled { color: var(--quiet); cursor: default; text-decoration: none; }
.demo-hint-title {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 0.82rem;
  font-weight: 700;
  margin-bottom: 8px;
}
.demo-btn-group {
  display: flex;
  flex-direction: column;
  gap: 6px;
  margin-bottom: 8px;
}
.demo-chip-btn {
  background: #ffffff;
  border: 1px solid var(--line);
  padding: 8px 12px;
  border-radius: 10px;
  font-size: 0.82rem;
  cursor: pointer;
  color: var(--ink);
  transition: all 0.16s ease;
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.theme-dark .demo-chip-btn {
  background: #202e29;
  border-color: #354a42;
  color: #e3efea;
}
.demo-chip-btn:hover {
  background: #eef6f2;
  border-color: #71bc97;
  transform: translateY(-1px);
}
.theme-dark .demo-chip-btn:hover {
  background: #2b3d36;
  border-color: #71bc97;
}
.chip-badge {
  background: #214e42;
  color: #ffffff;
  font-size: 0.7rem;
  font-weight: 700;
  padding: 2px 8px;
  border-radius: 999px;
  letter-spacing: 0.02em;
}
.theme-dark .chip-badge {
  background: #71bc97;
  color: #12211c;
}
.demo-pass-note {
  font-size: 0.76rem;
  color: var(--quiet);
  display: block;
}
''',
    'js/app.js': r'''(() => {
  const frequencySelect = document.querySelector("#frequency-select");
  const timeSlots = [...document.querySelectorAll("[data-time-slot]")];
  const addTimeButton = document.querySelector("#add-time-button");

  function updateTimeInputs() {
    if (!frequencySelect || !timeSlots.length) return;
    const frequency = frequencySelect.value;
    const visibleCount = frequency === "Once daily" ? 1 : frequency === "Twice daily" ? 2 : 3;
    timeSlots.forEach((slot, index) => {
      const visible = index < visibleCount || frequency === "Custom";
      slot.hidden = !visible;
      const input = slot.querySelector("input");
      input.disabled = !visible;
      input.required = index === 0;
      if (!visible) input.value = "";
    });
    if (addTimeButton) addTimeButton.hidden = frequency !== "Custom";
  }

  frequencySelect?.addEventListener("change", updateTimeInputs);
  updateTimeInputs();

  addTimeButton?.addEventListener("click", () => {
    const container = document.querySelector("#time-fields");
    const count = container.querySelectorAll("[data-time-slot]").length;
    if (count >= 8) return;
    const wrapper = document.createElement("label");
    wrapper.className = "time-input-wrap";
    wrapper.dataset.timeSlot = String(count);
    wrapper.innerHTML = `Additional time ${count - 2}<input type="time" name="times" required>`;
    container.insertBefore(wrapper, addTimeButton);
  });

  document.querySelectorAll("form[data-confirm]").forEach((form) => {
    form.addEventListener("submit", (event) => {
      if (!window.confirm(form.dataset.confirm)) event.preventDefault();
    });
  });

  const notificationButton = document.querySelector("#enable-notifications");
  notificationButton?.addEventListener("click", async () => {
    if (!("Notification" in window)) {
      window.alert("Browser notifications are not available in this browser.");
      return;
    }
    const permission = await Notification.requestPermission();
    notificationButton.textContent = permission === "granted"
      ? "Browser notifications are enabled"
      : "Notifications were not enabled";
  });

  const firebaseWebConfig = window.__FIREBASE_WEB_CONFIG__ || {};
  const pushButton = document.querySelector("#enable-push");

  function loadScript(src) {
    return new Promise((resolve, reject) => {
      const script = document.createElement("script");
      script.src = src;
      script.onload = resolve;
      script.onerror = () => reject(new Error(`Could not load ${src}`));
      document.head.appendChild(script);
    });
  }

  pushButton?.addEventListener("click", async () => {
    pushButton.disabled = true;
    const status = document.querySelector("#push-status");
    try {
      if (!("serviceWorker" in navigator) || !("Notification" in window)) {
        throw new Error("This browser does not support push notifications.");
      }
      const permission = await Notification.requestPermission();
      if (permission !== "granted") throw new Error("Notification permission was not granted.");
      await loadScript("https://www.gstatic.com/firebasejs/10.12.5/firebase-app-compat.js");
      await loadScript("https://www.gstatic.com/firebasejs/10.12.5/firebase-messaging-compat.js");
      if (!window.firebase) throw new Error("The Firebase SDK failed to load.");
      if (!window.firebase.apps.length) window.firebase.initializeApp(firebaseWebConfig);
      const registration = await navigator.serviceWorker.register("/firebase-messaging-sw.js");
      const messaging = window.firebase.messaging();
      const token = await messaging.getToken({ serviceWorkerRegistration: registration, vapidKey: firebaseWebConfig.vapidKey });
      if (!token) throw new Error("No device token was returned.");
      const response = await fetch("/api/push-token", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token }),
      });
      if (!response.ok) throw new Error("The server rejected this device.");
      pushButton.textContent = "Missed-dose alerts are enabled";
      if (status) status.textContent = "This device will be notified when a missed dose needs a check-in.";
    } catch (error) {
      window.alert(`Could not enable push alerts: ${error.message}`);
      pushButton.disabled = false;
    }
  });

  const careList = document.querySelector("#care-dose-list");
  if (careList) {
    const escapeHtml = (value) => String(value).replace(/[&<>"']/g, (char) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[char]));
    const refreshCareDoses = async () => {
      try {
        const response = await fetch(`/api/caregiver/doses?person=${encodeURIComponent(careList.dataset.person)}`);
        if (!response.ok) return;
        const payload = await response.json();
        if (!Array.isArray(payload.doses)) return;
        const nextUrl = location.pathname + location.search;
        careList.innerHTML = payload.doses.length
          ? payload.doses.map((dose) => {
              const canMark = dose.status === "Upcoming" || dose.status === "Missed";
              const action = canMark
                ? `<form method="post" action="/dose/${dose.id}/taken" class="care-take-form"><input type="hidden" name="next" value="${escapeHtml(nextUrl)}"><button class="button button-take button-small" type="submit">Mark taken</button></form>`
                : "";
              return `<div class="care-dose-row"><span class="care-dose-time">${formatTime(dose.scheduled_time)}</span><div class="care-dose-name"><strong>${escapeHtml(dose.medicine_name)}</strong><small>${escapeHtml(dose.dosage)}</small></div><span class="status-pill status-pill-${dose.status.toLowerCase()}"><span></span>${dose.status}</span>${action}</div>`;
            }).join("")
          : `<p class="empty-inline">No medicines are scheduled for today.</p>`;
      } catch (error) {
        // Keep the last good view if the refresh fails.
      }
    };
    setInterval(refreshCareDoses, 30000);
  }

  const doseList = document.querySelector("#dose-list, #global-dose-list");
  const reminderDialog = document.querySelector("#reminder-dialog");
  const takenForm = document.querySelector("#reminder-taken-form");
  const laterButton = document.querySelector("#remind-later");
  let snoozeTimer;

  function formatTime(value) {
    const [hours, minutes] = value.split(":").map(Number);
    const suffix = hours >= 12 ? "PM" : "AM";
    return `${hours % 12 || 12}:${String(minutes).padStart(2, "0")} ${suffix}`;
  }

  function openReminder(dose, snoozed = false) {
    if (!reminderDialog || !dose) return;
    document.querySelector("#reminder-medicine").textContent = `${dose.dataset.name} · ${dose.dataset.dosage}`;
    document.querySelector("#reminder-schedule").textContent = `Scheduled for ${formatTime(dose.dataset.time)}`;
    takenForm.action = `/dose/${dose.dataset.doseId}/taken`;
    if (!reminderDialog.open) reminderDialog.showModal();
    if (!snoozed) {
      playReminderSound();
      const popupEnabled = doseList.dataset.popupEnabled === "1";
      const notificationsEnabled = doseList.dataset.notificationsEnabled === "1";
      if (notificationsEnabled && "Notification" in window && Notification.permission === "granted") {
        new Notification("Time for your medicine", { body: `${dose.dataset.name} · ${dose.dataset.dosage}` });
      }
      if (popupEnabled && reminderDialog.open) document.querySelector("#reminder-title").focus?.();
    }
  }

  function playReminderSound() {
    if (!doseList || doseList.dataset.soundEnabled !== "1") return;
    const AudioContextClass = window.AudioContext || window.webkitAudioContext;
    if (!AudioContextClass) return;
    const audioContext = new AudioContextClass();
    if (audioContext.state === "suspended") audioContext.resume();
    [660, 520].forEach((frequency, index) => {
      const oscillator = audioContext.createOscillator();
      const gain = audioContext.createGain();
      const startAt = audioContext.currentTime + index * 0.18;
      oscillator.frequency.value = frequency;
      gain.gain.setValueAtTime(0.0001, startAt);
      gain.gain.exponentialRampToValueAtTime(0.08, startAt + 0.03);
      gain.gain.exponentialRampToValueAtTime(0.0001, startAt + 0.15);
      oscillator.connect(gain);
      gain.connect(audioContext.destination);
      oscillator.start(startAt);
      oscillator.stop(startAt + 0.16);
    });
    window.setTimeout(() => audioContext.close(), 600);
  }

  function checkSchedule() {
    if (!doseList) return;
    const now = new Date();
    const dayKey = `${now.getFullYear()}-${now.getMonth() + 1}-${now.getDate()}`;
    for (const dose of doseList.querySelectorAll("[data-reminder-dose]")) {
      if (dose.dataset.status !== "Upcoming") continue;
      const [hours, minutes] = dose.dataset.time.split(":").map(Number);
      const scheduled = new Date(now);
      scheduled.setHours(hours, minutes, 0, 0);
      const elapsed = now - scheduled;
      if (elapsed > 5 * 60 * 1000) {
        const missedKey = `pillpack-missed-${dayKey}-${dose.dataset.doseId}`;
        if (sessionStorage.getItem(missedKey)) continue;
        sessionStorage.setItem(missedKey, "updating");
        fetch(`/dose/${dose.dataset.doseId}/missed`, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({ next: window.location.pathname }),
        }).then((response) => {
          if (response.ok) window.location.reload();
          else sessionStorage.removeItem(missedKey);
        }).catch(() => sessionStorage.removeItem(missedKey));
        continue;
      }
      if (elapsed < 0) continue;
      const reminderKey = `pillpack-reminded-${dayKey}-${dose.dataset.doseId}`;
      if (sessionStorage.getItem(reminderKey)) continue;
      sessionStorage.setItem(reminderKey, "shown");
      if (doseList.dataset.popupEnabled === "1") openReminder(dose);
      else if (doseList.dataset.notificationsEnabled === "1" && "Notification" in window && Notification.permission === "granted") {
        new Notification("Time for your medicine", { body: `${dose.dataset.name} · ${dose.dataset.dosage}` });
      }
    }
  }

  laterButton?.addEventListener("click", () => {
    const activeDoseId = takenForm.action.match(/\/dose\/(\d+)\/taken$/)?.[1];
    const dose = doseList?.querySelector(`[data-dose-id="${activeDoseId}"]`);
    reminderDialog.close();
    window.clearTimeout(snoozeTimer);
    snoozeTimer = window.setTimeout(() => openReminder(dose, true), 5 * 60 * 1000);
  });

  if (doseList) {
    checkSchedule();
    let checkedDate = new Date().toDateString();
    window.setInterval(() => {
      const currentDate = new Date().toDateString();
      if (currentDate !== checkedDate) {
        window.location.reload();
        return;
      }
      checkSchedule();
    }, 15000);
  }

  // =========================================================================
  // Chatbot Client Controller
  // =========================================================================
  const chatbotContainer = document.querySelector("#chatbot-container");
  const chatbotLauncher = document.querySelector("#chatbot-launcher");
  const chatbotWindow = document.querySelector("#chatbot-window");
  const chatbotCloseBtn = document.querySelector("#chatbot-close-btn");
  const chatbotResetBtn = document.querySelector("#chatbot-reset-btn");
  const chatbotForm = document.querySelector("#chatbot-form");
  const chatbotInput = document.querySelector("#chatbot-input");
  const chatbotMessages = document.querySelector("#chatbot-messages");
  const chatbotTooltip = document.querySelector("#chatbot-tooltip");
  const chatbotSuggestions = document.querySelector("#chatbot-suggestions");

  if (chatbotLauncher && chatbotWindow) {
    function openChat() {
      chatbotWindow.hidden = false;
      chatbotLauncher.setAttribute("aria-expanded", "true");
      chatbotLauncher.setAttribute("title", "Close medication assistant");
      chatbotContainer?.classList.add("chat-active");
      if (chatbotTooltip) chatbotTooltip.hidden = true;
      window.setTimeout(() => chatbotInput?.focus(), 60);
      scrollToBottom();
    }

    function closeChat() {
      chatbotWindow.hidden = true;
      chatbotLauncher.setAttribute("aria-expanded", "false");
      chatbotLauncher.setAttribute("title", "Ask Smart PillPack Assistant");
      chatbotContainer?.classList.remove("chat-active");
    }

    function toggleChat() {
      if (chatbotWindow.hidden) {
        openChat();
      } else {
        closeChat();
      }
    }

    chatbotLauncher.addEventListener("click", (e) => {
      e.stopPropagation();
      toggleChat();
    });

    chatbotCloseBtn?.addEventListener("click", (e) => {
      e.stopPropagation();
      closeChat();
    });

    // Close when pressing Escape key
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && !chatbotWindow.hidden) {
        closeChat();
        chatbotLauncher.focus();
      }
    });

    // Close when clicking outside
    document.addEventListener("click", (e) => {
      if (!chatbotWindow.hidden && !chatbotContainer.contains(e.target)) {
        closeChat();
      }
    });

    function scrollToBottom() {
      if (chatbotMessages) {
        chatbotMessages.scrollTop = chatbotMessages.scrollHeight;
      }
    }

    function formatMarkdown(text) {
      if (!text) return "";
      let s = text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");
      s = s.replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>");
      s = s.replace(/\*(.*?)\*/g, "<em>$1</em>");
      s = s.replace(/\[(.*?)\]\((.*?)\)/g, '<a href="$2" class="chat-link" target="_self">$1</a>');
      s = s.replace(/^• (.*?)$/gm, '<li class="chat-bullet">$1</li>');
      s = s.replace(/(<li class="chat-bullet">.*?<\/li>)/s, '<ul class="chat-list">$1</ul>');
      s = s.replace(/\n\n/g, "<br><br>").replace(/\n/g, "<br>");
      return s;
    }

    function appendMessage(sender, htmlContent, suggestions = []) {
      const msgDiv = document.createElement("div");
      msgDiv.className = `chat-msg chat-msg-${sender}`;

      const avatarDiv = document.createElement("div");
      avatarDiv.className = "msg-avatar";
      avatarDiv.textContent = sender === "user" ? "Me" : "✦";

      const bubbleDiv = document.createElement("div");
      bubbleDiv.className = "msg-bubble";
      bubbleDiv.innerHTML = htmlContent;

      msgDiv.appendChild(avatarDiv);
      msgDiv.appendChild(bubbleDiv);
      chatbotMessages.appendChild(msgDiv);

      if (suggestions && suggestions.length > 0) {
        const suggWrap = document.createElement("div");
        suggWrap.className = "chatbot-suggestions chatbot-suggestions-inline";
        suggestions.forEach((q) => {
          const btn = document.createElement("button");
          btn.type = "button";
          btn.className = "chip-btn";
          btn.textContent = q;
          btn.addEventListener("click", () => sendQuery(q));
          suggWrap.appendChild(btn);
        });
        chatbotMessages.appendChild(suggWrap);
      }

      scrollToBottom();
    }

    function appendTypingIndicator() {
      const typingDiv = document.createElement("div");
      typingDiv.className = "chat-msg chat-msg-bot chat-typing";
      typingDiv.id = "chat-typing-indicator";
      typingDiv.innerHTML = '<div class="msg-avatar">✦</div><div class="msg-bubble"><div class="typing-dots"><span></span><span></span><span></span></div></div>';
      chatbotMessages.appendChild(typingDiv);
      scrollToBottom();
      return typingDiv;
    }

    async function sendQuery(queryText) {
      if (!queryText || !queryText.trim()) return;
      const text = queryText.trim();
      appendMessage("user", formatMarkdown(text));
      if (chatbotInput) chatbotInput.value = "";
      const indicator = appendTypingIndicator();
      if (chatbotInput) chatbotInput.disabled = true;

      try {
        const res = await fetch("/api/chat", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ message: text }),
        });
        indicator.remove();
        if (res.ok) {
          const data = await res.json();
          appendMessage("bot", formatMarkdown(data.reply), data.suggestions);
        } else {
          appendMessage("bot", "Sorry, I ran into an issue finding that answer. Please try again.");
        }
      } catch (err) {
        indicator.remove();
        appendMessage("bot", "Could not reach the assistant server. Please check your connection.");
      } finally {
        if (chatbotInput) {
          chatbotInput.disabled = false;
          chatbotInput.focus();
        }
      }
    }

    chatbotForm?.addEventListener("submit", (e) => {
      e.preventDefault();
      const val = chatbotInput.value;
      sendQuery(val);
    });

    chatbotSuggestions?.addEventListener("click", (e) => {
      const chip = e.target.closest(".chip-btn");
      if (chip && chip.dataset.query) {
        sendQuery(chip.dataset.query);
      }
    });

    chatbotResetBtn?.addEventListener("click", () => {
      chatbotMessages.innerHTML = `
        <div class="chat-msg chat-msg-bot">
          <div class="msg-avatar">✦</div>
          <div class="msg-bubble">
            <p>Chat cleared! How can I assist you with your schedule or medicines now?</p>
          </div>
        </div>
        <div class="chatbot-suggestions" id="chatbot-suggestions">
          <span class="suggestions-heading">Common questions:</span>
          <button type="button" class="chip-btn" data-query="What is my next scheduled dose?">⏰ Next dose</button>
          <button type="button" class="chip-btn" data-query="What medicines do I have scheduled today?">💊 Today's medicines</button>
          <button type="button" class="chip-btn" data-query="What should I do if I miss a dose?">⚠️ Missed dose guidance</button>
          <button type="button" class="chip-btn" data-query="How is my medication adherence this week?">📊 Adherence score</button>
        </div>
      `;
      chatbotMessages.querySelector("#chatbot-suggestions")?.addEventListener("click", (e) => {
        const chip = e.target.closest(".chip-btn");
        if (chip && chip.dataset.query) sendQuery(chip.dataset.query);
      });
    });

    if (chatbotTooltip) {
      window.setTimeout(() => {
        chatbotTooltip.style.opacity = "0";
        window.setTimeout(() => chatbotTooltip.remove(), 400);
      }, 7000);
    }
  }

  // Demo login credentials quick filler
  const fillRaviBtn = document.querySelector("#demo-fill-ravi");
  const fillAnitaBtn = document.querySelector("#demo-fill-anita");
  if (fillRaviBtn || fillAnitaBtn) {
    const emailInput = document.querySelector("#login-email");
    const passInput = document.querySelector("#login-password");
    const roleUser = document.querySelector("#role-user");
    const roleCaregiver = document.querySelector("#role-caregiver");

    fillRaviBtn?.addEventListener("click", () => {
      if (emailInput) emailInput.value = "ravi@pillpack.test";
      if (passInput) passInput.value = "demo1234";
      if (roleUser) roleUser.checked = true;
      emailInput?.focus();
    });

    fillAnitaBtn?.addEventListener("click", () => {
      if (emailInput) emailInput.value = "anita@pillpack.test";
      if (passInput) passInput.value = "demo1234";
      if (roleCaregiver) roleCaregiver.checked = true;
      emailInput?.focus();
    });
  }
})();
''',
    'js/swarm.js': r'''// Hendekeract 11-D hypercube particle swarm: 2048 vertices, rotated through 5
// hyperplanes and projected to 3D with perspective divide, dynamic breathing,
// live contrast spectrum colors, bloom post-processing, and interactive camera.
const host = document.getElementById("swarm");

async function start() {
  const THREE = await import("three");
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const lowPower = window.innerWidth < 760 || (navigator.hardwareConcurrency || 8) <= 4;
  const VERTS = 2048;
  const count = lowPower ? VERTS * 4 : 20000;
  const PARAMS = { scale: 40, rotSpeed: 0.4, focal: 4, jitter: 0.4 };

  const renderer = new THREE.WebGLRenderer({ antialias: false, alpha: false, powerPreference: "high-performance" });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.5));
  renderer.setClearColor(0x020806, 1);
  host.appendChild(renderer.domElement);

  const scene = new THREE.Scene();
  scene.fog = new THREE.FogExp2(0x020806, 0.0035);
  const camera = new THREE.PerspectiveCamera(60, 1, 0.1, 2000);

  const geometry = new THREE.TetrahedronGeometry(0.38);
  const material = new THREE.MeshBasicMaterial({ color: 0xffffff, toneMapped: false });
  const mesh = new THREE.InstancedMesh(geometry, material, count);
  mesh.frustumCulled = false;
  mesh.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
  mesh.instanceColor = new THREE.InstancedBufferAttribute(new Float32Array(count * 3), 3);
  mesh.instanceColor.setUsage(THREE.DynamicDrawUsage);
  scene.add(mesh);

  let composer = null;
  let bloom = null;
  try {
    const { EffectComposer } = await import("three/addons/postprocessing/EffectComposer.js");
    const { RenderPass } = await import("three/addons/postprocessing/RenderPass.js");
    const { UnrealBloomPass } = await import("three/addons/postprocessing/UnrealBloomPass.js");
    composer = new EffectComposer(renderer);
    composer.addPass(new RenderPass(scene, camera));
    bloom = new UnrealBloomPass(new THREE.Vector2(window.innerWidth, window.innerHeight), 1.8, 0.45, 0.08);
    composer.addPass(bloom);
  } catch (bloomErr) {
    console.warn("UnrealBloomPass post-processing unavailable, rendering directly:", bloomErr);
  }

  // 11-D hypercube vertices (+/- 1)
  const G = new Float32Array(VERTS * 11);
  for (let v = 0; v < VERTS; v++) {
    for (let k = 0; k < 11; k++) {
      G[v * 11 + k] = ((v >> k) & 1) * 2 - 1;
    }
  }

  // Instances initial setup
  const mat = mesh.instanceMatrix.array;
  const pos = new Float32Array(count * 3);
  for (let i = 0; i < count; i++) {
    mat[i * 16] = mat[i * 16 + 5] = mat[i * 16 + 10] = mat[i * 16 + 15] = 1;
    for (let k = 0; k < 3; k++) pos[i * 3 + k] = (Math.random() - 0.5) * 100;
  }

  const base = new Float32Array(VERTS * 3);
  const colorBuf = new Float32Array(VERTS * 3);
  const col = new THREE.Color();
  const colorArr = mesh.instanceColor.array;
  const subs = Math.ceil(count / VERTS);
  const off = new Float32Array(subs * 3);

  function update(time) {
    const { scale, rotSpeed, focal, jitter } = PARAMS;
    const ca = [], sa = [];
    for (const m of [1.0, 1.15, 0.85, 1.3, 0.65]) {
      const a = time * rotSpeed * m;
      ca.push(Math.cos(a));
      sa.push(Math.sin(a));
    }
    const k10 = 0.5 + 0.5 * Math.sin(time * rotSpeed * 0.7);
    const perspMax = focal / (focal - 1);
    const breathe = 0.85 + 0.15 * Math.sin(time * 0.5);
    const fs = scale * breathe;

    for (let v = 0; v < VERTS; v++) {
      const o = v * 11;
      const g0 = G[o], g1 = G[o + 1], g2 = G[o + 2], g3 = G[o + 3], g4 = G[o + 4], g5 = G[o + 5];
      const g6 = G[o + 6], g7 = G[o + 7], g8 = G[o + 8], g9 = G[o + 9], g10 = G[o + 10];
      const r0 = g0 * ca[0] - g1 * sa[0], r1 = g0 * sa[0] + g1 * ca[0];
      const r2 = g2 * ca[1] - g3 * sa[1], r3 = g2 * sa[1] + g3 * ca[1];
      const r4 = g4 * ca[2] - g5 * sa[2], r5 = g4 * sa[2] + g5 * ca[2];
      const r6 = g6 * ca[3] - g7 * sa[3], r7 = g6 * sa[3] + g7 * ca[3];
      const r8 = g8 * ca[4] - g9 * sa[4], r9 = g8 * sa[4] + g9 * ca[4];
      const r10 = g10 * k10;
      const w = (r3 + r4 + r5 + r6 + r7 + r8 + r9 + r10) * 0.125;
      const persp = focal / (focal - w);
      base[v * 3] = r0 * persp * fs;
      base[v * 3 + 1] = r1 * persp * fs;
      base[v * 3 + 2] = r2 * persp * fs;

      // Vivid contrast spectrum: cycling saturated neon colors (cyan, emerald, purple, magenta, gold, electric blue)
      const hue = (v / VERTS * 1.25 + time * 0.05) % 1.0;
      // High contrast saturation (100%) and optimal lum for rich color pop
      const light = 0.50 + 0.18 * Math.sin(time * 0.8 + (v / VERTS) * 6.28);
      col.setHSL(hue, 1.0, light);
      colorBuf[v * 3] = col.r;
      colorBuf[v * 3 + 1] = col.g;
      colorBuf[v * 3 + 2] = col.b;
    }

    for (let s = 0; s < subs; s++) {
      const ja = s * 2.39996 + time * 0.25;
      const jr = jitter * (0.3 + 0.7 * ((s % 5) / 5));
      off[s * 3] = Math.cos(ja) * jr;
      off[s * 3 + 1] = Math.sin(ja * 1.3) * jr;
      off[s * 3 + 2] = Math.sin(ja * 0.7 + 1.1) * jr;
    }

    for (let i = 0; i < count; i++) {
      const v = i & (VERTS - 1), s = i >> 11;
      for (let k = 0; k < 3; k++) {
        const p = i * 3 + k;
        pos[p] += (base[v * 3 + k] + off[s * 3 + k] - pos[p]) * 0.1;
        mat[i * 16 + 12 + k] = pos[p];
        colorArr[p] = colorBuf[v * 3 + k];
      }
    }
    mesh.instanceMatrix.needsUpdate = true;
    mesh.instanceColor.needsUpdate = true;
  }

  let mouseX = 0, mouseY = 0;
  let targetRotX = 0, targetRotY = 0;
  window.addEventListener("pointermove", (e) => {
    const rect = host.getBoundingClientRect();
    if (rect.width > 0 && rect.height > 0) {
      const x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
      const y = ((e.clientY - rect.top) / rect.height) * 2 - 1;
      targetRotX = Math.max(-1, Math.min(1, x)) * 0.6;
      targetRotY = Math.max(-1, Math.min(1, y)) * 0.35;
    }
  }, { passive: true });

  let camDist = 100;
  function resize() {
    const w = Math.max(host.clientWidth, 1), h = Math.max(host.clientHeight, 1);
    renderer.setSize(w, h, false);
    if (composer) composer.setSize(w, h);
    if (bloom && bloom.resolution) bloom.resolution.set(w, h);
    camera.aspect = w / h;
    camDist = Math.max(100, 66 / (Math.tan(Math.PI / 6) * camera.aspect));
    camera.updateProjectionMatrix();
  }

  function frame(time) {
    update(time);
    mouseX += (targetRotX - mouseX) * 0.05;
    mouseY += (targetRotY - mouseY) * 0.05;
    const a = time * (Math.PI * 2 / 30) + mouseX;
    const elevation = mouseY * 35;
    camera.position.set(Math.sin(a) * camDist, elevation, Math.cos(a) * camDist);
    camera.lookAt(0, 0, 0);

    if (composer) {
      composer.render();
    } else {
      renderer.render(scene, camera);
    }
  }

  new ResizeObserver(resize).observe(host);
  resize();
  host.parentElement.classList.add("swarm-on");

  if (reduceMotion) {
    for (let n = 0; n < 60; n++) update(8);
    frame(8);
    return;
  }

  const clock = new THREE.Clock();
  let raf = 0;
  const loop = () => {
    frame(clock.getElapsedTime());
    raf = requestAnimationFrame(loop);
  };
  const toggle = () => {
    cancelAnimationFrame(raf);
    if (!document.hidden) loop();
  };
  document.addEventListener("visibilitychange", toggle);
  loop();
}

if (host) start().catch((err) => {
  console.warn("3D background unavailable, using standard panel fallback.", err);
  host.remove();
});
''',
}

STATIC_TYPES = {".css": "text/css", ".js": "text/javascript"}


def serve_static(filename):
    body = STATIC_ASSETS.get(filename)
    if body is None:
        abort(404)
    response = Response(body, mimetype=STATIC_TYPES[Path(filename).suffix])
    response.headers["Cache-Control"] = "no-cache"
    return response


app.jinja_loader = DictLoader(TEMPLATES)
app.add_url_rule("/static/<path:filename>", endpoint="static", view_func=serve_static)


@app.route("/firebase-messaging-sw.js")
def firebase_messaging_sw():
    """Service worker: shows missed-dose alerts even when no tab is open."""
    config = firebase_web_config()
    sw_body = f"""// Generated by Smart PillPack
importScripts('https://www.gstatic.com/firebasejs/10.12.5/firebase-app-compat.js');
importScripts('https://www.gstatic.com/firebasejs/10.12.5/firebase-messaging-compat.js');
firebase.initializeApp({json.dumps(config)});
const messaging = firebase.messaging();
messaging.onBackgroundMessage((payload) => {{
  const notification = payload.notification || {{}};
  const link = (payload.fcm_options && payload.fcm_options.link) || '/caregiver';
  self.registration.showNotification(notification.title || 'Smart PillPack', {{
    body: notification.body || '',
    data: {{ url: link }},
  }});
}});
self.addEventListener('notificationclick', (event) => {{
  event.notification.close();
  event.waitUntil(clients.openWindow(event.notification.data && event.notification.data.url || '/caregiver'));
}});
"""
    response = Response(sw_body, mimetype="application/javascript")
    response.headers["Cache-Control"] = "no-cache"
    return response


_alerts_poller = {"started": False, "lock": threading.Lock()}


def _missed_dose_poller():
    while True:
        time.sleep(max(app.config["ALERTS_POLL_SECONDS"], 10))
        if app.config.get("TESTING"):
            continue
        try:
            today_text = date.today().isoformat()
            with connect_db() as db:
                user_ids = [
                    row["user_id"]
                    for row in db.execute(
                        """SELECT DISTINCT user_id FROM medications
                        WHERE start_date <= ? AND (end_date = '' OR end_date >= ?)""",
                        (today_text, today_text),
                    ).fetchall()
                ]
            for user_id in user_ids:
                sync_doses(user_id)
        except Exception:
            app.logger.exception("Missed-dose poller iteration failed")


def start_alerts_poller():
    if app.config.get("TESTING") or _alerts_poller["started"]:
        return
    with _alerts_poller["lock"]:
        if _alerts_poller["started"]:
            return
        _alerts_poller["started"] = True
        threading.Thread(target=_missed_dose_poller, daemon=True).start()


@app.before_request
def _ensure_alerts_poller():
    start_alerts_poller()


if __name__ == "__main__":
    app.run(
        debug=os.environ.get("FLASK_DEBUG") == "1",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5000")),
    )