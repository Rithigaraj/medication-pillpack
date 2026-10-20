# Smart PillPack – Medication Reminder

A responsive medication schedule and reminder web app for users and caregivers. It uses Flask, SQLite, and browser-based reminders.

## Requirements

- Python 3.10 or newer
- A modern browser

## Install and run on Windows

Open PowerShell in this folder and run:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install -r requirements.txt
py app.py
```

If PowerShell blocks virtual-environment activation, run `py -m pip install -r requirements.txt` with your selected Python installation and then `py app.py`.

Open [http://127.0.0.1:5000](http://127.0.0.1:5000). The local server is intended for development and personal testing.

For deployment, set a unique `SECRET_KEY`, turn off Flask debug mode, use HTTPS, and use a production WSGI server. The built-in development server and default secret are not suitable for public deployment.

## Password reset (email OTP)

The **Forgot password?** flow emails a 6-digit verification code; after the code is confirmed, the user chooses a new password. Codes expire after 10 minutes, allow 5 attempts, and are rate-limited (60-second resend cooldown, 3 codes per hour per account).

Configure delivery in a `.env` file in the project folder (copy `.env.example`):

```dotenv
MAIL_USERNAME=you@gmail.com
MAIL_PASSWORD=your-16-character-gmail-app-password
MAIL_DEFAULT_SENDER=you@gmail.com
```

Gmail does not accept your normal account password. Create a one-time **App Password** at <https://myaccount.google.com/apppasswords> (requires 2-Step Verification) and use it as `MAIL_PASSWORD`. The app defaults to `smtp.gmail.com:587` with STARTTLS; override with `MAIL_SERVER`, `MAIL_PORT`, or `MAIL_USE_TLS=0` for other providers.

Without SMTP configuration the app runs in local mode: the code is shown on the verification screen and archived to `instance/sent_emails.log`. Optional tuning keys: `OTP_TTL_SECONDS` (600), `OTP_MAX_ATTEMPTS` (5), `OTP_RESEND_COOLDOWN_SECONDS` (60), `OTP_MAX_PER_HOUR` (3).

## Database

The app creates `instance/pillpack.sqlite3` and its tables the first time it starts. It seeds the two demo accounts and Ravi’s sample schedule automatically. The database stays on this machine. To start over, stop the app and remove that database file; the next start will create a fresh demo database.

## Demo accounts

Both accounts use the password `demo1234`:

| Account | Email | Sign in as |
| --- | --- | --- |
| Ravi Kumar | `ravi@pillpack.test` | Me |
| Anita Kumar | `anita@pillpack.test` | Caregiver |

Anita is linked to Ravi in the sample data. When creating a user account, add the email address of an existing caregiver account to link the caregiver view. A user can manage a schedule from **My medicines**; missed doses appear in the linked caregiver’s overview.

## Features

- Account registration, password hashing, login, logout, and session-based access
- Separate user and caregiver dashboards
- Medication schedule creation, editing, and removal
- Daily dose records with upcoming, taken, missed, and skipped states
- Browser dashboard popups, optional browser notifications, and five-minute snooze
- Today, week, and month history filters
- Downloadable CSV medication-history reports for each history period
- Seven-day adherence summary on the user dashboard
- Caregiver adherence totals, upcoming schedule, and missed-dose alerts
- Caregivers can mark a linked person’s dose as taken directly from the caregiver overview
- Live schedule refresh on the caregiver page (every 30 seconds)
- Firebase Cloud Messaging push alerts to caregiver devices when a dose is missed
- Editable profile and saved text-size, theme, and reminder preferences
- Responsive layouts, keyboard focus styles, and larger readable controls

Browser reminders run while the dashboard is open. Browser notifications require permission and are generally available only on localhost or a secure HTTPS site. Missed-dose status is updated whenever a page checks the schedule, and a background poller (every `ALERTS_POLL_SECONDS`, default 45 s) updates it even when nobody has the app open, so a caregiver is alerted promptly.

## Caregiver push alerts (Firebase Cloud Messaging)

Push is optional — everything else works without it. To enable it:

1. Create a Firebase project and enable **Cloud Messaging**.
2. **Project settings → Service accounts → Generate new private key**; save the JSON and point `FIREBASE_CREDENTIALS` at it (or copy it to `instance/firebase-service-account.json`), and set `FIREBASE_PROJECT_ID`.
3. **Project settings → General → Your apps → Web app**: copy `FIREBASE_API_KEY`, `FIREBASE_AUTH_DOMAIN`, `FIREBASE_MESSAGING_SENDER_ID`, and `FIREBASE_APP_ID` into `.env`.
4. **Cloud Messaging → Web configuration**: generate a Web Push certificate and set `FIREBASE_VAPID_KEY`.

With those set, the caregiver overview shows an **Enable missed-dose alerts** button; the browser registers its device token at `POST /api/push-token`. When a dose flips to *Missed*, the server sends a push to every linked caregiver device. Without configuration, the button stays hidden and the app behaves as before.

## Tests

Run the route tests with:

```powershell
py -m unittest -v
```