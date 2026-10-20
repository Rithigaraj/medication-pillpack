import re
import tempfile
import unittest
from datetime import date, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import app as pillpack


class PillPackRoutesTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        pillpack.app.config.update(
            TESTING=True,
            DATABASE=str(Path(self.temp_dir.name) / "test.sqlite3"),
            SECRET_KEY="test-secret",
            MAIL_USERNAME="",
            MAIL_PASSWORD="",
        )
        pillpack.init_db()
        self.client = pillpack.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def login(self, email="ravi@pillpack.test", role="user"):
        return self.client.post(
            "/login",
            data={"email": email, "password": "demo1234", "role": role},
            follow_redirects=True,
        )

    def test_demo_user_can_open_dashboard_and_history(self):
        response = self.login()
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Today\xe2\x80\x99s medicines", response.data)
        self.assertIn(b"Metformin", response.data)
        self.assertIn(b"Your next medicine is", response.data)
        history = self.client.get("/history?period=week")
        self.assertEqual(history.status_code, 200)
        self.assertIn(b"Medication history", history.data)
        self.assertIn(b"Your consistency", response.data)

    def test_history_csv_export_is_available_to_user_only(self):
        self.login()
        response = self.client.get("/history/export?period=week")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/csv", response.content_type)
        self.assertIn("attachment", response.headers["Content-Disposition"])
        self.assertIn(b"date,medicine,dosage", response.data.lower())
        self.assertIn(b"Metformin", response.data)
        self.client.post("/logout")
        self.login("anita@pillpack.test", "caregiver")
        denied = self.client.get("/history/export?period=week")
        self.assertEqual(denied.status_code, 302)

    def test_user_can_create_edit_and_delete_medication(self):
        self.login()
        response = self.client.post(
            "/medications/new",
            data={
                "medicine_name": "Test medicine",
                "dosage": "10 mg",
                "medicine_type": "Tablet",
                "frequency": "Once daily",
                "times": "23:59",
                "start_date": date.today().isoformat(),
                "end_date": "",
                "food_instruction": "After food",
                "notes": "With water",
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Test medicine", response.data)
        with pillpack.connect_db() as db:
            medicine_id = db.execute(
                "SELECT id FROM medications WHERE medicine_name = ?", ("Test medicine",)
            ).fetchone()["id"]
        response = self.client.post(
            f"/medications/{medicine_id}/edit",
            data={
                "medicine_name": "Updated medicine",
                "dosage": "20 mg",
                "medicine_type": "Tablet",
                "frequency": "Once daily",
                "times": "23:59",
                "start_date": date.today().isoformat(),
                "food_instruction": "After food",
            },
            follow_redirects=True,
        )
        self.assertIn(b"Updated medicine", response.data)
        response = self.client.post(f"/medications/{medicine_id}/delete", follow_redirects=True)
        self.assertNotIn(b"Updated medicine", response.data)

    def test_caregiver_sees_linked_person_and_schedule(self):
        response = self.login("anita@pillpack.test", "caregiver")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Ravi Kumar", response.data)
        self.assertIn(b"Medication schedule", response.data)

    def test_registration_creates_a_logged_in_user(self):
        response = self.client.post(
            "/register",
            data={
                "name": "New User",
                "email": "new-user@example.test",
                "password": "securepass123",
                "confirm_password": "securepass123",
                "age": "68",
                "role": "user",
                "caregiver_contact": "anita@pillpack.test",
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"New User", response.data)
        self.assertIn(b"Your plan starts here", response.data)

    def test_user_can_mark_a_scheduled_dose_taken(self):
        self.login()
        scheduled_time = (datetime.now() + timedelta(minutes=2)).strftime("%H:%M")
        self.client.post(
            "/medications/new",
            data={
                "medicine_name": "Dose test",
                "dosage": "1 tablet",
                "medicine_type": "Tablet",
                "frequency": "Once daily",
                "times": scheduled_time,
                "start_date": date.today().isoformat(),
                "food_instruction": "Any time",
            },
        )
        self.client.get("/dashboard")
        with pillpack.connect_db() as db:
            dose = db.execute(
                "SELECT id FROM medication_history WHERE medication_id = (SELECT id FROM medications WHERE medicine_name = ?) AND date = ?",
                ("Dose test", date.today().isoformat()),
            ).fetchone()
        self.assertIsNotNone(dose)
        response = self.client.post(f"/dose/{dose['id']}/taken", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        with pillpack.connect_db() as db:
            status = db.execute(
                "SELECT status, taken_time FROM medication_history WHERE id = ?", (dose["id"],)
            ).fetchone()
        self.assertEqual(status["status"], "Taken")
        self.assertTrue(status["taken_time"])

    def test_overdue_dose_can_be_marked_missed(self):
        self.login()
        with pillpack.connect_db() as db:
            user_id = db.execute(
                "SELECT id FROM users WHERE email = ?", ("ravi@pillpack.test",)
            ).fetchone()["id"]
            medication_id = db.execute(
                "SELECT id FROM medications WHERE user_id = ? LIMIT 1", (user_id,)
            ).fetchone()["id"]
            cursor = db.execute(
                """INSERT INTO medication_history
                (user_id, medication_id, scheduled_time, date, status)
                VALUES (?, ?, '09:00', ?, 'Upcoming')""",
                (user_id, medication_id, date.today().isoformat()),
            )
            dose_id = cursor.lastrowid
        fixed_now = datetime.combine(date.today(), datetime.min.time()).replace(hour=22)
        with patch.object(pillpack, "datetime") as mocked_datetime:
            mocked_datetime.now.return_value = fixed_now
            response = self.client.post(f"/dose/{dose_id}/missed")
        self.assertEqual(response.status_code, 302)
        with pillpack.connect_db() as db:
            status = db.execute(
                "SELECT status FROM medication_history WHERE id = ?", (dose_id,)
            ).fetchone()["status"]
        self.assertEqual(status, "Missed")

    def test_profile_and_settings_are_saved(self):
        self.login()
        response = self.client.post(
            "/profile",
            data={
                "name": "Ravi K.",
                "email": "ravi@pillpack.test",
                "age": "73",
                "caregiver_contact": "anita@pillpack.test",
            },
            follow_redirects=True,
        )
        self.assertIn(b"Ravi K.", response.data)
        response = self.client.post(
            "/settings",
            data={"font_size": "larger", "theme": "dark", "notifications": "on", "reminder_popup": "on"},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        with pillpack.connect_db() as db:
            settings = db.execute(
                "SELECT font_size, theme FROM user_settings WHERE user_id = 1"
            ).fetchone()
        self.assertEqual(settings["font_size"], "larger")
        self.assertEqual(settings["theme"], "dark")

    @patch.object(pillpack, "domain_can_receive_mail", return_value=True)
    @patch.object(pillpack, "smtp_configured", return_value=True)
    @patch.object(pillpack, "send_otp_email")
    def test_forgot_password_sends_otp_and_resets_password(self, send_email, _smtp, _domain):
        send_email.return_value = True
        response = self.client.post("/forgot-password", data={"email": "ravi@pillpack.test"})
        self.assertEqual(response.status_code, 302)
        send_email.assert_called_once()
        code = send_email.call_args.args[1]
        self.assertEqual(len(code), 6)
        self.assertTrue(code.isdigit())

        page = self.client.get("/verify-otp")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"Enter the 6-digit code", page.data)
        self.assertIn(b"ra\xe2\x80\xa2\xe2\x80\xa2\xe2\x80\xa2@pillpack.test", page.data)

        wrong = self.client.post("/verify-otp", data={"code": ["0"] * 6}, follow_redirects=True)
        self.assertIn(b"incorrect", wrong.data)

        verify = self.client.post("/verify-otp", data={"code": list(code)}, follow_redirects=True)
        self.assertIn(b"Choose a new password", verify.data)

        response = self.client.post(
            "/reset-password",
            data={"password": "newsecurepass", "confirm_password": "newsecurepass"},
            follow_redirects=True,
        )
        self.assertIn(b"Your password has been reset", response.data)
        self.assertEqual(
            self.client.post(
                "/login", data={"email": "ravi@pillpack.test", "password": "newsecurepass", "role": "user"}
            ).status_code,
            302,
        )

    @patch.object(pillpack, "domain_can_receive_mail", return_value=True)
    @patch.object(pillpack, "smtp_configured", return_value=True)
    @patch.object(pillpack, "send_otp_email")
    def test_reset_requires_verified_code_before_password_change(self, send_email, _smtp, _domain):
        send_email.return_value = True
        self.client.post("/forgot-password", data={"email": "ravi@pillpack.test"})
        blocked = self.client.post(
            "/reset-password",
            data={"password": "newsecurepass", "confirm_password": "newsecurepass"},
            follow_redirects=True,
        )
        self.assertIn(b"Verify the code", blocked.data)
        with pillpack.connect_db() as db:
            password = db.execute(
                "SELECT password FROM users WHERE email = ?", ("ravi@pillpack.test",)
            ).fetchone()["password"]
        self.assertTrue(password)
        self.assertNotIn(b"Your password has been reset", blocked.data)

    @patch.object(pillpack, "send_otp_email")
    def test_forgot_password_does_not_reveal_unknown_email(self, send_email):
        response = self.client.post("/forgot-password", data={"email": "unknown@example.test"}, follow_redirects=True)
        self.assertIn(b"If an account matches that email", response.data)
        send_email.assert_not_called()

    @patch.object(pillpack, "domain_can_receive_mail", return_value=True)
    @patch.object(pillpack, "smtp_configured", return_value=True)
    @patch.object(pillpack, "send_otp_email")
    def test_otp_locks_out_after_max_attempts(self, send_email, _smtp, _domain):
        send_email.return_value = True
        self.client.post("/forgot-password", data={"email": "ravi@pillpack.test"})
        code = send_email.call_args.args[1]
        wrong_digit = "0" if code[0] != "0" else "1"
        for _ in range(5):
            self.client.post("/verify-otp", data={"code": [wrong_digit] * 6})
        locked = self.client.post("/verify-otp", data={"code": list(code)}, follow_redirects=True)
        self.assertIn(b"Too many incorrect attempts", locked.data)

    @patch.object(pillpack, "domain_can_receive_mail", return_value=True)
    @patch.object(pillpack, "smtp_configured", return_value=True)
    @patch.object(pillpack, "send_otp_email")
    def test_forgot_password_rate_limits_with_visible_message(self, send_email, _smtp, _domain):
        send_email.return_value = True
        self.client.post("/forgot-password", data={"email": "ravi@pillpack.test"})
        second = self.client.post("/forgot-password", data={"email": "ravi@pillpack.test"}, follow_redirects=True)
        self.assertIn(b"please wait", second.data.lower())
        self.assertIn(b"before requesting another code", second.data)
        send_email.assert_called_once()

    def test_domain_can_receive_mail_checks_dns(self):
        self.assertFalse(pillpack.domain_can_receive_mail("ravi@pillpack.test"))
        self.assertFalse(pillpack.domain_can_receive_mail("not-an-email"))
        self.assertTrue(pillpack.domain_can_receive_mail("someone@gmail.com"))

    def test_chatbot_answers_user_queries(self):
        # 1. Unauthenticated request should redirect to login
        unauth_resp = self.client.post("/api/chat", json={"message": "What is my next dose?"})
        self.assertEqual(unauth_resp.status_code, 302)

        # 2. Login as demo user
        self.login("ravi@pillpack.test", role="user")

        # 3. Empty message returns 400
        empty_resp = self.client.post("/api/chat", json={"message": "   "})
        self.assertEqual(empty_resp.status_code, 400)

        # 4. Next dose inquiry
        next_resp = self.client.post("/api/chat", json={"message": "What is my next dose?"})
        self.assertEqual(next_resp.status_code, 200)
        data = next_resp.get_json()
        self.assertIn("reply", data)
        self.assertIn("suggestions", data)

        # 5. Missed dose guidance
        missed_resp = self.client.post("/api/chat", json={"message": "What if I miss a dose?"})
        self.assertEqual(missed_resp.status_code, 200)
        missed_data = missed_resp.get_json()
        self.assertIn("double dose", missed_data["reply"].lower())

    def test_caregiver_can_login_with_autofilled_default_role(self):
        # Even if the role radio was defaulted to 'user', caregiver credentials must succeed
        response = self.client.post(
            "/login",
            data={"email": "anita@pillpack.test", "password": "demo1234", "role": "user"},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Care overview", response.data)

    def test_forgot_password_in_local_dev_provides_reset_card_and_outbox(self):
        response = self.client.post(
            "/forgot-password",
            data={"email": "ravi@pillpack.test"},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Verification code (shown here)", response.data)
        self.assertIn(b"Archived to", response.data)
        log_text = (pillpack.BASE_DIR / "instance" / "sent_emails.log").read_text(encoding="utf-8")
        entries = re.findall(r"RECIPIENT: ravi@pillpack\.test\r?\nSUBJECT: [^\r\n]+\r?\nCODE: (\d{6})", log_text)
        self.assertTrue(entries)
        self.assertIn(entries[-1].encode(), response.data)


    def test_caregiver_can_mark_linked_dose_taken(self):
        response = self.login("anita@pillpack.test", "caregiver")
        self.assertIn(b"Medication schedule", response.data)
        with pillpack.connect_db() as db:
            user_id = db.execute(
                "SELECT id FROM users WHERE email = ?", ("ravi@pillpack.test",)
            ).fetchone()["id"]
            medication_id = db.execute(
                "SELECT id FROM medications WHERE user_id = ? LIMIT 1", (user_id,)
            ).fetchone()["id"]
            future_time = (datetime.now() + timedelta(hours=3)).strftime("%H:%M")
            cursor = db.execute(
                """INSERT INTO medication_history
                (user_id, medication_id, scheduled_time, date, status)
                VALUES (?, ?, ?, ?, 'Upcoming')""",
                (user_id, medication_id, future_time, date.today().isoformat()),
            )
            dose_id = cursor.lastrowid
        response = self.client.post(
            f"/dose/{dose_id}/taken",
            data={"next": "/caregiver"},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Marked as taken", response.data)
        with pillpack.connect_db() as db:
            dose = db.execute(
                "SELECT status, taken_time FROM medication_history WHERE id = ?", (dose_id,)
            ).fetchone()
        self.assertEqual(dose["status"], "Taken")
        self.assertTrue(dose["taken_time"])

    def test_caregiver_cannot_mark_unlinked_person_dose(self):
        with pillpack.connect_db() as db:
            cursor = db.execute(
                """INSERT INTO users (name, email, age, role, password)
                VALUES ('Stranger', 'stranger@example.test', 60, 'user', 'x')"""
            )
            stranger_id = cursor.lastrowid
            cursor = db.execute(
                """INSERT INTO medications
                (user_id, medicine_name, dosage, medicine_type, frequency, time, start_date)
                VALUES (?, 'Private med', '1 tablet', 'Tablet', 'Once daily', '09:00', ?)""",
                (stranger_id, date.today().isoformat()),
            )
            cursor = db.execute(
                """INSERT INTO medication_history
                (user_id, medication_id, scheduled_time, date, status)
                VALUES (?, ?, '09:00', ?, 'Upcoming')""",
                (stranger_id, cursor.lastrowid, date.today().isoformat()),
            )
            dose_id = cursor.lastrowid
        self.login("anita@pillpack.test", "caregiver")
        denied = self.client.post(f"/dose/{dose_id}/taken", follow_redirects=False)
        self.assertEqual(denied.status_code, 403)
        with pillpack.connect_db() as db:
            status = db.execute(
                "SELECT status FROM medication_history WHERE id = ?", (dose_id,)
            ).fetchone()["status"]
        self.assertEqual(status, "Upcoming")

    def test_push_token_register_and_unregister(self):
        unauth = self.client.post("/api/push-token", json={"token": "device-abc"})
        self.assertEqual(unauth.status_code, 302)
        self.login("anita@pillpack.test", "caregiver")
        ok = self.client.post("/api/push-token", json={"token": "device-abc"})
        self.assertEqual(ok.status_code, 200)
        bad = self.client.post("/api/push-token", json={})
        self.assertEqual(bad.status_code, 400)
        with pillpack.connect_db() as db:
            rows = db.execute(
                "SELECT user_id FROM push_tokens WHERE token = ?", ("device-abc",)
            ).fetchall()
        self.assertEqual(len(rows), 1)
        removed = self.client.delete("/api/push-token", json={"token": "device-abc"})
        self.assertEqual(removed.status_code, 200)
        with pillpack.connect_db() as db:
            rows = db.execute(
                "SELECT id FROM push_tokens WHERE token = ?", ("device-abc",)
            ).fetchall()
        self.assertEqual(rows, [])

    @patch.object(pillpack, "notify_caregivers_of_missed")
    def test_missed_dose_notifies_caregivers(self, notify):
        self.login()
        with pillpack.connect_db() as db:
            user_id = db.execute(
                "SELECT id FROM users WHERE email = ?", ("ravi@pillpack.test",)
            ).fetchone()["id"]
            medication_id = db.execute(
                "SELECT id FROM medications WHERE user_id = ? LIMIT 1", (user_id,)
            ).fetchone()["id"]
            db.execute(
                """INSERT INTO medication_history
                (user_id, medication_id, scheduled_time, date, status)
                VALUES (?, ?, '00:01', ?, 'Upcoming')""",
                (user_id, medication_id, date.today().isoformat()),
            )
        response = self.client.get("/dashboard")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(notify.called)
        self.assertTrue(any(call.args[0] == user_id for call in notify.call_args_list))
        with pillpack.connect_db() as db:
            missed = db.execute(
                """SELECT COUNT(*) AS n FROM medication_history
                WHERE user_id = ? AND status = 'Missed' AND scheduled_time = '00:01'""",
                (user_id,),
            ).fetchone()["n"]
        self.assertEqual(missed, 1)
        first_pass = sum(1 for call in notify.call_args_list if call.args[3] == "00:01")
        self.assertEqual(first_pass, 1)
        self.client.get("/dashboard")
        second_pass = sum(1 for call in notify.call_args_list if call.args[3] == "00:01")
        self.assertEqual(second_pass, 1, "A missed dose must be announced only once")

    def test_caregiver_doses_api_checks_linkage(self):
        self.login("anita@pillpack.test", "caregiver")
        with pillpack.connect_db() as db:
            ravi_id = db.execute(
                "SELECT id FROM users WHERE email = ?", ("ravi@pillpack.test",)
            ).fetchone()["id"]
        ok = self.client.get(f"/api/caregiver/doses?person={ravi_id}")
        self.assertEqual(ok.status_code, 200)
        self.assertIsInstance(ok.get_json().get("doses"), list)
        denied = self.client.get("/api/caregiver/doses?person=999999")
        self.assertEqual(denied.status_code, 403)

    def test_firebase_service_worker_route(self):
        response = self.client.get("/firebase-messaging-sw.js")
        self.assertEqual(response.status_code, 200)
        self.assertIn("javascript", response.content_type)
        self.assertIn(b"importScripts", response.data)
        self.assertIn(b"onBackgroundMessage", response.data)


if __name__ == "__main__":
    unittest.main()