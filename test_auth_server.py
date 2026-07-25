"""
Experiment 13 - Test Cases
--------------------------------
Run from the Experiment13_Security directory with:
    python3 tests/test_auth_server.py -v
"""

import unittest
import sys
import os
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import auth_server
from auth_server import LoginServer, AuthError
import database as db


class TestRegistrationAndLogin(unittest.TestCase):

    def setUp(self):
        self.srv = LoginServer(db_path="test_auth.db", fresh=True)

    def tearDown(self):
        if os.path.exists("test_auth.db"):
            os.remove("test_auth.db")

    def test_register_and_login_success(self):
        self.srv.register_user("alice", "AliceP@ss123", "student")
        token = self.srv.login("alice", "AliceP@ss123")
        self.assertIsInstance(token, str)
        self.assertIn(token, self.srv.sessions)

    def test_duplicate_registration_fails(self):
        self.srv.register_user("alice", "AliceP@ss123", "student")
        with self.assertRaises(AuthError):
            self.srv.register_user("alice", "Another1!", "student")

    def test_wrong_password_fails(self):
        self.srv.register_user("alice", "AliceP@ss123", "student")
        with self.assertRaises(AuthError):
            self.srv.login("alice", "wrong-password")

    def test_unknown_user_fails(self):
        with self.assertRaises(AuthError):
            self.srv.login("ghost", "whatever")

    def test_invalid_role_rejected(self):
        with self.assertRaises(AuthError):
            self.srv.register_user("x", "Passw0rd!", "superuser")


class TestRBAC(unittest.TestCase):

    def setUp(self):
        self.srv = LoginServer(db_path="test_auth.db", fresh=True)
        self.srv.register_user("stu", "StuP@ss123", "student")
        self.srv.register_user("lec", "LecP@ss123", "lecturer")
        self.srv.register_user("adm", "AdmP@ss123", "admin")
        self.stu_tok = self.srv.login("stu", "StuP@ss123")
        self.lec_tok = self.srv.login("lec", "LecP@ss123")
        self.adm_tok = self.srv.login("adm", "AdmP@ss123")

    def tearDown(self):
        if os.path.exists("test_auth.db"):
            os.remove("test_auth.db")

    def test_student_permissions(self):
        self.assertTrue(self.srv.check_permission(self.stu_tok, "read"))
        self.assertTrue(self.srv.check_permission(self.stu_tok, "write", is_owner=True))
        self.assertFalse(self.srv.check_permission(self.stu_tok, "write", is_owner=False))
        self.assertFalse(self.srv.check_permission(self.stu_tok, "delete", is_owner=True))

    def test_lecturer_permissions(self):
        self.assertTrue(self.srv.check_permission(self.lec_tok, "read"))
        self.assertTrue(self.srv.check_permission(self.lec_tok, "write", is_owner=False))
        self.assertTrue(self.srv.check_permission(self.lec_tok, "delete", is_owner=True))
        self.assertFalse(self.srv.check_permission(self.lec_tok, "delete", is_owner=False))

    def test_admin_permissions(self):
        self.assertTrue(self.srv.check_permission(self.adm_tok, "read"))
        self.assertTrue(self.srv.check_permission(self.adm_tok, "write", is_owner=False))
        self.assertTrue(self.srv.check_permission(self.adm_tok, "delete", is_owner=False))

    def test_invalid_token_denied(self):
        self.assertFalse(self.srv.check_permission("not-a-real-token", "read"))


class TestSessions(unittest.TestCase):

    def setUp(self):
        self.orig_ttl = auth_server.SESSION_TTL_SECONDS
        self.orig_idle = auth_server.IDLE_TIMEOUT_SECONDS
        auth_server.SESSION_TTL_SECONDS = 2
        auth_server.IDLE_TIMEOUT_SECONDS = 1

        self.srv = LoginServer(db_path="test_auth.db", fresh=True)
        self.srv.register_user("sam", "SamP@ss123", "student")

    def tearDown(self):
        auth_server.SESSION_TTL_SECONDS = self.orig_ttl
        auth_server.IDLE_TIMEOUT_SECONDS = self.orig_idle
        if os.path.exists("test_auth.db"):
            os.remove("test_auth.db")

    def test_idle_timeout_expires_session(self):
        token = self.srv.login("sam", "SamP@ss123")
        time.sleep(1.5)
        with self.assertRaises(AuthError):
            self.srv.validate_session(token)

    def test_logout_invalidates_session(self):
        token = self.srv.login("sam", "SamP@ss123")
        self.srv.logout(token)
        with self.assertRaises(AuthError):
            self.srv.validate_session(token)


class TestBruteForceLockout(unittest.TestCase):

    def setUp(self):
        self.orig_max = auth_server.MAX_FAILED_ATTEMPTS
        self.orig_lockout = auth_server.LOCKOUT_SECONDS
        auth_server.MAX_FAILED_ATTEMPTS = 3
        auth_server.LOCKOUT_SECONDS = 1

        self.srv = LoginServer(db_path="test_auth.db", fresh=True)
        self.srv.register_user("greg", "GregP@ss123", "student")

    def tearDown(self):
        auth_server.MAX_FAILED_ATTEMPTS = self.orig_max
        auth_server.LOCKOUT_SECONDS = self.orig_lockout
        if os.path.exists("test_auth.db"):
            os.remove("test_auth.db")

    def test_account_locks_after_max_failed_attempts(self):
        for _ in range(3):
            with self.assertRaises(AuthError):
                self.srv.login("greg", "wrong-password")

        # Even the CORRECT password should now be rejected (locked).
        with self.assertRaises(AuthError) as ctx:
            self.srv.login("greg", "GregP@ss123")
        self.assertIn("locked", str(ctx.exception).lower())

    def test_lockout_clears_after_timeout(self):
        for _ in range(3):
            with self.assertRaises(AuthError):
                self.srv.login("greg", "wrong-password")

        time.sleep(1.2)
        token = self.srv.login("greg", "GregP@ss123")
        self.assertIsInstance(token, str)


class TestPasswordStrengthOnRegistration(unittest.TestCase):

    def setUp(self):
        self.srv = LoginServer(db_path="test_auth.db", fresh=True)

    def tearDown(self):
        if os.path.exists("test_auth.db"):
            os.remove("test_auth.db")

    def test_weak_password_rejected(self):
        """Passwords with entropy < 28 bits (e.g. '12345', 'abc') must be rejected."""
        weak_passwords = [
            ("user1", "12345"),
            ("user2", "abc"),
            ("user3", "a1b2"),
            ("user4", "xy"),
        ]
        for username, pwd in weak_passwords:
            with self.subTest(password=pwd):
                with self.assertRaises(AuthError) as ctx:
                    self.srv.register_user(username, pwd, "student")
                self.assertIn("weak", str(ctx.exception).lower())

    def test_medium_password_accepted(self):
        """Medium-strength passwords (e.g. 'Password1') must be accepted."""
        self.srv.register_user("alice", "Password1", "student")
        # register_user returns None; verify by trying to log in
        login_token = self.srv.login("alice", "Password1")
        self.assertIsInstance(login_token, str)

    def test_strong_password_accepted(self):
        """Strong passwords with high entropy must be accepted."""
        self.srv.register_user("bob", "Tr@il-Bl@zer#2026", "admin")
        login_token = self.srv.login("bob", "Tr@il-Bl@zer#2026")
        self.assertIsInstance(login_token, str)

    def test_rejected_password_logged_in_audit(self):
        """A rejected registration due to weak password must be logged in the audit log."""
        try:
            self.srv.register_user("dave", "12345", "student")
        except AuthError:
            pass

        log = db.get_audit_log(self.srv.db_path)
        relevant = [r for r in log if r["action"] == "REGISTER" and r["result"] == "REJECTED"]
        self.assertEqual(len(relevant), 1, "Expected exactly one REJECTED registration event")
        self.assertIn("weak", relevant[0]["detail"].lower())


if __name__ == "__main__":
    unittest.main()
