"""
Experiment 13 - Core Login Server
--------------------------------------
Implements:
  - User registration with bcrypt password hashing
  - Login with role-based access control (RBAC)
  - Session tokens with absolute expiry + idle timeout (auto-logout)
  - Account lockout after repeated failed logins (brute-force protection)
  - Audit logging of every login attempt / permission check
  - Optional MFA (OTP) hook used by mfa_otp.py

Roles and permissions (from the lab spec):

    Role       Read   Write        Delete
    Student    Yes    Own files    No
    Lecturer   Yes    Yes          Limited (own files only)
    Admin      Yes    Yes          Yes
"""

import secrets
import time
import bcrypt

import database as db
import password_strength as pw_strength

# ---------- Permission matrix ----------
# 'all'  -> always allowed
# 'own'  -> allowed only if the resource belongs to the requesting user
# 'none' -> never allowed
PERMISSIONS = {
    "student":  {"read": "all", "write": "own",  "delete": "none"},
    "lecturer": {"read": "all", "write": "all",  "delete": "own"},
    "admin":    {"read": "all", "write": "all",  "delete": "all"},
}

SESSION_TTL_SECONDS = 300      # absolute session lifetime (5 minutes)
IDLE_TIMEOUT_SECONDS = 60      # auto-logout after this long with no activity
MAX_FAILED_ATTEMPTS = 3
LOCKOUT_SECONDS = 30


class AuthError(Exception):
    pass


class LoginServer:
    def __init__(self, db_path: str = db.DB_PATH, fresh: bool = False):
        self.db_path = db_path
        if fresh:
            db.reset_db(db_path)
        else:
            db.init_db(db_path)
        # in-memory session store: token -> {username, role, issued_at, last_activity}
        self.sessions = {}

    # ---------- Registration ----------

    def register_user(self, username: str, password: str, role: str, mfa_secret: str = None):
        if role not in PERMISSIONS:
            raise AuthError(f"Unknown role: {role}")
        if db.get_user(username, self.db_path) is not None:
            raise AuthError(f"User '{username}' already exists")

        # Password strength check — reject weak passwords
        analysis = pw_strength.analyze(password)
        if analysis["strength"] == "WEAK":
            db.log_event(username, "REGISTER", "REJECTED",
                         f"password too weak (entropy={analysis['entropy_bits']} bits, "
                         f"crack_time={analysis['estimated_crack_time']})",
                         self.db_path)
            raise AuthError(
                f"Password too weak. "
                f"Entropy: {analysis['entropy_bits']} bits, "
                f"estimated crack time: {analysis['estimated_crack_time']}. "
                f"Use a longer password with mixed case, digits, and symbols."
            )

        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        db.insert_user(username, pw_hash, "bcrypt", role, mfa_secret, self.db_path)
        db.log_event(username, "REGISTER", "SUCCESS", f"role={role}", self.db_path)

    # ---------- Login / lockout ----------

    def _is_locked(self, user_row) -> bool:
        locked_until = user_row["locked_until"]
        return locked_until is not None and time.time() < locked_until

    def login(self, username: str, password: str, otp: str = None, verify_otp_fn=None) -> str:
        """
        Attempt to authenticate. Returns a session token on success, raises
        AuthError on failure. `verify_otp_fn(mfa_secret, otp) -> bool` is an
        optional callback used when MFA is enabled for the account
        (see mfa_otp.py for a concrete implementation).
        """
        user = db.get_user(username, self.db_path)

        if user is None:
            db.log_event(username, "LOGIN", "FAILURE", "no such user", self.db_path)
            raise AuthError("Invalid username or password")

        if self._is_locked(user):
            remaining = int(user["locked_until"] - time.time())
            db.log_event(username, "LOGIN", "LOCKED", f"{remaining}s remaining", self.db_path)
            raise AuthError(f"Account locked. Try again in {remaining}s")

        password_ok = bcrypt.checkpw(password.encode(), user["password_hash"].encode())

        if not password_ok:
            self._register_failed_attempt(user)
            db.log_event(username, "LOGIN", "FAILURE", "bad password", self.db_path)
            raise AuthError("Invalid username or password")

        if user["mfa_secret"]:
            if verify_otp_fn is None or otp is None or not verify_otp_fn(user["mfa_secret"], otp):
                db.log_event(username, "LOGIN", "FAILURE", "bad/missing OTP", self.db_path)
                raise AuthError("Invalid or missing one-time password")

        # success: reset failed attempts, issue session token
        db.update_failed_attempts(username, 0, None, self.db_path)
        token = self._issue_session(username, user["role"])
        db.log_event(username, "LOGIN", "SUCCESS", f"role={user['role']}", self.db_path)
        return token

    def _register_failed_attempt(self, user_row):
        attempts = user_row["failed_attempts"] + 1
        locked_until = None
        if attempts >= MAX_FAILED_ATTEMPTS:
            locked_until = time.time() + LOCKOUT_SECONDS
        db.update_failed_attempts(user_row["username"], attempts, locked_until, self.db_path)

    # ---------- Sessions ----------

    def _issue_session(self, username: str, role: str) -> str:
        token = secrets.token_hex(16)
        now = time.time()
        self.sessions[token] = {
            "username": username,
            "role": role,
            "issued_at": now,
            "last_activity": now,
        }
        return token

    def _touch_session(self, token: str):
        self.sessions[token]["last_activity"] = time.time()

    def validate_session(self, token: str) -> dict:
        """Return the session dict if valid, else raise AuthError."""
        session = self.sessions.get(token)
        if session is None:
            raise AuthError("Invalid session token")

        now = time.time()
        if now - session["issued_at"] > SESSION_TTL_SECONDS:
            del self.sessions[token]
            raise AuthError("Session expired (absolute TTL exceeded)")
        if now - session["last_activity"] > IDLE_TIMEOUT_SECONDS:
            del self.sessions[token]
            raise AuthError("Session expired (idle timeout)")

        self._touch_session(token)
        return session

    def logout(self, token: str):
        self.sessions.pop(token, None)

    # ---------- RBAC ----------

    def check_permission(self, token: str, action: str, is_owner: bool = False) -> bool:
        """
        Returns True/False rather than raising, so callers (e.g. the
        role-escalation test) can easily assert on denial without a
        try/except for every check.
        """
        try:
            session = self.validate_session(token)
        except AuthError:
            return False

        role = session["role"]
        level = PERMISSIONS.get(role, {}).get(action, "none")

        allowed = (
            level == "all"
            or (level == "own" and is_owner)
        )

        db.log_event(
            session["username"], f"PERMISSION_CHECK:{action}",
            "ALLOWED" if allowed else "DENIED",
            f"role={role}, is_owner={is_owner}", self.db_path,
        )
        return allowed
