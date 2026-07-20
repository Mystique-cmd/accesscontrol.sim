"""
Experiment 13 - Activity 6: Multi-Factor Authentication (TOTP)
--------------------------------------------------------------------
A minimal, dependency-free implementation of Time-based One-Time
Passwords (TOTP, RFC 6238) - the same mechanism apps like Google
Authenticator use. Built from scratch with hashlib/hmac/struct so the
mechanics are visible, instead of hiding it behind a library.
"""

import base64
import hashlib
import hmac
import struct
import time
import secrets

from auth_server import LoginServer, AuthError


def generate_secret() -> str:
    """Base32 secret, the standard encoding used by authenticator apps."""
    return base64.b32encode(secrets.token_bytes(10)).decode()


def _hotp(secret_b32: str, counter: int, digits: int = 6) -> str:
    key = base64.b32decode(secret_b32.upper())
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code_int = (struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code_int).zfill(digits)


def totp_now(secret_b32: str, step: int = 30, digits: int = 6) -> str:
    counter = int(time.time() // step)
    return _hotp(secret_b32, counter, digits)


def verify_totp(secret_b32: str, code: str, step: int = 30, digits: int = 6, window: int = 1) -> bool:
    """Accept the code if it matches the current step or one step to
    either side, to tolerate small clock drift between client/server."""
    counter = int(time.time() // step)
    for offset in range(-window, window + 1):
        if _hotp(secret_b32, counter + offset, digits) == code:
            return True
    return False


def main():
    print("=== Activity 6: Multi-Factor Authentication (TOTP) ===\n")

    srv = LoginServer(fresh=True)
    secret = generate_secret()
    srv.register_user("frank", "FrankP@ss123", "admin", mfa_secret=secret)
    print(f"Registered 'frank' with MFA secret: {secret}")
    print("(In a real system this secret is shown once as a QR code for "
          "the user's authenticator app.)\n")

    # --- Attempt login WITHOUT an OTP ---
    print("-- Attempt 1: login without OTP --")
    try:
        srv.login("frank", "FrankP@ss123", otp=None, verify_otp_fn=verify_totp)
        print("Logged in (unexpected!)")
    except AuthError as e:
        print(f"Correctly rejected: {e}")

    # --- Attempt with WRONG OTP ---
    print("\n-- Attempt 2: login with WRONG OTP --")
    try:
        srv.login("frank", "FrankP@ss123", otp="000000", verify_otp_fn=verify_totp)
        print("Logged in (unexpected!)")
    except AuthError as e:
        print(f"Correctly rejected: {e}")

    # --- Attempt with CORRECT OTP ---
    print("\n-- Attempt 3: login with CORRECT OTP --")
    code = totp_now(secret)
    print(f"Current valid OTP: {code}")
    token = srv.login("frank", "FrankP@ss123", otp=code, verify_otp_fn=verify_totp)
    print(f"Logged in successfully. Token: {token[:8]}...")


if __name__ == "__main__":
    main()
