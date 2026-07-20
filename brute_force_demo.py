"""
Experiment 13 - Activity 9: Brute Force Protection
--------------------------------------------------------
Demonstrates the account-lockout mechanism already built into
LoginServer: after MAX_FAILED_ATTEMPTS consecutive failed logins, the
account is locked for LOCKOUT_SECONDS, blocking further attempts (even
with the correct password) until the lockout expires.
"""

import time
import auth_server
from auth_server import LoginServer, AuthError


def main():
    print("=== Activity 9: Brute Force Protection ===\n")

    # Shorten the lockout window just for this demo.
    auth_server.MAX_FAILED_ATTEMPTS = 3
    auth_server.LOCKOUT_SECONDS = 5

    srv = LoginServer(fresh=True)
    srv.register_user("greg", "GregRealP@ss1", "student")

    print(f"Policy: lock account after {auth_server.MAX_FAILED_ATTEMPTS} failed attempts, "
          f"for {auth_server.LOCKOUT_SECONDS}s.\n")

    guesses = ["wrong1", "wrong2", "wrong3", "GregRealP@ss1"]  # last one is correct!
    for i, guess in enumerate(guesses, start=1):
        try:
            token = srv.login("greg", guess)
            print(f"Attempt {i} ('{guess}'): SUCCESS, token={token[:8]}...")
        except AuthError as e:
            print(f"Attempt {i} ('{guess}'): FAILED - {e}")

    print("\n-- Even the correct password is now rejected until the lockout expires --")
    print(f"Waiting {auth_server.LOCKOUT_SECONDS}s for the lockout to clear...")
    time.sleep(auth_server.LOCKOUT_SECONDS + 0.5)

    try:
        token = srv.login("greg", "GregRealP@ss1")
        print(f"Post-lockout attempt: SUCCESS, token={token[:8]}...")
    except AuthError as e:
        print(f"Post-lockout attempt: FAILED - {e}")


if __name__ == "__main__":
    main()
