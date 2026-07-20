"""
Experiment 13 - Activity 3: Session Management
------------------------------------------------
Demonstrates the two timeout mechanisms already built into
LoginServer (auth_server.py):
  - Absolute session TTL   (SESSION_TTL_SECONDS)
  - Idle timeout / auto-logout (IDLE_TIMEOUT_SECONDS)

To keep the demo fast, we temporarily patch very short timeouts instead
of waiting for the real 5-minute / 60-second defaults.
"""

import time
import auth_server
from auth_server import LoginServer, AuthError


def main():
    print("=== Activity 3: Session Management (token expiry + idle timeout) ===\n")

    # Use short timeouts just for this demo so it runs in a few seconds.
    auth_server.SESSION_TTL_SECONDS = 6
    auth_server.IDLE_TIMEOUT_SECONDS = 3

    srv = LoginServer(fresh=True)
    srv.register_user("dana", "DanaPass#123", "student")

    token = srv.login("dana", "DanaPass#123")
    print(f"Logged in. Token: {token[:8]}...  "
          f"(TTL={auth_server.SESSION_TTL_SECONDS}s, idle timeout={auth_server.IDLE_TIMEOUT_SECONDS}s)")

    print("\n-- Scenario 1: idle timeout --")
    print("Waiting 4s without activity (idle timeout is 3s)...")
    time.sleep(4)
    try:
        srv.validate_session(token)
        print("Session still valid (unexpected)")
    except AuthError as e:
        print(f"Session rejected as expected: {e}")

    print("\n-- Scenario 2: absolute TTL, even with activity --")
    token2 = srv.login("dana", "DanaPass#123")
    print(f"New login. Token: {token2[:8]}...")
    for i in range(4):
        time.sleep(2)  # each sleep < idle timeout, so idle timeout won't trigger
        try:
            srv.validate_session(token2)
            print(f"  t+{(i + 1) * 2}s: session still valid (touched, resets idle clock)")
        except AuthError as e:
            print(f"  t+{(i + 1) * 2}s: session rejected: {e}")
            break


if __name__ == "__main__":
    main()
