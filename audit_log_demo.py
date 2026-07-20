"""
Experiment 13 - Activity 5: Audit Logging
-----------------------------------------------
Every login attempt (success, failure, locked) and every permission
check performed by LoginServer is already recorded to the audit_log
table (see database.py / auth_server.py). This script generates some
activity, then displays the resulting audit trail.
"""

import database as db
from auth_server import LoginServer, AuthError


def print_audit_log(db_path=db.DB_PATH):
    rows = db.get_audit_log(db_path)
    print(f"{'Time':<10}{'User':<10}{'Action':<24}{'Result':<10}{'Detail'}")
    print("-" * 80)
    for r in rows:
        ts = f"{r['timestamp']:.2f}"
        print(f"{ts:<12}{(r['username'] or '-'):<10}{r['action']:<24}{r['result']:<10}{r['detail'] or ''}")


def main():
    print("=== Activity 5: Audit Logging ===\n")

    srv = LoginServer(fresh=True)
    srv.register_user("erin", "ErinP@ss1234", "lecturer")

    # A mix of successful and failed events to populate the log
    tok = srv.login("erin", "ErinP@ss1234")            # SUCCESS
    srv.check_permission(tok, "read")                   # ALLOWED
    srv.check_permission(tok, "delete", is_owner=False)  # lecturer can delete only own -> DENIED

    try:
        srv.login("erin", "wrong-password")              # FAILURE
    except AuthError:
        pass

    try:
        srv.login("ghost", "whatever")                    # FAILURE (no such user)
    except AuthError:
        pass

    print("Audit trail:\n")
    print_audit_log()


if __name__ == "__main__":
    main()
