"""
Experiment 13 - Activity 4: Role Escalation Test
----------------------------------------------------
Attempts unauthorized operations using different roles and verifies that
access is correctly denied per the permission matrix:

    Role       Read   Write        Delete
    Student    Yes    Own files    No
    Lecturer   Yes    Yes          Limited (own files only)
    Admin      Yes    Yes          Yes
"""

from auth_server import LoginServer


def attempt(label, srv, token, action, is_owner, expected):
    result = srv.check_permission(token, action, is_owner=is_owner)
    status = "PASS" if result == expected else "FAIL"
    verdict = "ALLOWED" if result else "DENIED"
    print(f"[{status}] {label:<45} -> {verdict} (expected {'ALLOWED' if expected else 'DENIED'})")
    return status == "PASS"


def main():
    print("=== Activity 4: Role Escalation Test ===\n")

    srv = LoginServer(fresh=True)
    srv.register_user("stu1", "StudentP@ss1", "student")
    srv.register_user("lec1", "LecturerP@ss1", "lecturer")
    srv.register_user("adm1", "AdminP@ss1", "admin")

    stu_tok = srv.login("stu1", "StudentP@ss1")
    lec_tok = srv.login("lec1", "LecturerP@ss1")
    adm_tok = srv.login("adm1", "AdminP@ss1")

    results = []

    print("-- Student attempts --")
    results.append(attempt("Student reads any file", srv, stu_tok, "read", False, True))
    results.append(attempt("Student writes OWN file", srv, stu_tok, "write", True, True))
    results.append(attempt("Student writes ANOTHER user's file (escalation!)",
                            srv, stu_tok, "write", False, False))
    results.append(attempt("Student deletes OWN file (escalation!)",
                            srv, stu_tok, "delete", True, False))
    results.append(attempt("Student deletes another user's file (escalation!)",
                            srv, stu_tok, "delete", False, False))

    print("\n-- Lecturer attempts --")
    results.append(attempt("Lecturer reads any file", srv, lec_tok, "read", False, True))
    results.append(attempt("Lecturer writes any file", srv, lec_tok, "write", False, True))
    results.append(attempt("Lecturer deletes OWN file", srv, lec_tok, "delete", True, True))
    results.append(attempt("Lecturer deletes ANOTHER user's file (escalation!)",
                            srv, lec_tok, "delete", False, False))

    print("\n-- Admin attempts --")
    results.append(attempt("Admin reads any file", srv, adm_tok, "read", False, True))
    results.append(attempt("Admin writes any file", srv, adm_tok, "write", False, True))
    results.append(attempt("Admin deletes any file", srv, adm_tok, "delete", False, True))

    print("\n-- Invalid / expired token attempt --")
    results.append(attempt("Forged/garbage token reads a file",
                            srv, "not-a-real-token", "read", False, False))

    passed = sum(results)
    print(f"\n{passed}/{len(results)} checks behaved as expected.")


if __name__ == "__main__":
    main()
