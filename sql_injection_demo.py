"""
Experiment 13 - Activity 8: SQL Injection Investigation
--------------------------------------------------------------
Demonstrates a classic SQL injection vulnerability in a login query
built with raw string formatting, then shows how the SAME query, when
parameterized, safely neutralizes the attack.

WARNING: the "vulnerable" function below is intentionally unsafe and is
only ever run against a local, disposable SQLite demo database in this
script - never do this in a real system.
"""

import sqlite3

DEMO_DB = "sqli_demo.db"


def setup_demo_db(db_path: str = DEMO_DB):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS accounts")
    cur.execute("""
        CREATE TABLE accounts (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    """)
    cur.executemany(
        "INSERT INTO accounts (username, password, role) VALUES (?, ?, ?)",
        [
            ("alice", "AliceP@ss123", "student"),
            ("admin", "SuperSecretAdminPW", "admin"),
        ],
    )
    conn.commit()
    conn.close()


# ---------- VULNERABLE version (string formatting) ----------

def vulnerable_login(username: str, password: str, db_path: str = DEMO_DB):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    # DANGEROUS: user input is spliced directly into the SQL string.
    query = f"SELECT * FROM accounts WHERE username = '{username}' AND password = '{password}'"
    print(f"  [vulnerable] Executing: {query}")

    cur.execute(query)
    row = cur.fetchone()
    conn.close()
    return row


# ---------- SAFE version (parameterized query) ----------

def safe_login(username: str, password: str, db_path: str = DEMO_DB):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    query = "SELECT * FROM accounts WHERE username = ? AND password = ?"
    print(f"  [safe] Executing: {query}  with params={(username, password)}")

    cur.execute(query, (username, password))
    row = cur.fetchone()
    conn.close()
    return row


def main():
    print("=== Activity 8: SQL Injection Investigation ===\n")
    setup_demo_db()

    injection_payload_user = "' OR '1'='1"
    injection_payload_pass = "' OR '1'='1"

    print("-- Attack attempt against the VULNERABLE query --")
    print(f"Attacker input -> username: {injection_payload_user!r}, password: {injection_payload_pass!r}")
    result = vulnerable_login(injection_payload_user, injection_payload_pass)
    if result:
        print(f"  RESULT: Logged in as {result[0]} (role={result[2]}) "
              f"WITHOUT knowing any real password! Injection succeeded.\n")
    else:
        print("  RESULT: No match returned.\n")

    print("-- Same attack attempt against the SAFE (parameterized) query --")
    result = safe_login(injection_payload_user, injection_payload_pass)
    if result:
        print(f"  RESULT: Logged in as {result[0]} (unexpected - injection worked!)\n")
    else:
        print("  RESULT: No match returned - injection correctly neutralized. "
              "The whole payload was treated as a literal username string, "
              "not as SQL syntax.\n")

    print("-- Sanity check: legitimate login still works on both --")
    print("Vulnerable version, correct creds:", vulnerable_login("alice", "AliceP@ss123"))
    print("Safe version, correct creds       :", safe_login("alice", "AliceP@ss123"))


if __name__ == "__main__":
    main()
