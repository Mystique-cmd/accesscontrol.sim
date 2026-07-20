"""
Experiment 13 - Database Layer
------------------------------------
Thin SQLite wrapper for the authentication system. All queries here use
parameterized statements (safe from SQL injection) - the deliberately
UNSAFE version used for the Activity 8 demonstration lives separately in
sql_injection_demo.py so it's obvious which code is vulnerable on purpose.
"""

import sqlite3
import time
from contextlib import contextmanager

DB_PATH = "auth_system.db"


def get_connection(db_path: str = DB_PATH):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def db_cursor(db_path: str = DB_PATH):
    conn = get_connection(db_path)
    try:
        yield conn.cursor()
        conn.commit()
    finally:
        conn.close()


def init_db(db_path: str = DB_PATH):
    with db_cursor(db_path) as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                hash_scheme TEXT NOT NULL,
                role TEXT NOT NULL,
                mfa_secret TEXT,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until REAL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                username TEXT,
                action TEXT NOT NULL,
                result TEXT NOT NULL,
                detail TEXT
            )
        """)


def reset_db(db_path: str = DB_PATH):
    """Wipe and recreate all tables - handy for repeatable demo runs."""
    with db_cursor(db_path) as cur:
        cur.execute("DROP TABLE IF EXISTS users")
        cur.execute("DROP TABLE IF EXISTS audit_log")
    init_db(db_path)


# ---------- Safe (parameterized) user queries ----------

def insert_user(username, password_hash, hash_scheme, role, mfa_secret=None, db_path: str = DB_PATH):
    with db_cursor(db_path) as cur:
        cur.execute(
            "INSERT INTO users (username, password_hash, hash_scheme, role, mfa_secret, "
            "failed_attempts, locked_until) VALUES (?, ?, ?, ?, ?, 0, NULL)",
            (username, password_hash, hash_scheme, role, mfa_secret),
        )


def get_user(username, db_path: str = DB_PATH):
    """SAFE lookup - parameterized, immune to SQL injection."""
    with db_cursor(db_path) as cur:
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        return cur.fetchone()


def update_failed_attempts(username, attempts, locked_until, db_path: str = DB_PATH):
    with db_cursor(db_path) as cur:
        cur.execute(
            "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE username = ?",
            (attempts, locked_until, username),
        )


def log_event(username, action, result, detail="", db_path: str = DB_PATH):
    with db_cursor(db_path) as cur:
        cur.execute(
            "INSERT INTO audit_log (timestamp, username, action, result, detail) "
            "VALUES (?, ?, ?, ?, ?)",
            (time.time(), username, action, result, detail),
        )


def get_audit_log(db_path: str = DB_PATH):
    with db_cursor(db_path) as cur:
        cur.execute("SELECT * FROM audit_log ORDER BY id ASC")
        return cur.fetchall()
