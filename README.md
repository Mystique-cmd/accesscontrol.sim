# Experiment 13 – Security: Access Control & Authentication (Distributed Systems Lab)

**Aim:** Develop secure distributed authentication.
**Unit:** Distributed Systems (CCS 3103)

## Objective
Build a login server with role-based access control (RBAC), then explore
password security, sessions, brute-force protection, MFA, encrypted
communication, and SQL injection defense through nine activities.

## Roles and Permissions

| Role     | Read | Write        | Delete             |
|----------|------|--------------|---------------------|
| Student  | Yes  | Own files    | No                  |
| Lecturer | Yes  | Yes          | Limited (own only)  |
| Admin    | Yes  | Yes          | Yes                 |

## Folder Contents

```
Experiment13_Security/
├── requirements.txt
├── database.py               # SQLite layer (parameterized/safe queries)
├── auth_server.py            # Core LoginServer: RBAC, sessions, lockout, audit log
├── password_strength.py      # Activity 1
├── hash_comparison.py        # Activity 2
├── session_demo.py           # Activity 3
├── role_escalation_test.py   # Activity 4
├── audit_log_demo.py         # Activity 5
├── mfa_otp.py                 # Activity 6
├── secure_channel.py          # Activity 7
├── sql_injection_demo.py      # Activity 8
├── brute_force_demo.py        # Activity 9
├── tests/
│   └── test_auth_server.py    # 13 unit tests
└── README.md
```

## Requirements

```bash
pip install -r requirements.txt --break-system-packages
```
(`--break-system-packages` is only needed on newer Debian/Ubuntu-based
systems that block global pip installs; omit it if not needed, or use a
virtual environment instead.)

- Python 3.9+
- `bcrypt` (password hashing)
- `cryptography` (Activity 7 encryption)
- Everything else (sqlite3, hashlib, hmac, secrets) is standard library.

---

## How to Run Everything

Run these from inside the `Experiment13_Security` folder:

```bash
# Core system sanity check (optional, see below for a quick manual test)
python3 -c "from auth_server import LoginServer; s = LoginServer(fresh=True); s.register_user('a','Passw0rd!','student'); print(s.login('a','Passw0rd!'))"

python3 password_strength.py       # Activity 1
python3 hash_comparison.py         # Activity 2
python3 session_demo.py            # Activity 3 (~10s, uses short timeouts)
python3 role_escalation_test.py    # Activity 4
python3 audit_log_demo.py          # Activity 5
python3 mfa_otp.py                 # Activity 6
python3 secure_channel.py          # Activity 7
python3 sql_injection_demo.py      # Activity 8
python3 brute_force_demo.py        # Activity 9 (~6s, uses short lockout)

python3 tests/test_auth_server.py -v   # unit tests (~15s due to timing tests)
```

Each activity script is self-contained, resets its own database on
start (`fresh=True` / demo `.db` files), and can be run independently in
any order.

---

## Activity 1: Password Strength Testing

Scores weak/medium/strong passwords using Shannon entropy (`length ×
log2(charset size)`) and estimates brute-force crack time at a
deliberately pessimistic 10 billion guesses/second (modern GPU cluster
against fast, unsalted hashes).

**Result summary:** `12345` cracks instantly; `password` cracks in
seconds; `Password1`/`Sunshine22` (mixed case + digits, medium length)
survive days to about a year; long passwords mixing case, digits, and
symbols (`Tr@il-Bl@zer#2026`) become effectively uncrackable at this
scale. **Takeaway:** length matters more than complexity tricks — a
longer passphrase beats a short "complex-looking" password.

## Activity 2: Password Hash Comparison

Compares plaintext, SHA-256, and bcrypt storage of the same password.

**Findings:**
- Plaintext: a database leak = every password leaked instantly.
- SHA-256: fast (~0.2ms) and **unsalted** — identical passwords always
  produce identical hashes (demonstrated directly in the output), making
  it vulnerable to rainbow tables and fast brute-forcing.
- bcrypt: slow by design (~280ms at cost factor 12) and automatically
  salted — the same password hashed twice produces two different hashes,
  and the cost factor can be raised over time as hardware improves.

## Activity 3: Session Management

Demonstrates both timeout mechanisms built into `LoginServer`:
- **Absolute TTL** — session dies after a fixed lifetime no matter what.
- **Idle timeout** — session dies after a period of inactivity, but is
  extended ("touched") on every use.

Verified: a session idle beyond the idle-timeout window is correctly
rejected, and a session that's kept active still expires once the
absolute TTL is reached.

## Activity 4: Role Escalation Test

13 checks across all three roles, attempting both legitimate actions and
escalation attempts (e.g., a student trying to delete a file, a lecturer
trying to delete someone else's file). All 13 behaved exactly per the
permission matrix — every escalation attempt was correctly denied.

## Activity 5: Audit Logging

Every `REGISTER`, `LOGIN` (success/failure/locked), and
`PERMISSION_CHECK` (allowed/denied) event is written to a SQLite
`audit_log` table with a timestamp, username, action, result, and
detail — giving a full forensic trail of who did what and when.

## Activity 6: Multi-Factor Authentication

Implements TOTP (RFC 6238) from scratch using `hmac`/`hashlib`/`struct`
(no external MFA library), the same mechanism used by apps like Google
Authenticator. Verified: login fails with no OTP, fails with a wrong OTP,
and succeeds only with the current valid 6-digit code (± 1 time step to
tolerate clock drift).

## Activity 7: Secure Communication

Uses the `cryptography` library's `Fernet` (AES + HMAC, authenticated
encryption) to encrypt client→server messages. An eavesdropper on the
"wire" only ever sees ciphertext. Also demonstrates **tamper detection**
(a modified ciphertext is rejected) and that decryption with the wrong
key fails safely rather than returning garbage silently.

*(Fernet is used instead of setting up a full TLS certificate chain — it
demonstrates the same core guarantee, confidentiality + integrity, with
far less setup, while still being a real primitive from the same
`cryptography` package the lab spec allows.)*

## Activity 8: SQL Injection Investigation

Runs the classic `' OR '1'='1` payload against two versions of the same
login query:
- **Vulnerable** (raw f-string query): the injection succeeds — logs in
  as `alice` with no valid password at all.
- **Safe** (parameterized query, `?` placeholders): the same payload is
  treated as a literal string, not SQL syntax — login correctly fails.

Both versions still work correctly for legitimate credentials, showing
that parameterization fixes the vulnerability with no loss of
functionality.

## Activity 9: Brute Force Protection

After `MAX_FAILED_ATTEMPTS` (3) consecutive failed logins, the account
locks for `LOCKOUT_SECONDS`. Verified: the 4th attempt — even with the
**correct** password — is rejected while locked, and login succeeds
again once the lockout window passes.

---

## Discussion Questions

**1. Why shouldn't passwords be stored in plaintext?**
If the database is ever leaked, stolen, or accessed by a malicious
insider, every user's password is immediately exposed in readable form —
and because people frequently reuse passwords across services, that one
leak can compromise accounts on completely unrelated systems too.
Hashing (especially salted, slow hashing like bcrypt) means an attacker
who steals the database still has to do expensive, per-password work to
recover the original password, and salting prevents them from
cracking many accounts at once with a single precomputed table.

**2. How do distributed systems manage authentication?**
Common approaches include: a centralized authentication service (like
the `LoginServer` here) that all nodes trust and delegate to; token-based
schemes (e.g. JWTs or opaque session tokens, as implemented here) that
let a client prove it already authenticated without re-sending
credentials on every request; federated/SSO protocols (OAuth2, SAML,
OpenID Connect) that let multiple independent services trust a single
identity provider; and Kerberos-style ticket systems that use a trusted
third party to issue time-limited tickets for service-to-service auth.
The common thread is avoiding the need for every node to independently
verify raw credentials on every request.

**3. Why are access tokens preferred (over sending credentials
repeatedly)?**
Tokens are short-lived, scoped, and revocable — if one leaks, the damage
is limited to its lifetime and permissions, whereas a leaked password
compromises the account indefinitely until changed. Tokens also mean the
actual password only needs to be transmitted once (at login), reducing
the number of times it's exposed on the network or handled by
downstream services, and they let the server encode extra context (role,
expiry, session ID) directly in what's presented on each request instead
of re-deriving it from a credentials database every time.
