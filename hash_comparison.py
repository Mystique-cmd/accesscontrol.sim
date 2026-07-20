"""
Experiment 13 - Activity 2: Password Hash Comparison
------------------------------------------------------
Compares three ways of storing a password:
  1. Plaintext            - never do this
  2. SHA-256 (unsalted)   - fast, deterministic, vulnerable to rainbow
                             tables and brute-force at GPU speed
  3. bcrypt (salted, slow)- purpose-built for password storage; salted
                             per-hash and deliberately slow (tunable
                             "cost factor") to resist brute-forcing
"""

import hashlib
import time
import bcrypt


def store_plaintext(password: str) -> str:
    return password  # NEVER do this in a real system


def store_sha256(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def store_bcrypt(password: str, cost: int = 12) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=cost)).decode()


def verify_sha256(password: str, stored_hash: str) -> bool:
    return hashlib.sha256(password.encode()).hexdigest() == stored_hash


def verify_bcrypt(password: str, stored_hash: str) -> bool:
    return bcrypt.checkpw(password.encode(), stored_hash.encode())


def main():
    print("=== Activity 2: Password Hash Comparison ===\n")

    password = "MySecureP@ssw0rd!"

    print(f"Original password: {password}\n")

    # --- Plaintext ---
    plain = store_plaintext(password)
    print(f"1. Plaintext storage : {plain}")
    print("   Risk: anyone with DB read access (or a leak) instantly has every password.\n")

    # --- SHA-256 ---
    t0 = time.perf_counter()
    sha_hash = store_sha256(password)
    sha_time = time.perf_counter() - t0
    print(f"2. SHA-256 storage   : {sha_hash}")
    print(f"   Hash time: {sha_time * 1000:.4f} ms")
    print("   Risk: unsalted + very fast, so it's practical to brute-force or use "
          "precomputed rainbow tables. Same password always -> same hash, "
          "leaking which accounts share a password.\n")

    # --- bcrypt ---
    t0 = time.perf_counter()
    bcrypt_hash = store_bcrypt(password, cost=12)
    bcrypt_time = time.perf_counter() - t0
    print(f"3. bcrypt storage    : {bcrypt_hash}")
    print(f"   Hash time: {bcrypt_time * 1000:.2f} ms  (cost factor = 12)")
    print("   Notes: automatically salted (salt embedded in the hash string), "
          "and deliberately slow - the cost factor can be increased over time "
          "as hardware gets faster, unlike SHA-256.\n")

    # --- Verification demo ---
    print("--- Verification ---")
    print("SHA-256 verify (correct password):", verify_sha256(password, sha_hash))
    print("SHA-256 verify (wrong password)  :", verify_sha256("wrong", sha_hash))
    print("bcrypt  verify (correct password):", verify_bcrypt(password, bcrypt_hash))
    print("bcrypt  verify (wrong password)  :", verify_bcrypt("wrong", bcrypt_hash))

    # --- Same password, different bcrypt hashes (salting demo) ---
    print("\n--- Salting demo: hashing the SAME password twice with bcrypt ---")
    h1 = store_bcrypt(password)
    h2 = store_bcrypt(password)
    print(f"Hash 1: {h1}")
    print(f"Hash 2: {h2}")
    print(f"Hashes identical? {h1 == h2}  <- always False, because of the random salt")
    print(f"Both still verify correctly? {verify_bcrypt(password, h1) and verify_bcrypt(password, h2)}")

    print(f"\nSame demo with SHA-256 (unsalted): "
          f"{store_sha256(password) == store_sha256(password)}  <- always True, this is the weakness")


if __name__ == "__main__":
    main()
