"""
Experiment 13 - Activity 1: Password Strength Testing
------------------------------------------------------
Tests weak, medium, and strong passwords, scores their strength, and
estimates brute-force resistance (a rough order-of-magnitude "time to
crack" based on character-set size and password length).
"""

import math
import re


def charset_size(password: str) -> int:
    size = 0
    if re.search(r"[a-z]", password):
        size += 26
    if re.search(r"[A-Z]", password):
        size += 26
    if re.search(r"[0-9]", password):
        size += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        size += 32  # rough count of common symbols
    return size or 1


def entropy_bits(password: str) -> float:
    """log2(charset_size ^ length) = length * log2(charset_size)."""
    return len(password) * math.log2(charset_size(password))


def classify_strength(bits: float) -> str:
    if bits < 28:
        return "WEAK"
    if bits < 60:
        return "MEDIUM"
    return "STRONG"


def estimate_crack_time(bits: float, guesses_per_second: float = 1e10) -> str:
    """
    Very rough estimate assuming an offline brute-force attack at
    `guesses_per_second` (1e10/s ~ a modern GPU cluster cracking
    fast, unsalted hashes - deliberately pessimistic to make the point
    that weak passwords fall in seconds even to strong hardware).
    """
    total_guesses = 2 ** bits
    seconds = total_guesses / guesses_per_second / 2  # average case = half the space
    if seconds < 1:
        return "< 1 second"
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    if seconds < 3600:
        return f"{seconds / 60:.1f} minutes"
    if seconds < 86400:
        return f"{seconds / 3600:.1f} hours"
    if seconds < 31_536_000:
        return f"{seconds / 86400:.1f} days"
    years = seconds / 31_536_000
    if years > 1e9:
        return f"{years:.2e} years (effectively uncrackable)"
    return f"{years:.1f} years"


def analyze(password: str) -> dict:
    bits = entropy_bits(password)
    return {
        "password": password,
        "length": len(password),
        "charset_size": charset_size(password),
        "entropy_bits": round(bits, 1),
        "strength": classify_strength(bits),
        "estimated_crack_time": estimate_crack_time(bits),
    }


def main():
    print("=== Activity 1: Password Strength Testing ===\n")

    test_passwords = [
        ("weak", "12345"),
        ("weak", "password"),
        ("medium", "Password1"),
        ("medium", "Sunshine22"),
        ("strong", "Tr@il-Bl@zer#2026"),
        ("strong", "xK9!vQ2#mZ7$pL4@"),
    ]

    print(f"{'Label':<8}{'Password':<20}{'Length':<8}{'Entropy(bits)':<15}{'Strength':<10}{'Est. Crack Time'}")
    print("-" * 90)
    for label, pwd in test_passwords:
        r = analyze(pwd)
        print(f"{label:<8}{r['password']:<20}{r['length']:<8}{r['entropy_bits']:<15}"
              f"{r['strength']:<10}{r['estimated_crack_time']}")


if __name__ == "__main__":
    main()
