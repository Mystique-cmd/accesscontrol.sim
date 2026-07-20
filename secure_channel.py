"""
Experiment 13 - Activity 7: Secure Communication
--------------------------------------------------------
Encrypts client<->server messages using the `cryptography` library.

We use Fernet (symmetric, authenticated encryption - AES-128 in CBC mode
with an HMAC for integrity) rather than setting up a full TLS certificate
chain, since Fernet demonstrates the same core idea (confidentiality +
tamper detection) with far less setup, while still being a real,
production-grade primitive from the `cryptography` package.

In a real deployment, the shared key here would instead be established
via a TLS handshake (asymmetric key exchange) rather than being
pre-shared, but the *effect* - an eavesdropper on the wire cannot read
the plaintext - is the same.
"""

from cryptography.fernet import Fernet, InvalidToken


class SecureChannel:
    """Simulates an encrypted client<->server communication channel."""

    def __init__(self):
        self.key = Fernet.generate_key()
        self._fernet = Fernet(self.key)

    def client_send(self, plaintext: str) -> bytes:
        return self._fernet.encrypt(plaintext.encode())

    def server_receive(self, ciphertext: bytes) -> str:
        return self._fernet.decrypt(ciphertext).decode()


def main():
    print("=== Activity 7: Secure Communication ===\n")

    channel = SecureChannel()
    print(f"Shared symmetric key (would be exchanged via a TLS handshake "
          f"in a real system): {channel.key.decode()}\n")

    message = "LOGIN alice:AliceP@ss123"
    print(f"Client plaintext message : {message}")

    ciphertext = channel.client_send(message)
    print(f"On-the-wire ciphertext   : {ciphertext}")
    print("(An eavesdropper sniffing the network sees only this - no "
          "username or password is visible.)\n")

    decrypted = channel.server_receive(ciphertext)
    print(f"Server decrypts to       : {decrypted}")
    print(f"Matches original?          {decrypted == message}\n")

    # --- Tamper detection demo ---
    print("-- Tamper detection --")
    tampered = ciphertext[:-2] + b"XX"
    try:
        channel.server_receive(tampered)
        print("Tampered message accepted (unexpected!)")
    except InvalidToken:
        print("Tampered ciphertext correctly rejected (integrity check failed).")

    # --- Wrong key demo ---
    print("\n-- Wrong key demo --")
    other_channel = SecureChannel()  # different random key
    try:
        other_channel.server_receive(ciphertext)
        print("Decrypted with wrong key (unexpected!)")
    except InvalidToken:
        print("Decryption with the wrong key correctly rejected.")


if __name__ == "__main__":
    main()
