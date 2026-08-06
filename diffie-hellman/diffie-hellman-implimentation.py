import random
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def toy_diffie_hellman_demo():
    print("=" * 65)
    print("1. TOY DIFFIE-HELLMAN DEMONSTRATION (Small Numbers)")
    print("=" * 65)

    # 1. Public parameters
    p = 23  # A prime number
    g = 5   # A primitive root modulo 23
    print(f"Publicly shared prime (p): {p}")
    print(f"Publicly shared generator (g): {g}\n")

    # 2. Private secrets chosen independently
    a = random.randint(1, 15)  # Alice's private key
    b = random.randint(1, 15)  # Bob's private key
    print(f"[Alice] Private key (a): {a}")
    print(f"[Bob]   Private key (b): {b}\n")

    # 3. Compute public values
    A = (g ** a) % p  # Alice's public key
    B = (g ** b) % p  # Bob's public key
    print(f"[Alice] Calculates public key A = (g^a mod p): {A}")
    print(f"[Bob]   Calculates public key B = (g^b mod p): {B}")
    print("--> Public keys A and B are sent across the insecure network.\n")

    # 4. Shared secret calculation
    s_alice = (B ** a) % p
    s_bob = (A ** b) % p

    print(f"[Alice] Computes Shared Secret (B^a mod p): {s_alice}")
    print(f"[Bob]   Computes Shared Secret (A^b mod p): {s_bob}")

    assert s_alice == s_bob, "Keys do not match!"
    print("\nSUCCESS: Both parties derived the exact same shared secret!")
    print("=" * 65 + "\n")


def production_diffie_hellman_demo():
    print("=" * 65)
    print("2. PRODUCTION-GRADE DIFFIE-HELLMAN (2048-bit Prime)")
    print("=" * 65)

    # 1. Generate DH parameters (Shared globally)
    parameters = dh.generate_parameters(generator=2, key_size=2048)

    # 2. Alice generates her private and public keys
    alice_private_key = parameters.generate_private_key()
    alice_public_key = alice_private_key.public_key()

    # 3. Bob generates his private and public keys
    bob_private_key = parameters.generate_private_key()
    bob_public_key = bob_private_key.public_key()

    # 4. Exchange public keys and derive raw shared secret
    alice_raw_shared_key = alice_private_key.exchange(bob_public_key)
    bob_raw_shared_key = bob_private_key.exchange(alice_public_key)

    # 5. Pass raw secret through HKDF to derive a standard 256-bit AES key
    alice_aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(alice_raw_shared_key)

    bob_aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(bob_raw_shared_key)

    print(f"Alice's derived AES Key (Hex): {alice_aes_key.hex()}")
    print(f"Bob's   derived AES Key (Hex): {bob_aes_key.hex()}")

    assert alice_aes_key == bob_aes_key, "Derived symmetric keys do not match!"
    print("\nSUCCESS: Industrial-strength 256-bit key successfully negotiated.")
    print("=" * 65)


if __name__ == "__main__":
    toy_diffie_hellman_demo()
    production_diffie_hellman_demo()