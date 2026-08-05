import hashlib
import os

def display_hash_demonstration(password: str):
    print("=" * 60)
    print(f"INPUT PASSWORD: '{password}'")
    print("=" * 60)

    # 1. MD5 Demonstration
    md5_hash = hashlib.md5(password.encode('utf-8')).hexdigest()
    print(f"MD5    (Length: {len(md5_hash)} chars / {len(md5_hash)*4} bits): {md5_hash}")

    # 2. SHA-1 Demonstration
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest()
    print(f"SHA-1  (Length: {len(sha1_hash)} chars / {len(sha1_hash)*4} bits): {sha1_hash}")

    # 3. SHA-256 Demonstration
    sha256_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
    print(f"SHA-256(Length: {len(sha256_hash)} chars / {len(sha256_hash)*4} bits): {sha256_hash}")
    print()

def demonstrate_avalanche_effect():
    print("=" * 60)
    print("DEMONSTRATING THE AVALANCHE EFFECT")
    print("=" * 60)
    
    pass1 = "Password123"
    pass2 = "password123"  # Single character case change ('P' -> 'p')

    hash1 = hashlib.sha256(pass1.encode('utf-8')).hexdigest()
    hash2 = hashlib.sha256(pass2.encode('utf-8')).hexdigest()

    print(f"Original String: '{pass1}'")
    print(f"SHA-256 Hash:    {hash1}\n")
    
    print(f"Modified String: '{pass2}'")
    print(f"SHA-256 Hash:    {hash2}\n")
    
    # Calculate how many characters changed
    diff_count = sum(1 for a, b in zip(hash1, hash2) if a != b)
    print(f"Result: Changing 1 character altered {diff_count} out of 64 hexadecimal characters.")
    print()

def demonstrate_salting():
    print("=" * 60)
    print("DEMONSTRATING PASSWORD SALTING")
    print("=" * 60)
    
    password = "MySecretPassword!"

    # Generating random 16-byte salts for two separate users with identical passwords
    salt_user1 = os.urandom(16)
    salt_user2 = os.urandom(16)

    # Hashing password + salt using PBKDF2 (SHA-256)
    hash_user1 = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt_user1, 100000)
    hash_user2 = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt_user2, 100000)

    print(f"User 1 Password: '{password}'")
    print(f"User 1 Salt:     {salt_user1.hex()}")
    print(f"User 1 Stored Hash: {hash_user1.hex()}\n")

    print(f"User 2 Password: '{password}'")
    print(f"User 2 Salt:     {salt_user2.hex()}")
    print(f"User 2 Stored Hash: {hash_user2.hex()}")
    print("\nNotice: Identical passwords result in totally different stored hashes due to unique salts.")

if __name__ == "__main__":
    # Task 1: Hash generation across MD5, SHA-1, SHA-256
    display_hash_demonstration("ComputerSecurity2026")
    
    # Task 2: Avalanche Effect Demonstration
    demonstrate_avalanche_effect()
    
    # Task 3: Salting Demonstration
    demonstrate_salting()