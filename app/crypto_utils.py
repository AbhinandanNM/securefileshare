import hashlib
import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad

# Fixed salt for Master Key Derivation (PBKDF2-HMAC-SHA256)
KDF_SALT = b"CNS_SECURE_CLOUD_KEK_SALT_v1"
PBKDF2_ITERATIONS = 100_000


def derive_master_key(secret_key: str) -> bytes:
    """
    Derive 256-bit Key Encryption Key (KEK) using PBKDF2-HMAC-SHA256
    with 100,000 iterations and cryptographic salt.
    """
    return hashlib.pbkdf2_hmac('sha256', secret_key.encode('utf-8'), KDF_SALT, PBKDF2_ITERATIONS, dklen=32)


def compute_hash(data: bytes) -> str:
    """Return SHA-256 hex digest of data."""
    return hashlib.sha256(data).hexdigest()


def verify_hash(data: bytes, expected_hash: str) -> bool:
    """Return True if SHA-256 of data matches expected_hash."""
    return compute_hash(data) == expected_hash


def encrypt_file(plaintext: bytes, master_key: bytes) -> dict:
    """
    Two-Tier Key Hierarchy:
    1. Generate cryptographically strong random per-file DEK (Data Encryption Key, 256-bit)
       and 128-bit Initialisation Vector (IV).
    2. Encrypt plaintext with AES-256 in CBC mode with PKCS#7 padding.
    3. Wrap (encrypt) the DEK using the Master KEK (Key Encryption Key) using AES-256-ECB.

    Returns dict:
        ciphertext        – encrypted file content (bytes)
        ciphertext_hash   – SHA-256 digest of the ciphertext (str)
        encrypted_key     – wrapped DEK (bytes)
        iv                – 16-byte IV (bytes)
        dek_preview       – first 4 bytes hex preview of DEK for educational inspector
    """
    dek = os.urandom(32)  # 256-bit Data Encryption Key
    iv = os.urandom(16)   # 128-bit IV

    # AES-256-CBC encryption of payload
    cipher_cbc = AES.new(dek, AES.MODE_CBC, iv)
    ciphertext = cipher_cbc.encrypt(pad(plaintext, AES.block_size))

    # Wrap DEK using Master KEK
    cipher_ecb = AES.new(master_key, AES.MODE_ECB)
    encrypted_key = cipher_ecb.encrypt(pad(dek, AES.block_size))

    return {
        'ciphertext': ciphertext,
        'ciphertext_hash': compute_hash(ciphertext),
        'encrypted_key': encrypted_key,
        'iv': iv,
        'dek_preview': dek[:4].hex() + '...',
    }


def decrypt_file(
    ciphertext: bytes,
    encrypted_key: bytes,
    iv: bytes,
    master_key: bytes,
) -> bytes:
    """
    1. Unwrap DEK using Master KEK.
    2. Decrypt ciphertext with AES-256-CBC using recovered DEK and IV.
    3. Unpad PKCS#7.
    """
    # Unwrap DEK
    cipher_ecb = AES.new(master_key, AES.MODE_ECB)
    dek = unpad(cipher_ecb.decrypt(encrypted_key), AES.block_size)

    # Decrypt payload
    cipher_cbc = AES.new(dek, AES.MODE_CBC, iv)
    plaintext = unpad(cipher_cbc.decrypt(ciphertext), AES.block_size)
    return plaintext


def format_hex_dump(data: bytes, max_bytes: int = 128) -> str:
    """Generate a clean Wireshark/xxd style hex dump for student/professor inspection."""
    slice_data = data[:max_bytes]
    lines = []
    for i in range(0, len(slice_data), 16):
        chunk = slice_data[i:i+16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{i:04x}   {hex_part:<48}   |{ascii_part}|")
    if len(data) > max_bytes:
        lines.append(f"... ({len(data) - max_bytes} more encrypted bytes)")
    return "\n".join(lines)
