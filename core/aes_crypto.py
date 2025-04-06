from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import os

BLOCK_SIZE = AES.block_size  # 16 bytes


def pad(data: bytes) -> bytes:
    pad_len = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([pad_len]) * pad_len

def unpad(data: bytes) -> bytes:
    return data[:-data[-1]]


def generate_key(password: str = None, key_size: int = 32):
    """
    Generate an AES key (128 or 256 bits).
    If password is given, derive key using PBKDF2.
    """
    if password:
        salt = get_random_bytes(16)
        key = PBKDF2(password, salt, dkLen=key_size)
        return key, salt
    else:
        key = get_random_bytes(key_size)
        return key, None


def encrypt_file(input_file: str, output_file: str, key: bytes):
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    with open(input_file, 'rb') as f:
        data = f.read()

    padded_data = pad(data)
    ciphertext = cipher.encrypt(padded_data)

    with open(output_file, 'wb') as f:
        f.write(iv + ciphertext)


def decrypt_file(input_file: str, output_file: str, key: bytes):
    with open(input_file, 'rb') as f:
        iv = f.read(BLOCK_SIZE)
        ciphertext = f.read()

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext))

    with open(output_file, 'wb') as f:
        f.write(decrypted)
