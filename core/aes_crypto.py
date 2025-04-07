# core/aes_crypto.py

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import os

BLOCK_SIZE = AES.block_size  # 16 bytes

def pad(data: bytes) -> bytes:
    padding_length = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([padding_length] * padding_length)

def unpad(data: bytes) -> bytes:
    padding_length = data[-1]
    return data[:-padding_length]

def generate_key(password=None, key_size=32):
    if password:
        salt = get_random_bytes(16)
        key = PBKDF2(password, salt, dkLen=key_size)
        return key, salt
    else:
        return get_random_bytes(key_size), None

def encrypt_file(input_path, output_path, key, iv=None, salt=None):
    iv = iv or get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    with open(input_path, 'rb') as f:
        data = pad(f.read())

    encrypted = cipher.encrypt(data)

    with open(output_path, 'wb') as f:
        if salt:
            f.write(salt)  # 16 bytes
        f.write(iv)       # 16 bytes
        f.write(encrypted)

def decrypt_file(input_path, output_path, password=None, key=None, key_size=32):
    with open(input_path, 'rb') as f:
        if password:
            salt = f.read(16)
            key = PBKDF2(password, salt, dkLen=key_size)
        iv = f.read(16)
        encrypted = f.read()

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(encrypted))

    with open(output_path, 'wb') as f:
        f.write(decrypted)

