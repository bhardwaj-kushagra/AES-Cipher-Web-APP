# cli/aes_cli.py

import argparse
import os
from core.aes_crypto import generate_key, encrypt_file, decrypt_file

parser = argparse.ArgumentParser(description="AES Encryption Tool (CLI)")
parser.add_argument("mode", choices=["encrypt", "decrypt"], help="Mode: encrypt or decrypt")
parser.add_argument("input", help="Input file path")
parser.add_argument("--output", required=True, help="Output file path")
parser.add_argument("--password", help="Password for key derivation")
parser.add_argument("--keysize", type=int, choices=[16, 32], default=32, help="Key size (16 for AES-128, 32 for AES-256)")

args = parser.parse_args()

if not os.path.exists(args.input):
    print("❌ Error: Input file not found!")
    exit(1)

key, salt = generate_key(args.password, args.keysize)

if args.mode == "encrypt":
    key, salt = generate_key(args.password, args.keysize)
    encrypt_file(args.input, args.output, key=key, iv=None, salt=salt)
    print(f"✅ File encrypted and saved to {args.output}")

elif args.mode == "decrypt":
    decrypt_file(args.input, args.output, password=args.password, key_size=args.keysize)
    print(f"✅ File decrypted and saved to {args.output}")

