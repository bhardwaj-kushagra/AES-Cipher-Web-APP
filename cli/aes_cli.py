import argparse
from core.aes_crypto import generate_key, encrypt_file, decrypt_file
from utils.logger import info, success, error

def main():
    parser = argparse.ArgumentParser(description="AES Encryption Tool CLI")

    parser.add_argument("mode", choices=["encrypt", "decrypt"], help="Mode: encrypt or decrypt")
    parser.add_argument("input", help="Input file path")
    parser.add_argument("--output", required=True, help="Output file path")
    parser.add_argument("--password", help="Password for encryption/decryption")
    parser.add_argument("--keysize", type=int, choices=[16, 32], default=32, help="Key size (16 = AES-128, 32 = AES-256)")

    args = parser.parse_args()

    try:
        if args.mode == "encrypt":
            if not args.password:
                return error("Password is required for encryption.")

            key, salt = generate_key(args.password, args.keysize)
            encrypt_file(args.input, args.output, key=key, salt=salt)
            success(f"File encrypted and saved to {args.output}")

        elif args.mode == "decrypt":
            if not args.password:
                return error("Password is required for decryption.")

            decrypt_file(args.input, args.output, password=args.password, key_size=args.keysize)
            success(f"File decrypted and saved to {args.output}")

    except FileNotFoundError:
        error(f"File not found: {args.input}")
    except ValueError as ve:
        error(f"Decryption failed: {ve}")
    except Exception as e:
        error(f"Unexpected error: {e}")

if __name__ == "__main__":
    main()
