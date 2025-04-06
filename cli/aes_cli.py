import argparse
import os
from core import aes_crypto


def main():
    parser = argparse.ArgumentParser(description="AES File Encryptor/Decryptor CLI")
    subparsers = parser.add_subparsers(dest='command', help='Sub-command help')

    # Encrypt command
    encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt a file')
    encrypt_parser.add_argument('input', help='Input file path')
    encrypt_parser.add_argument('--output', help='Output encrypted file name', default=None)
    encrypt_parser.add_argument('--password', help='Password to derive key (PBKDF2)')
    encrypt_parser.add_argument('--keysize', type=int, choices=[16, 32], default=32, help='Key size (16 for AES-128, 32 for AES-256)')

    # Decrypt command
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt a file')
    decrypt_parser.add_argument('input', help='Encrypted file path')
    decrypt_parser.add_argument('--output', help='Output decrypted file name', default=None)
    decrypt_parser.add_argument('--password', help='Password used for encryption (PBKDF2)')
    decrypt_parser.add_argument('--keysize', type=int, choices=[16, 32], default=32, help='Key size used in encryption')

    args = parser.parse_args()

    if args.command == 'encrypt':
        if not os.path.exists(args.input):
            print(f"[!] File '{args.input}' does not exist.")
            return

        output_file = args.output or args.input + '.enc'

        # Generate key
        key, salt = aes_crypto.generate_key(args.password, args.keysize)

        # Encrypt the file
        aes_crypto.encrypt_file(args.input, output_file, key)

        print(f"[+] File encrypted and saved as '{output_file}'")
        if args.password:
            print(f"[!] Remember your password – it's required for decryption.")
        else:
            print(f"[!] Store your key safely – it's required for decryption.")

    elif args.command == 'decrypt':
        if not os.path.exists(args.input):
            print(f"[!] File '{args.input}' does not exist.")
            return

        output_file = args.output or args.input.replace('.enc', '.dec')

        if not args.password:
            print("[!] Password required for decryption (for now).")
            return

        key, _ = aes_crypto.generate_key(args.password, args.keysize)

        try:
            aes_crypto.decrypt_file(args.input, output_file, key)
            print(f"[+] File decrypted and saved as '{output_file}'")
        except ValueError:
            print("[!] Decryption failed: Incorrect password or corrupted file.")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
