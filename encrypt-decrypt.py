# Sotiris Gypsiotis (ID: 22983)

import os
import sys
import random
import argparse
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Caesar Cipher functions
def caesar_encrypt(text, key):
    # perform character shift based on key for encryption
    return ''.join(chr((ord(char) + key) % 256) for char in text)

def caesar_decrypt(text, key):
    # perform character shift based on key for decryption
    return ''.join(chr((ord(char) - key) % 256) for char in text)

# One-Time Pad (XOR) functions
def otp_encrypt(text, key):
    # ensure the key is as long as the input text
    if len(key) < len(text):
        raise ValueError("The key must be at least as long as the input text.")
    # XOR each byte of text with the corresponding byte of the key
    return bytes([t ^ k for t, k in zip(text, key)])

def otp_decrypt(text, key):
    # ensure the key is as long as the input text
    if len(key) < len(text):
        raise ValueError("The key must be at least as long as the input text.")
    # XOR each byte of text with the corresponding byte of the key for decryption
    return bytes([t ^ k for t, k in zip(text, key)])

# AES functions
def aes_encrypt(data, key):
    # create a new AES cipher in CBC mode
    cipher = AES.new(key, AES.MODE_CBC)
    # encrypt data after padding to match block size
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    # prepend the IV to the ciphertext
    return cipher.iv + ct_bytes

def aes_decrypt(ct, key):
    # extract the IV from the first block
    iv = ct[:AES.block_size]
    # extract the actual ciphertext
    ct = ct[AES.block_size:]
    # create a new AES cipher in CBC mode using the extracted IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # decrypt and unpad the ciphertext
    return unpad(cipher.decrypt(ct), AES.block_size)

# RSA functions
def rsa_encrypt(data, key_path):
    # import the public key for encryption
    key = RSA.import_key(open(key_path).read())
    cipher = PKCS1_OAEP.new(key)  # create cipher using public key
    return cipher.encrypt(data)

def rsa_decrypt(ct, key_path):
    # import the private key for decryption
    key = RSA.import_key(open(key_path).read())
    cipher = PKCS1_OAEP.new(key)  # create cipher using private key
    return cipher.decrypt(ct)

# main function
def main():
    try:
        # parse command-line arguments
        parser = argparse.ArgumentParser(description="File Encryption Tool")
        parser.add_argument('--encrypt', action='store_true', help='Encrypt the file')
        parser.add_argument('--decrypt', action='store_true', help='Decrypt the file')
        parser.add_argument('--algorithm', required=True, choices=['caesar', 'otp', 'aes', 'rsa'], help='Algorithm to use')
        parser.add_argument('--key', help='Path to the key file')
        parser.add_argument('--input', required=True, help='Path to the input file')
        parser.add_argument('--output', required=True, help='Path to the output file')
        args = parser.parse_args()

        # read input data as bytes
        with open(args.input, 'rb') as f:
            data = f.read()

        # check if key file is empty during decryption
        if args.decrypt:
            if not args.key or not os.path.exists(args.key):
                print("Error: The key file is missing. Decryption process cannot proceed.")
                sys.exit(1)
            if os.path.getsize(args.key) == 0:
                print(f"Error: The key file '{args.key}' is empty. Decryption process cannot proceed.")
                sys.exit(1)

        #CAESAR
        if args.algorithm == 'caesar':
            key_file_name = "caesar_key.txt"
            if args.encrypt and (not os.path.exists(key_file_name) or os.path.getsize(key_file_name) == 0):
                # generate a random shift value if no key is provided
                key = random.randint(1, 255)
                with open(key_file_name, 'w') as key_file:
                    key_file.write(str(key))
                print(f"Generated Caesar Cipher key and saved to '{key_file_name}'")
            else:
                try:
                    # read key from file and convert to integer
                    key = int(open(args.key if args.key else key_file_name).read().strip())
                except ValueError:
                    print("Error: Key file must contain a valid integer for the Caesar Cipher.")
                    sys.exit(1)
            # perform encryption or decryption based on the flag
            result = caesar_encrypt(data.decode(), key) if args.encrypt else caesar_decrypt(data.decode(), key)

        # OTP
        elif args.algorithm == 'otp':
            key_file_name = "otp_key.txt"
            if args.encrypt and (not os.path.exists(key_file_name) or os.path.getsize(key_file_name) == 0):
                # Ensure the input data is not empty for key generation
                if len(data) == 0:
                    print("Error: Input file is empty. Cannot generate a key for OTP.")
                    sys.exit(1)

                # Generate a random key of the same length as the input data
                key = get_random_bytes(len(data))

                # Save the generated key to 'otp_key.txt'
                with open(key_file_name, 'wb') as key_file:
                    key_file.write(key)

                print(f"Generated OTP key and saved to '{key_file_name}'.")
            else:
                # Read the key as bytes from the file
                key = open(args.key if args.key else key_file_name, 'rb').read()

            # Validate key length before encryption or decryption
            if len(key) < len(data):
                print("Error: Key file must be at least as long as the input file for OTP.")
                sys.exit(1)

            # Perform encryption or decryption using XOR
            result = otp_encrypt(data, key) if args.encrypt else otp_decrypt(data, key)

        # AES
        elif args.algorithm == 'aes':
            key_file_name = "aes_key.txt"
            if args.encrypt and (not os.path.exists(key_file_name) or os.path.getsize(key_file_name) == 0):
                # generate a 16-byte (128-bit) AES key by default if no key is provided
                key = get_random_bytes(16)
                with open(key_file_name, 'w') as key_file:
                    key_file.write(key.hex())
                print(f"Generated a 128-bit AES key and saved to '{key_file_name}'")
            else:
                try:
                    # read the key from file and convert it from hex to bytes
                    key = bytes.fromhex(open(args.key if args.key else key_file_name).read().strip())
                    # validate key length
                    if len(key) not in (16, 32):  # accept 16 bytes (AES-128) or 32 bytes (AES-256)
                        raise ValueError("AES key must be 16 bytes (128 bits) or 32 bytes (256 bits) long.")
                except ValueError:
                    print("Error: Key file must contain a valid hexadecimal string of 16 or 32 bytes.")
                    sys.exit(1)
                except FileNotFoundError:
                    print(f"Error: Key file '{args.key}' not found.")
                    sys.exit(1)

            # perform AES encryption or decryption
            result = aes_encrypt(data, key) if args.encrypt else aes_decrypt(data, key)

        # RSA key handling
        elif args.algorithm == 'rsa':
            private_key_path = 'private_key.pem'
            public_key_path = 'public_key.pem'

            if not os.path.exists(private_key_path) or os.path.getsize(private_key_path) == 0 or \
                    not os.path.exists(public_key_path) or os.path.getsize(public_key_path) == 0:
                print("RSA key files not found or empty. Generating new RSA key pair...")

                # generate a new RSA key pair
                key = RSA.generate(2048)

                # save private key
                with open(private_key_path, 'wb') as priv_file:
                    priv_file.write(key.export_key())

                # save public key
                with open(public_key_path, 'wb') as pub_file:
                    pub_file.write(key.publickey().export_key())

                print(f"Generated new RSA key pair: '{private_key_path}' and '{public_key_path}'")

            args.key = private_key_path if args.decrypt else public_key_path

            try:
                # perform RSA encryption or decryption
                result = rsa_encrypt(data, args.key) if args.encrypt else rsa_decrypt(data, args.key)
            except FileNotFoundError:
                print(f"Error: RSA key file '{args.key}' not found.")
                sys.exit(1)
            except ValueError:
                print("Error: Invalid RSA key file format.")
                sys.exit(1)

        # ensure the output file is created if missing
        if args.encrypt:
            if not os.path.exists(args.output):
                print(f"Output file '{args.output}' not found. Creating it...")
                open(args.output, 'wb').close()  # create the file

        # write the result to the output file
        with open(args.output, 'wb') as f:
            f.write(result.encode() if isinstance(result, str) else result)

        print(f"Operation completed successfully. Output written to '{args.output}'.")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
