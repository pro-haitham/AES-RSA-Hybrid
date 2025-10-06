import argparse
import os
import json
import base64
import sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidTag

# --- Constants ---
RSA_KEY_SIZE = 2048
AES_KEY_SIZE = 32  # 256 bits
AES_NONCE_SIZE = 12
KEY_DIR = Path('sample_keys')

# --- Utility Functions ---

def ensure_key_dir():
    """Ensures the sample_keys directory exists."""
    KEY_DIR.mkdir(exist_ok=True)

def b64_encode(data: bytes) -> str:
    """Base64 encodes bytes to a string."""
    return base64.b64encode(data).decode('utf-8')

def b64_decode(data_str: str) -> bytes:
    """Base64 decodes a string to bytes."""
    return base64.b64decode(data_str)

# --- RSA Key Operations (Requirement 1) ---

def generate_rsa_keys(user_id: str):
    """
    Generates a 2048-bit RSA public/private key pair and saves them in PEM format.
    """
    ensure_key_dir()
    
    # Generate the 2048-bit private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE
    )

    # Get the public key
    public_key = private_key.public_key()

    # Define file paths
    private_path = KEY_DIR / f"{user_id}_private.pem"
    public_path = KEY_DIR / f"{user_id}_public.pem"

    # Serialize and save Private Key (PKCS8, No Encryption)
    with open(private_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Serialize and save Public Key (SubjectPublicKeyInfo)
    with open(public_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print(f"Keys generated for '{user_id}':")
    print(f"  Private Key: {private_path}")
    print(f"  Public Key: {public_path}")

# --- Hybrid Encryption Operations (Requirement 2) ---

def load_public_key(pub_path: Path):
    """Loads an RSA Public Key from a PEM file."""
    with open(pub_path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def encrypt_file(in_path: Path, out_path: Path, recipient_id: str, pub_path: Path):
    """
    Encrypts a file using AES-GCM and wraps the AES key using RSA-OAEP-SHA256.
    Outputs a JSON file containing the ciphertext and wrapped key material.
    """
    if not in_path.exists():
        raise FileNotFoundError(f"Input file not found: {in_path}")
        
    public_key = load_public_key(pub_path)
    file_data = in_path.read_bytes()

    # 1. Generate random AES-256 key and 12-byte nonce
    aes_key = os.urandom(AES_KEY_SIZE)
    nonce = os.urandom(AES_NONCE_SIZE)

    # 2. Encrypt data with AES-GCM
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=None)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(file_data) + encryptor.finalize()
    # The GCM tag is now stored in encryptor.tag

    # 3. Wrap AES key with RSA-OAEP-SHA256
    wrapped_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 4. Construct JSON payload (base64 encode all binary data)
    encrypted_data = {
        "recipient": recipient_id,
        "enc_key_b64": b64_encode(wrapped_aes_key),
        "nonce_b64": b64_encode(nonce),
        "ciphertext_b64": b64_encode(ciphertext + encryptor.tag) # Append the tag for storage
    }

    # Write the JSON data to the output file
    with open(out_path, 'w') as f:
        json.dump(encrypted_data, f, indent=4)
        
    print(f"File encrypted successfully and saved to {out_path}")


# --- Hybrid Decryption Operations (Requirement 3) ---

def load_private_key(priv_path: Path):
    """Loads an RSA Private Key from a PEM file."""
    with open(priv_path, "rb") as f:
        # Assuming no password for simplicity in this exercise
        return serialization.load_pem_private_key(
            f.read(),
            password=None
        )

def decrypt_file(in_path: Path, out_path: Path, priv_path: Path):
    """
    Reads an encrypted JSON file, unwraps the AES key, and decrypts the data.
    """
    if not in_path.exists():
        raise FileNotFoundError(f"Input file not found: {in_path}")
        
    private_key = load_private_key(priv_path)

    # 1. Read and parse JSON input file
    try:
        with open(in_path, 'r') as f:
            encrypted_data = json.load(f)
    except json.JSONDecodeError:
        raise ValueError(f"Input file is not valid JSON: {in_path}")

    # Decode binary fields
    try:
        wrapped_aes_key = b64_decode(encrypted_data["enc_key_b64"])
        nonce = b64_decode(encrypted_data["nonce_b64"])
        ciphertext_with_tag = b64_decode(encrypted_data["ciphertext_b64"])
        
        # Split ciphertext and tag (GCM tag is 16 bytes)
        tag = ciphertext_with_tag[-16:]
        ciphertext = ciphertext_with_tag[:-16]

    except (KeyError, base64.binascii.Error) as e:
        raise ValueError(f"JSON input missing required fields or has invalid Base64 encoding: {e}")
        
    if len(nonce) != AES_NONCE_SIZE:
        raise ValueError("Invalid nonce size in file.")


    # 2. Unwrap AES key using RSA private key (RSA-OAEP-SHA256)
    try:
        aes_key = private_key.decrypt(
            wrapped_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except ValueError as e:
        # This occurs if the key is corrupted or the wrong private key is used
        raise PermissionError(f"Failed to unwrap AES key. Check if the private key is correct. Error: {e}")

    # 3. Decrypt AES-GCM ciphertext
    # The tag must be passed to GCM mode for validation
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag), backend=None)
    decryptor = cipher.decryptor()
    
    try:
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # 4. Write decrypted output file
        out_path.write_bytes(decrypted_data)
        
        print(f"File decrypted successfully and saved to {out_path}")
        
    except InvalidTag:
        # This is the crucial AES-GCM authentication failure check
        raise PermissionError("Decryption failed! Ciphertext was tampered with or key/nonce is incorrect (Invalid Authentication Tag).")

# --- Command Line Interface (CLI) Logic ---

def main():
    """Main function for the command-line interface."""
    parser = argparse.ArgumentParser(
        description="Hybrid RSA/AES-GCM File Encryptor (Single File Version).",
        formatter_class=argparse.RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers(dest='command', required=True)

    # Key Generation Command
    parser_gen = subparsers.add_parser('generate-keys', help='Generate an RSA key pair.')
    parser_gen.add_argument('--id', required=True, help='Identifier for the key pair (e.g., alice).')
    parser_gen.add_argument('--type', required=True, choices=['rsa'], help='Type of key to generate (must be rsa).')
    
    # Encryption Command
    parser_enc = subparsers.add_parser('encrypt', help='Encrypt an input file.')
    parser_enc.add_argument('--in', dest='input_file', required=True, type=Path, help='Path to the file to encrypt.')
    parser_enc.add_argument('--out', dest='output_file', required=True, type=Path, help='Path for the encrypted JSON output file.')
    parser_enc.add_argument('--recipient', required=True, help='Identifier of the intended recipient (e.g., alice).')
    parser_enc.add_argument('--pub', dest='public_key', required=True, type=Path, help='Path to the recipient\'s public key (.pem).')
    
    # Decryption Command
    parser_dec = subparsers.add_parser('decrypt', help='Decrypt an encrypted file.')
    parser_dec.add_argument('--in', dest='input_file', required=True, type=Path, help='Path to the encrypted JSON input file.')
    parser_dec.add_argument('--out', dest='output_file', required=True, type=Path, help='Path for the decrypted output file.')
    parser_dec.add_argument('--key', dest='private_key', required=True, type=Path, help='Path to the recipient\'s private key (.pem).')

    # Parse arguments
    args = parser.parse_args()

    try:
        if args.command == 'generate-keys':
            generate_rsa_keys(args.id)
            
        elif args.command == 'encrypt':
            encrypt_file(args.input_file, args.output_file, args.recipient, args.public_key)
            
        elif args.command == 'decrypt':
            decrypt_file(args.input_file, args.output_file, args.private_key)

    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except PermissionError as e:
        # Handles InvalidTag (GCM failure) and failed key unwrap
        print(f"Authentication/Decryption Error: {e}", file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        # Handles malformed JSON, invalid base64, etc.
        print(f"Data Integrity Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
