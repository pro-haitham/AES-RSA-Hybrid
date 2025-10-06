# Hybrid RSA/AES-GCM File Encryptor

This project is a **single-file hybrid encryption tool** written in Python.
It uses **RSA** for encrypting (wrapping) a random AES session key and **AES-GCM** for encrypting file contents.

The tool provides a **command-line interface (CLI)** to generate keys, encrypt files, and decrypt encrypted files.

---

## Features

* **RSA Key Pair Generation** (2048-bit).
* **Hybrid Encryption**: AES-256 (GCM) for files + RSA-OAEP (SHA-256) for AES key wrapping.
* **Authentication**: AES-GCM ensures integrity and tamper detection.
* **JSON Output**: Encrypted files are stored as JSON with Base64 encoding.

---

##  Dependencies

* Python 3.8+
* [cryptography](https://cryptography.io/) library

Install dependency:

```bash
pip install cryptography
```

---

##  Project Structure

* `Single-File Hybrid Encryptor.py` → Main script
* `sample_keys/` → Directory where RSA keys are stored
* Encrypted files → JSON files (e.g., `hello.enc`)

---

##  Usage Workflow

### 1. Generate RSA Keys

Generate a key pair for `alice`:

```bash
py "Single-File Hybrid Encryptor.py" generate-keys --id alice --type rsa
```

This creates:

* `sample_keys/alice_private.pem`
* `sample_keys/alice_public.pem`

---

### 2. Create a Test File

```bash
echo "This is my secret message!" > hello.txt
```

---

### 3. Encrypt the File

Encrypt `hello.txt` for recipient `alice`:

```bash
py "Single-File Hybrid Encryptor.py" encrypt \
  --in hello.txt \
  --out hello.enc \
  --recipient alice \
  --pub sample_keys/alice_public.pem
```

---

### 4. Decrypt the File

Decrypt `hello.enc` using Alice’s private key:

```bash
py "Single-File Hybrid Encryptor.py" decrypt \
  --in hello.enc \
  --out hello.dec \
  --key sample_keys/alice_private.pem
```

---

### 5. Verify Decryption

```bash
cat hello.dec
```

Expected output:

```
This is my secret message!
```

---

##  Help Commands

List all available commands:

```bash
py "Single-File Hybrid Encryptor.py" --help
py "Single-File Hybrid Encryptor.py" encrypt --help
py "Single-File Hybrid Encryptor.py" decrypt --help
```

---

##  How It Works

1. **Key Generation**: Generates RSA-2048 public/private key pair in PEM format.
2. **Encryption**:

   * Generates a random AES-256 key and nonce.
   * Encrypts file contents with AES-GCM.
   * Wraps AES key with RSA-OAEP (SHA-256).
   * Stores result in a JSON file with Base64-encoded fields.
3. **Decryption**:

   * Loads recipient’s RSA private key.
   * Unwraps AES key.
   * Decrypts AES-GCM ciphertext.
   * Validates integrity using GCM authentication tag.
   * Outputs the plaintext file.

---

##  License

This project is released under the **MIT License**.
