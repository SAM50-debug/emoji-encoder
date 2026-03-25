# Emoji Cipher

A secure command-line tool that encrypts text into emoji sequences using AES-GCM encryption and password-based key derivation.

The output is visually human-readable, but cryptographically secure.

---

## Overview

Emoji Cipher transforms plaintext into encrypted emoji strings.  
Unlike simple encoders, the system applies **authenticated encryption first**, then converts the result into emojis.

Without the correct password, the emoji output cannot be decrypted.

---

## Key Capabilities

### Secure Encryption
- AES-GCM (confidentiality + integrity)
- Scrypt-based key derivation
- Random salt and nonce per message

### Emoji Encoding Layer
- Lossless mapping from Base64 → emoji alphabet
- Fully reversible transformation
- Independent of encryption logic

### Theme Support
- Multiple emoji alphabets:
  - faces
  - animals
  - food
  - symbols

### CLI Interface
- Encrypt/decrypt commands
- Multi-line paste mode
- Optional fast mode for testing
- Readable grouped output

---

## Example

### Encrypt

```bash
python cli.py encrypt -m "Hello World"
