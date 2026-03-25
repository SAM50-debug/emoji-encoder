# Emoji Cipher

A command-line tool that encrypts text into emoji sequences using real cryptography (AES-GCM + scrypt), and allows secure decryption back to plaintext.

This is not a toy encoder — messages are fully encrypted and authenticated before being represented as emojis.

---

## What It Does

- Encrypts plaintext using a password
- Converts encrypted data into emoji strings
- Supports multiple emoji “themes” (faces, animals, food, symbols)
- Decrypts emoji strings back to original messages

The emoji output is safe to share publicly — without the password, it cannot be decrypted.

---

## How It Works (High-Level)

1. Message is encrypted using AES-GCM
2. Key is derived from password using scrypt
3. Encrypted bytes are Base64 encoded
4. Each Base64 character is mapped to an emoji (64-symbol alphabet)

Decryption reverses this process.

---

## Features

### Secure Encryption
- AES-GCM (authenticated encryption)
- Scrypt key derivation (resistant to brute force)
- Random salt and nonce per message

### Emoji Encoding Layer
- 1:1 mapping from Base64 → emoji
- No information loss
- Deterministic decoding

### Multiple Themes
- `faces`
- `animals`
- `food`
- `symbols`

Each theme defines a unique 64-emoji alphabet.

### CLI Usability
- Supports stdin and arguments
- Multi-line paste mode for decryption
- Optional fast mode for testing
- Readable emoji formatting (grouped output)

---

## Usage

### Encrypt

```bash
python cli.py encrypt -m "Hello World"
----
### Options:

--theme → choose emoji set
--single-line → disable formatting
--fast → reduce scrypt cost (testing only)
Decrypt
python cli.py decrypt -e "😀😃😄..."

Options:

--paste → multi-line emoji input
--theme → force a theme (otherwise auto-detected)
--fast → match fast encryption mode
Password Requirements
Minimum length: 14 characters
Output Format

By default, emojis are grouped for readability:

😀😃😄😁 😆😅😂🤣
😊😉😎😍 😘😗😙😚

This formatting does not affect decryption.

Security Notes
Encryption uses AES-GCM with authenticated data
Incorrect password or modified emoji text will fail decryption
Each encryption uses:
new salt
new nonce
