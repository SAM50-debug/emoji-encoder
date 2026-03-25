---

### ✅ Improved `ARCHITECTURE.md`

```markdown
# Architecture

## Overview

The system is a two-layer pipeline:

1. **Cryptographic Layer** → Encrypts and authenticates data
2. **Encoding Layer** → Converts binary data into emoji sequences

The CLI acts as a thin orchestration layer over these components.

---

## Module Responsibilities

### 1. CLI Layer (`cli.py`)

Handles:
- Argument parsing (`encrypt`, `decrypt`)
- Input sources (stdin / flags / paste mode)
- Password input and validation
- Output formatting (grouped emojis)
- Passing configuration (theme, fast mode)

No cryptographic logic is implemented here.

---

### 2. Core Engine (`emoji_cipher.py`)

#### A. Cryptographic Layer

**Key Derivation**
- Algorithm: scrypt
- Inputs: password + random salt
- Output: 256-bit key

**Encryption**
- Algorithm: AES-GCM
- Inputs: key + nonce + plaintext
- Output: ciphertext + authentication tag

**Security Properties**
- Confidentiality (encryption)
- Integrity (GCM authentication)
- Resistance to brute-force (scrypt)

---

#### B. Payload Structure

Encrypted data is serialized into:


[version][salt_len][salt][nonce_len][nonce][ciphertext]


This allows:
- self-contained messages
- forward compatibility via versioning

---

#### C. Encoding Layer

**Step 1: Base64 Encoding**
- Binary payload → URL-safe Base64 (no padding)

**Step 2: Emoji Mapping**
- Each Base64 character (0–63) maps to one emoji
- Mapping defined by selected theme

This ensures:
- reversible encoding
- no entropy loss

---

#### D. Decoding Logic

1. Parse emoji string
2. Identify matching theme:
   - either forced by user
   - or auto-tried across all themes
3. Convert emoji → Base64 → bytes
4. Deserialize payload
5. Decrypt using AES-GCM

---

## Data Flow

### Encryption


plaintext
→ UTF-8 encoding
→ key derivation (scrypt)
→ AES-GCM encryption
→ payload serialization
→ Base64 encoding
→ emoji mapping
→ output string


---

### Decryption


emoji string
→ emoji parsing
→ theme resolution
→ Base64 reconstruction
→ payload parsing
→ key derivation
→ AES-GCM decryption
→ plaintext


---

## Theme System

Each theme defines:
- exactly 64 emojis
- 1:1 mapping with Base64 index space

Themes are interchangeable encoding layers:
- do not affect encryption
- only affect representation

---

## Error Handling

- Invalid emoji → `InvalidEmojiInput`
- Wrong password / tampered data → `DecryptionFailed`
- Password validation enforced before encryption/decryption

---

## Performance Considerations

- Default scrypt parameters are intentionally high (secure but slower)
- `--fast` mode reduces cost for testing

---

## Design Characteristics

- Stateless (no storage)
- Deterministic decoding
- Strong separation:
  - CLI (interaction)
  - crypto (security)
  - encoding (representation)
