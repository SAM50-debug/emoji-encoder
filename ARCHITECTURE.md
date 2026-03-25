
---

### ✅ 2. FINAL `ARCHITECTURE.md`

```markdown
# Architecture

## System Overview

The system consists of two primary layers:

1. Cryptographic Layer (security)
2. Encoding Layer (representation)

The CLI orchestrates both.

---

## High-Level Flow

### Encryption

plaintext
→ key derivation (scrypt)
→ AES-GCM encryption
→ payload serialization
→ Base64 encoding
→ emoji mapping
→ output


### Decryption

emoji input
→ emoji decoding
→ Base64 reconstruction
→ payload parsing
→ key derivation
→ AES-GCM decryption
→ plaintext

---

## Module Responsibilities

### CLI (`cli.py`)

Responsibilities:
- Command parsing (encrypt/decrypt)
- Input handling (message, stdin, paste mode)
- Password validation
- Output formatting
- Passing parameters to core engine

No cryptographic logic is implemented here.

---

### Core Engine (`emoji_cipher.py`)

#### 1. Cryptographic Layer

Key derivation:
- Algorithm: scrypt
- Input: password + salt

Encryption:
- Algorithm: AES-GCM
- Input: key + nonce + plaintext
- Output: ciphertext + authentication tag

#### 2. Payload Structure

Serialized format:

[version][salt][nonce][ciphertext]

Ensures:
- self-contained encrypted message
- forward compatibility

---

#### 3. Encoding Layer

Step 1:
Binary payload → Base64 (no padding)

Step 2:
Base64 characters → emoji symbols (64-character mapping)

Each theme defines its own mapping.

---

## Theme System

- Each theme contains exactly 64 emojis
- Provides a direct mapping to Base64 index space
- Does not affect encryption

---

## Decoding Strategy

- If theme is specified → direct decoding
- Otherwise → system attempts all themes

---

## Error Handling

- Invalid emoji input → decoding failure
- Wrong password → authentication failure
- Corrupted payload → decryption failure

---

## Design Properties

- Stateless system
- Deterministic decoding
- Clear separation of concerns:
  - CLI
  - crypto
  - encoding
