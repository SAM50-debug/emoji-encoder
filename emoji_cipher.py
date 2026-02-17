# emoji_cipher.py
from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


# -------------------------
# Base64 index space (0..63)
# -------------------------
_B64_STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


# -------------------------
# 64-emoji alphabets/themes
# -------------------------
# IMPORTANT: Keep 64 emojis per theme. Avoid flags/family/skin-tone/ZWJ where possible.
THEMES: Dict[str, List[str]] = {}

THEMES["faces"] = [
    "😀","😁","😂","🤣","😃","😄","😅","😆",
    "😉","😊","😋","😎","😍","😘","😗","😙",
    "😚","🙂","🤗","🤩","🤔","🤨","😐","😑",
    "😶","🙄","😏","😣","😥","😮","🤐","😯",
    "😪","😫","🥱","😴","😌","😛","😜","😝",
    "🤤","😒","😓","😔","😕","🙃","🫠","🤑",
    "😲","🙁","😖","😞","😟","😤","😢","😭",
    "😦","😧","😨","😩","🤯","😬","😰","🤫",
]

THEMES["animals"] = [
    "🐶","🐱","🐭","🐹","🐰","🦊","🐻","🐼",
    "🐨","🐯","🦁","🐮","🐷","🐸","🐵","🐔",
    "🐧","🐦","🐤","🦆","🦉","🦇","🐺","🐗",
    "🐴","🦄","🐝","🐛","🦋","🐌","🐞","🕸",
    "🦂","🐢","🐍","🦎","🐙","🦑","🦐","🦀",
    "🐟","🐠","🐡","🦈","🐬","🐳","🐋","🦭",
    "🦦","🦥","🐘","🦛","🦏","🦒","🦘","🐪",
    "🐫","🦙","🦌","🐐","🐑","🐏","🐄","🐓",
]

THEMES["food"] = [
    "🍎","🍐","🍊","🍋","🍌","🍉","🍇","🍓",
    "🫐","🍈","🍒","🍑","🥭","🍍","🥥","🥝",
    "🍅","🍆","🥑","🥦","🥬","🥒","🌶️","🌽",
    "🥕","🧄","🧅","🥔","🍠","🥐","🥯","🍞",
    "🥖","🧀","🥚","🍳","🥞","🧇","🥓","🍗",
    "🍖","🌭","🍔","🍟","🍕","🥪","🌮","🌯",
    "🥙","🧆","🍝","🍜","🍲","🍛","🍣","🍱",
    "🥟","🫔","🍤","🍙","🍚","🍘","🍥","🥮",
]

THEMES["symbols"] = [
    "⭐","🌟","✨","⚡","🔥","💧","❄️","🌈",
    "🎯","🎲","🎮","🎧","🎵","🎶","📌","📍",
    "📎","✂️","🧷","🧲","🔑","🔒","🔓","🧠",
    "💡","🕯️","🧨","🎁","📦","🧾","🪙","💎",
    "🧭","🗺️","🧩","🧪","🧫","🧬","🔭","🔬",
    "📡","💻","🖥️","📱","⌚","📷","🎥","📺",
    "🔋","🔌","🧯","⚙️","🛠️","🔧","🔩","⛓️",
    "🚀","🛰️","🛸","✈️","🚁","🚦","🧱","🏁",
]


# -------------------------
# VERY-STRONG defaults
# -------------------------
DEFAULT_SCRYPT_N = 2**17
DEFAULT_SCRYPT_R = 8
DEFAULT_SCRYPT_P = 1
SALT_LEN = 32
NONCE_LEN = 12
MIN_PASSWORD_LEN = 14


class EmojiCipherError(Exception):
    pass


class InvalidEmojiInput(EmojiCipherError):
    pass


class DecryptionFailed(EmojiCipherError):
    pass


@dataclass(frozen=True)
class EncryptedPayload:
    version: int
    salt: bytes
    nonce: bytes
    ciphertext: bytes

    def to_bytes(self) -> bytes:
        return (
            bytes([self.version, len(self.salt)]) + self.salt
            + bytes([len(self.nonce)]) + self.nonce
            + self.ciphertext
        )

    @staticmethod
    def from_bytes(data: bytes) -> "EncryptedPayload":
        if len(data) < 3:
            raise ValueError("payload too short")

        v = data[0]
        salt_len = data[1]
        pos = 2
        if len(data) < pos + salt_len + 1:
            raise ValueError("payload too short (salt)")
        salt = data[pos:pos + salt_len]
        pos += salt_len

        nonce_len = data[pos]
        pos += 1
        if len(data) < pos + nonce_len:
            raise ValueError("payload too short (nonce)")
        nonce = data[pos:pos + nonce_len]
        pos += nonce_len

        ciphertext = data[pos:]
        if len(ciphertext) < 16:
            raise ValueError("payload too short (ciphertext)")

        return EncryptedPayload(v, salt, nonce, ciphertext)


def validate_password(pw: str, *, min_len: int = MIN_PASSWORD_LEN) -> None:
    if not pw:
        raise ValueError("Password cannot be empty.")
    if len(pw) < min_len:
        raise ValueError(f"Password too short. Use at least {min_len} characters.")


def _derive_key(password: str, salt: bytes, *, scrypt_n: int, scrypt_r: int, scrypt_p: int) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=scrypt_n, r=scrypt_r, p=scrypt_p)
    return kdf.derive(password.encode("utf-8"))


def encrypt_to_bytes(
    plaintext: str,
    password: str,
    *,
    scrypt_n: int = DEFAULT_SCRYPT_N,
    scrypt_r: int = DEFAULT_SCRYPT_R,
    scrypt_p: int = DEFAULT_SCRYPT_P,
) -> bytes:
    salt = os.urandom(SALT_LEN)
    key = _derive_key(password, salt, scrypt_n=scrypt_n, scrypt_r=scrypt_r, scrypt_p=scrypt_p)
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_LEN)
    aad = b"emoji-cipher-v1"
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), aad)
    return EncryptedPayload(1, salt, nonce, ciphertext).to_bytes()


def decrypt_from_bytes(
    payload_bytes: bytes,
    password: str,
    *,
    scrypt_n: int = DEFAULT_SCRYPT_N,
    scrypt_r: int = DEFAULT_SCRYPT_R,
    scrypt_p: int = DEFAULT_SCRYPT_P,
) -> str:
    payload = EncryptedPayload.from_bytes(payload_bytes)
    if payload.version != 1:
        raise DecryptionFailed(f"Unsupported version: {payload.version}")

    key = _derive_key(password, payload.salt, scrypt_n=scrypt_n, scrypt_r=scrypt_r, scrypt_p=scrypt_p)
    aesgcm = AESGCM(key)
    aad = b"emoji-cipher-v1"
    pt = aesgcm.decrypt(payload.nonce, payload.ciphertext, aad)
    return pt.decode("utf-8")


# -------------------------
# Emoji codec (NO PAD)
# -------------------------
def _bytes_to_emoji(data: bytes, alphabet: List[str]) -> str:
    b64 = base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")
    out = []
    for ch in b64:
        std_ch = ch.replace("-", "+").replace("_", "/")
        idx = _B64_STD.index(std_ch)
        out.append(alphabet[idx])
    return "".join(out)


def _emoji_to_bytes(s: str, alphabet: List[str]) -> bytes:
    emoji_to_idx = {e: i for i, e in enumerate(alphabet)}
    chars = []
    i = 0
    s = s.strip()

    while i < len(s):
        if s[i].isspace():
            i += 1
            continue

        matched = None
        for e in alphabet:
            if s.startswith(e, i):
                matched = e
                break

        if matched is None:
            raise InvalidEmojiInput(f"Unknown symbol at position {i}")

        chars.append(_B64_STD[emoji_to_idx[matched]])
        i += len(matched)

    b64_std = "".join(chars)
    b64_url = b64_std.replace("+", "-").replace("/", "_")
    pad_len = (-len(b64_url)) % 4
    b64_url += "=" * pad_len
    return base64.urlsafe_b64decode(b64_url)


# -------------------------
# High-level helpers
# -------------------------
def encrypt_to_emojis(
    plaintext: str,
    password: str,
    *,
    theme: str = "faces",
    scrypt_n: int = DEFAULT_SCRYPT_N,
    scrypt_r: int = DEFAULT_SCRYPT_R,
    scrypt_p: int = DEFAULT_SCRYPT_P,
) -> str:
    if theme not in THEMES:
        raise ValueError(f"Unknown theme: {theme}")
    raw = encrypt_to_bytes(plaintext, password, scrypt_n=scrypt_n, scrypt_r=scrypt_r, scrypt_p=scrypt_p)
    return _bytes_to_emoji(raw, THEMES[theme])


def decrypt_from_emojis(
    emoji_text: str,
    password: str,
    *,
    theme: Optional[str] = None,
    scrypt_n: int = DEFAULT_SCRYPT_N,
    scrypt_r: int = DEFAULT_SCRYPT_R,
    scrypt_p: int = DEFAULT_SCRYPT_P,
) -> str:
    """
    If theme is provided, use it.
    Otherwise, auto-try all themes until AES-GCM validation passes.
    """
    s = emoji_text.strip()

    # Try a specific theme if user forces it
    if theme is not None:
        if theme not in THEMES:
            raise InvalidEmojiInput(f"Unknown theme: {theme}")
        try:
            raw = _emoji_to_bytes(s, THEMES[theme])
        except Exception as e:
            raise InvalidEmojiInput(f"Could not decode emoji text with theme '{theme}'.") from e
        try:
            return decrypt_from_bytes(raw, password, scrypt_n=scrypt_n, scrypt_r=scrypt_r, scrypt_p=scrypt_p)
        except Exception as e:
            raise DecryptionFailed("Wrong password or corrupted emoji text.") from e

    # Auto-try themes
    last_decode_err: Optional[Exception] = None
    for tname, alphabet in THEMES.items():
        try:
            raw = _emoji_to_bytes(s, alphabet)
        except Exception as e:
            last_decode_err = e
            continue

        try:
            return decrypt_from_bytes(raw, password, scrypt_n=scrypt_n, scrypt_r=scrypt_r, scrypt_p=scrypt_p)
        except Exception:
            # wrong theme OR wrong password OR tampered; keep trying
            continue

    # If we got here: nothing worked
    if last_decode_err is not None:
        raise InvalidEmojiInput("Emoji text doesn't match any theme (or got modified).") from last_decode_err
    raise DecryptionFailed("Wrong password or corrupted emoji text.")
