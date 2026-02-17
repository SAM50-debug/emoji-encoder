# cli.py
import argparse
import sys
from getpass import getpass

from emoji_cipher import (
    encrypt_to_emojis,
    decrypt_from_emojis,
    validate_password,
    DecryptionFailed,
    InvalidEmojiInput,
    THEMES,
)

FAST_SCRYPT_N = 2**14


def format_emojis_multiline(s: str, group_size: int = 4, groups_per_line: int = 4) -> str:
    if group_size <= 0:
        return s
    groups = [s[i:i + group_size] for i in range(0, len(s), group_size)]
    lines = []
    for i in range(0, len(groups), groups_per_line):
        lines.append(" ".join(groups[i:i + groups_per_line]))
    return "\n".join(lines)


def main() -> int:
    p = argparse.ArgumentParser(prog="emoji-cipher")
    sub = p.add_subparsers(dest="cmd", required=True)

    enc = sub.add_parser("encrypt")
    enc.add_argument("-m", "--message", help="Plaintext message. If omitted, reads from stdin.")
    enc.add_argument("--fast", action="store_true", help="Faster (less secure) for quick testing.")
    enc.add_argument("--single-line", action="store_true", help="Print emojis in one line.")
    enc.add_argument("--theme", choices=list(THEMES.keys()), default="faces", help="Emoji theme for output.")

    dec = sub.add_parser("decrypt")
    dec.add_argument("-e", "--emojis", help="Emoji text. If omitted, reads from stdin.")
    dec.add_argument("--fast", action="store_true", help="Faster (less secure) for quick testing.")
    dec.add_argument("--paste", action="store_true", help="Multi-line paste mode (Ctrl+Z + Enter in PowerShell).")
    dec.add_argument("--theme", choices=list(THEMES.keys()), default=None,
                     help="Optional: force a theme (otherwise auto-try all).")

    args = p.parse_args()

    scrypt_kwargs = {}
    if getattr(args, "fast", False):
        scrypt_kwargs = {"scrypt_n": FAST_SCRYPT_N}

    if args.cmd == "encrypt":
        msg = args.message if args.message is not None else sys.stdin.read()
        msg = msg.rstrip("\n")
        if not msg.strip():
            print("Error: No message provided.", file=sys.stderr)
            return 2

        pw = getpass("Password (14+ chars): ")
        try:
            validate_password(pw)
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 2

        pw2 = getpass("Confirm Password: ")
        if pw != pw2:
            print("Error: Passwords do not match.", file=sys.stderr)
            return 2

        out = encrypt_to_emojis(msg.strip(), pw, theme=args.theme, **scrypt_kwargs)

        if args.single_line:
            print(out)
        else:
            print(format_emojis_multiline(out, 4, 4))
        return 0

    if args.cmd == "decrypt":
        if args.paste:
            print("Paste emojis (multi-line ok). Then Ctrl+Z and Enter:\n")
            em = sys.stdin.read()
        else:
            em = args.emojis if args.emojis is not None else sys.stdin.read()

        em = em.strip()
        if not em:
            print("Error: No emoji text provided.", file=sys.stderr)
            return 2

        pw = getpass("Password: ")
        try:
            validate_password(pw)
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 2

        try:
            msg = decrypt_from_emojis(em, pw, theme=args.theme, **scrypt_kwargs)
            print(msg)
            return 0
        except (DecryptionFailed, InvalidEmojiInput) as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
