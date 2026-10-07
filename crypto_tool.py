"""Password-based AES, DES, and RC4 encryption for text and arbitrary files.

The encrypted representation is a self-contained JSON envelope, so the same
functions can process UTF-8 text, DOCX/PDF files, images, and other bytes.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import hmac
import json
import secrets
import sys
from pathlib import Path
from typing import Any

from Crypto.Cipher import AES, ARC4, DES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2

VERSION = 1
SALT_SIZE = 16
AES_NONCE_SIZE = 12
DES_IV_SIZE = 8
PBKDF2_ROUNDS = 600_000
ALGORITHMS = {"AES", "DES", "RC4"}


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


def _derive(password: str, salt: bytes, length: int) -> bytes:
    if not password:
        raise ValueError("Password must not be empty.")
    return PBKDF2(password, salt, dkLen=length, count=PBKDF2_ROUNDS, hmac_hash_module=SHA256)


def _pkcs7_pad(data: bytes, block_size: int) -> bytes:
    padding = block_size - len(data) % block_size
    return data + bytes([padding]) * padding


def _pkcs7_unpad(data: bytes, block_size: int) -> bytes:
    if not data or len(data) % block_size:
        raise ValueError("Invalid padding.")
    padding = data[-1]
    if padding < 1 or padding > block_size or data[-padding:] != bytes([padding]) * padding:
        raise ValueError("Invalid padding.")
    return data[:-padding]


def encrypt_bytes(data: bytes, password: str, algorithm: str = "AES", name: str = "data") -> bytes:
    """Encrypt bytes and return a UTF-8 JSON envelope."""
    algorithm = algorithm.upper()
    if algorithm not in ALGORITHMS:
        raise ValueError(f"Algorithm must be one of: {', '.join(sorted(ALGORITHMS))}.")
    salt = secrets.token_bytes(SALT_SIZE)
    fields: dict[str, Any] = {
        "version": VERSION,
        "algorithm": algorithm,
        "name": name,
        "salt": _b64(salt),
        "kdf": {"name": "PBKDF2-HMAC-SHA256", "iterations": PBKDF2_ROUNDS},
    }

    if algorithm == "AES":
        key = _derive(password, salt, 32)
        nonce = secrets.token_bytes(AES_NONCE_SIZE)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        fields.update(nonce=_b64(nonce), ciphertext=_b64(ciphertext), tag=_b64(tag))
    elif algorithm == "DES":
        key = _derive(password, salt, 8)
        iv = secrets.token_bytes(DES_IV_SIZE)
        ciphertext = DES.new(key, DES.MODE_CBC, iv=iv).encrypt(_pkcs7_pad(data, DES.block_size))
        mac = hmac.new(key, iv + ciphertext, hashlib.sha256).digest()
        fields.update(iv=_b64(iv), ciphertext=_b64(ciphertext), mac=_b64(mac))
    else:
        key = _derive(password, salt, 32)
        nonce = secrets.token_bytes(16)
        stream_key = hmac.new(key, nonce, hashlib.sha256).digest()
        ciphertext = ARC4.new(stream_key).encrypt(data)
        mac = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()
        fields.update(nonce=_b64(nonce), ciphertext=_b64(ciphertext), mac=_b64(mac))

    return json.dumps(fields, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def decrypt_bytes(envelope: bytes, password: str) -> tuple[bytes, str]:
    """Decrypt an envelope and return (original bytes, original name)."""
    try:
        fields = json.loads(envelope.decode("utf-8"))
        algorithm = fields["algorithm"].upper()
        salt = _unb64(fields["salt"])
        if fields["version"] != VERSION or algorithm not in ALGORITHMS:
            raise ValueError("Unsupported envelope format or version.")
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise ValueError("The encrypted file is not a valid envelope.") from exc

    if len(salt) != SALT_SIZE:
        raise ValueError("Invalid salt.")
    ciphertext = _unb64(fields["ciphertext"])
    try:
        if algorithm == "AES":
            key = _derive(password, salt, 32)
            nonce, tag = _unb64(fields["nonce"]), _unb64(fields["tag"])
            data = AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ciphertext, tag)
        elif algorithm == "DES":
            key = _derive(password, salt, 8)
            iv, mac = _unb64(fields["iv"]), _unb64(fields["mac"])
            if not hmac.compare_digest(mac, hmac.new(key, iv + ciphertext, hashlib.sha256).digest()):
                raise ValueError("Wrong password or the data has been modified.")
            data = _pkcs7_unpad(DES.new(key, DES.MODE_CBC, iv=iv).decrypt(ciphertext), DES.block_size)
        else:
            key = _derive(password, salt, 32)
            nonce, mac = _unb64(fields["nonce"]), _unb64(fields["mac"])
            if not hmac.compare_digest(mac, hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()):
                raise ValueError("Wrong password or the data has been modified.")
            stream_key = hmac.new(key, nonce, hashlib.sha256).digest()
            data = ARC4.new(stream_key).decrypt(ciphertext)
    except (KeyError, ValueError, TypeError, IndexError) as exc:
        if isinstance(exc, ValueError) and str(exc) in {"Wrong password or the data has been modified.", "Invalid padding."}:
            raise
        raise ValueError("Wrong password, corrupted envelope, or invalid parameters.") from exc
    return data, str(fields.get("name", "data"))


def _password(confirm: bool = False) -> str:
    password = getpass.getpass("Password: ")
    if confirm:
        if password != getpass.getpass("Confirm password: "):
            raise ValueError("Password confirmation does not match.")
    return password


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Encrypt or decrypt text and files with AES, DES, or RC4.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    enc = subparsers.add_parser("encrypt", help="Encrypt input into a JSON envelope")
    enc.add_argument("-a", "--algorithm", choices=sorted(ALGORITHMS), default="AES")
    enc.add_argument("-i", "--input", type=Path, help="Input file; use --text when omitted")
    enc.add_argument("-t", "--text", help="UTF-8 text to encrypt")
    enc.add_argument("-o", "--output", type=Path, required=True, help="Output envelope file")
    enc.add_argument("--password", help="Password (prompting is safer than putting it in the shell)")
    dec = subparsers.add_parser("decrypt", help="Decrypt a JSON envelope")
    dec.add_argument("-i", "--input", type=Path, required=True)
    dec.add_argument("-o", "--output", type=Path, help="Output file; required for binary data")
    dec.add_argument("--password", help="Password (prompting is safer than putting it in the shell)")
    args = parser.parse_args(argv)

    try:
        password = args.password or _password(confirm=args.command == "encrypt")
        if args.command == "encrypt":
            if (args.input is None) == (args.text is None):
                parser.error("Use exactly one of --text or --input.")
            data = args.text.encode("utf-8") if args.text is not None else args.input.read_bytes()
            name = "text.txt" if args.text is not None else args.input.name
            args.output.write_bytes(encrypt_bytes(data, password, args.algorithm, name))
        else:
            data, name = decrypt_bytes(args.input.read_bytes(), password)
            if args.output:
                args.output.write_bytes(data)
            else:
                try:
                    sys.stdout.write(data.decode("utf-8"))
                    sys.stdout.write("\n")
                except UnicodeDecodeError as exc:
                    raise ValueError("The result is binary data; use the --output option.") from exc
        return 0
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
