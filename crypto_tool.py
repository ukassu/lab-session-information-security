from __future__ import annotations

import argparse
import base64
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
AES_IV_SIZE = 16
DES_IV_SIZE = 8
PBKDF2_ROUNDS = 600_000
ALGORITHMS = {"AES", "DES", "RC4"}
CIPHERTEXT_DIR = Path(__file__).resolve().parent / "ciphertexts"


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def unb64(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


def derive(password: str, salt: bytes, length: int) -> bytes:
    if not password:
        raise ValueError("Password must not be empty.")
    return PBKDF2(password, salt, dkLen=length, count=PBKDF2_ROUNDS, hmac_hash_module=SHA256)


def pkcs7pad(data: bytes, block_size: int) -> bytes:
    padding = block_size - len(data) % block_size
    return data + bytes([padding]) * padding


def pkcs7unpad(data: bytes, block_size: int) -> bytes:
    if not data or len(data) % block_size:
        raise ValueError("Invalid padding.")
    padding = data[-1]
    if padding < 1 or padding > block_size or data[-padding:] != bytes([padding]) * padding:
        raise ValueError("Invalid padding.")
    return data[:-padding]


def encryptbytes(data: bytes, password: str, algorithm: str = "AES", name: str = "data") -> bytes:
    algorithm = algorithm.upper()
    if algorithm not in ALGORITHMS:
        raise ValueError(f"Algorithm must be one of AES, DSA, RC4")
    salt = secrets.token_bytes(SALT_SIZE)
    fields: dict[str, Any] = {
        "algorithm": algorithm,
        "name": name,
        "salt": b64(salt),
    }

    if algorithm == "AES":
        key = derive(password, salt, 32)
        iv = secrets.token_bytes(AES_IV_SIZE)
        ciphertext = AES.new(key, AES.MODE_CBC, iv=iv).encrypt(pkcs7pad(data, AES.block_size))
        fields.update(iv=b64(iv), ciphertext=b64(ciphertext))
    elif algorithm == "DES":
        key = derive(password, salt, 8)
        iv = secrets.token_bytes(DES_IV_SIZE)
        ciphertext = DES.new(key, DES.MODE_CBC, iv=iv).encrypt(pkcs7pad(data, DES.block_size))
        fields.update(iv=b64(iv), ciphertext=b64(ciphertext))
    else:
        key = derive(password, salt, 32)
        ciphertext = ARC4.new(key).encrypt(data)
        fields.update(ciphertext=b64(ciphertext))

    return json.dumps(fields, indent=4)


def decryptbytes(envelope: str | bytes, password: str) -> tuple[bytes, str]:
    try:
        fields = json.loads(envelope)
        algorithm = fields["algorithm"].upper()
        salt = unb64(fields["salt"])
        ciphertext = unb64(fields["ciphertext"])
        iv = unb64(fields["iv"]) if algorithm in {"AES", "DES"} else b""
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, AttributeError, ValueError) as exc:
        raise ValueError("The encrypted file is not a valid envelope.") from exc
    if algorithm not in ALGORITHMS:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    if len(salt) != SALT_SIZE:
        raise ValueError("Invalid salt.")

    try:
        if algorithm == "AES":
            key = derive(password, salt, 32)
            data = pkcs7unpad(AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ciphertext), AES.block_size)
        elif algorithm == "DES":
            key = derive(password, salt, 8)
            data = pkcs7unpad(DES.new(key, DES.MODE_CBC, iv=iv).decrypt(ciphertext), DES.block_size)
        else:
            key = derive(password, salt, 32)
            data = ARC4.new(key).decrypt(ciphertext)
    except ValueError as exc:
        raise ValueError("Wrong password or corrupted envelope.") from exc
    return data, str(fields.get("name", "data"))

# BAWAH CM HELPER. INTI CRYPTO NYA DI ATAS

def readpassword(confirm: bool = False) -> str:
    password = input("Password: ")
    if confirm and password != input("Confirm password: "):
        raise ValueError("Password confirmation does not match.")
    return password


def buildparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="crypto_tool.py",
        description="Encrypt or decrypt text and files with AES, DES, or RC4.",
    )
    subparsers = parser.add_subparsers(dest="command", metavar="<encrypt|decrypt>")

    enc = subparsers.add_parser("encrypt", help=f"Encrypt input into a JSON envelope in {CIPHERTEXT_DIR.name}/")
    source = enc.add_mutually_exclusive_group(required=True)
    source.add_argument("-i", "--input", type=Path, help="File to encrypt")
    source.add_argument("-t", "--text", help="UTF-8 text to encrypt")
    enc.add_argument("-a", "--algorithm", type=str.upper, choices=sorted(ALGORITHMS), default="AES")
    enc.add_argument("-o", "--output", help=f"Envelope filename inside {CIPHERTEXT_DIR.name}/ (default: <name>.<alg>.json)")
    enc.add_argument("--password", help="Password (prompting is safer than putting it in the shell)")

    dec = subparsers.add_parser("decrypt", help="Decrypt a JSON envelope")
    dec.add_argument("-i", "--input", type=Path, required=True, help=f"Envelope file to decrypt; a bare filename is also looked up in {CIPHERTEXT_DIR.name}/")
    dec.add_argument("-o", "--output", type=Path, help="Output file (default: print text, or restore the original filename for binary data)")
    dec.add_argument("--password", help="Password (prompting is safer than putting it in the shell)")
    return parser


def encryptcommand(args: argparse.Namespace) -> None:
    if args.text is not None:
        data, name = args.text.encode("utf-8"), "text.txt"
    else:
        data, name = args.input.read_bytes(), args.input.name
    password = args.password or readpassword(confirm=True)

    filename = args.output or f"{name}.{args.algorithm.lower()}.json"
    if not filename.endswith(".json"):
        filename += ".json"
    CIPHERTEXT_DIR.mkdir(exist_ok=True)
    output = CIPHERTEXT_DIR / Path(filename).name
    output.write_text(encryptbytes(data, password, args.algorithm, name), encoding="utf-8")
    print(f"Saved {output}")


def decryptcommand(args: argparse.Namespace) -> None:
    source = args.input
    if not source.exists() and (CIPHERTEXT_DIR / source.name).exists():
        source = CIPHERTEXT_DIR / source.name
    password = args.password or readpassword()
    data, name = decryptbytes(source.read_bytes(), password)
    if args.output is None:
        try:
            print(data.decode("utf-8"))
            return
        except UnicodeDecodeError:
            args.output = Path(name)
    args.output.write_bytes(data)
    print(f"Saved {args.output}")


def main(argv: list[str] | None = None) -> int:
    parser = buildparser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help(sys.stderr)
        return 2

    try:
        if args.command == "encrypt":
            encryptcommand(args)
        else:
            decryptcommand(args)
        return 0
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
