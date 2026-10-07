# AES, DES, and RC4 Encryption

A simple Python program for encrypting text and **any file as bytes**:
DOCX, PDF, images, ZIP archives, binary files, and more. Encrypted files are
stored as UTF-8 JSON envelopes containing metadata, the salt, cipher
parameters, ciphertext, and an integrity tag/MAC.

> **Security warning:** use **AES-GCM** for real data. DES and RC4 are
> insecure/deprecated and are included only for educational or compatibility
> purposes. Do not reuse the same password for important data.

## Installation

Python 3.10+ is recommended.

```powershell
py -m pip install -r requirements.txt
```

## Python API

`encrypt_bytes(data, password, algorithm, name)` accepts arbitrary bytes.
Encode text as UTF-8 and use `read_bytes()` for files.

```python
from pathlib import Path
from crypto_tool import decrypt_bytes, encrypt_bytes

encrypted = encrypt_bytes("Hello world".encode("utf-8"), "strong-password", "AES", "message.txt")
Path("message.enc.json").write_bytes(encrypted)

plain, original_name = decrypt_bytes(Path("message.enc.json").read_bytes(), "strong-password")
Path(original_name).write_bytes(plain)
```

Available algorithms:

- **AES**: AES-256-GCM authenticated encryption (recommended).
- **DES**: DES-CBC with PKCS#7 and HMAC-SHA256 (legacy, not secure).
- **RC4**: RC4 with HMAC-SHA256 (legacy, not secure).

Passwords are converted into keys using PBKDF2-HMAC-SHA256 with a random
16-byte salt and 600,000 iterations. Each encryption generates a new salt and
nonce/IV. The MAC for DES/RC4 and the tag for AES detect an incorrect password
or modified data.

## CLI: text

The password can be entered at the prompt (recommended) or supplied with
`--password`.

```powershell
py crypto_tool.py encrypt --algorithm AES --text "Hello world" --output message.enc.json
py crypto_tool.py decrypt --input message.enc.json --output message.txt
```

## CLI: text files, DOCX, and binary files

All files are processed as bytes, so no encoding is assumed and the file
contents are restored identically after decryption.

```powershell
# DOCX
py crypto_tool.py encrypt -a AES -i report.docx -o report.docx.enc.json
py crypto_tool.py decrypt -i report.docx.enc.json -o report-restored.docx

# Binary file or image
py crypto_tool.py encrypt -a AES -i photo.png -o photo.png.enc.json
py crypto_tool.py decrypt -i photo.png.enc.json -o photo-restored.png

# Demonstrate the legacy algorithms
py crypto_tool.py encrypt -a DES -i data.bin -o data.des.json
py crypto_tool.py encrypt -a RC4 -i data.bin -o data.rc4.json
```

When decrypting without `--output`, the program prints the result only if it is
valid UTF-8. Always use `--output` for DOCX, PDF, images, ZIP archives, or
binary data.

## Testing

```powershell
py -m unittest -v
```

The tests cover binary-data round trips for all three algorithms and rejection
of an incorrect password.
