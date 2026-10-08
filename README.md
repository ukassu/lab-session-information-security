# AES, DES, and RC4 Encryption

A simple Python program for encrypting text and **any file as bytes**:
DOCX, PDF, images, ZIP archives, binary files, and more. Encrypted data is
stored as a readable JSON envelope in the `ciphertexts/` folder, containing the
algorithm, the original filename, the salt, the IV, and the ciphertext.

> **Security warning:** this tool is for learning. There is no integrity check
> (MAC), so tampering is not detected and a wrong password is not always
> reported. DES and RC4 are insecure/deprecated. Do not use it for real data.

## Installation

Python 3.10+ is recommended.

```powershell
py -m pip install -r requirements.txt
```

## CLI usage

The script must be run with a command:

```powershell
py crypto_tool.py <encrypt|decrypt> [options]
```

Running `py crypto_tool.py` without a command prints the help. Use
`py crypto_tool.py encrypt -h` or `py crypto_tool.py decrypt -h` for the options
of each command.

The password is typed at the prompt (it is visible while typing) or supplied
with `--password`. When encrypting, the password is asked twice to confirm it.

### Encrypt

| Option | Description |
| --- | --- |
| `-i`, `--input FILE` | File to encrypt |
| `-t`, `--text TEXT` | UTF-8 text to encrypt (use either `-i` or `-t`) |
| `-a`, `--algorithm` | `AES` (default), `DES`, or `RC4`; case-insensitive |
| `-o`, `--output NAME` | Envelope filename inside `ciphertexts/` (default: `<name>.<alg>.json`) |
| `--password` | Password instead of the prompt |

Envelopes are always saved to `ciphertexts/` next to the script; the folder is
created if missing and an existing file with the same name is overwritten.

```powershell
py crypto_tool.py encrypt -t "Hello world"                    # ciphertexts/text.txt.aes.json
py crypto_tool.py encrypt -a DES -i report.docx               # ciphertexts/report.docx.des.json
py crypto_tool.py encrypt -a RC4 -i photo.png -o holiday      # ciphertexts/holiday.json
```

### Decrypt

| Option | Description |
| --- | --- |
| `-i`, `--input FILE` | Envelope to decrypt; a bare filename is also looked up in `ciphertexts/` |
| `-o`, `--output FILE` | Where to write the result |
| `--password` | Password instead of the prompt |

Without `-o`, text is printed to the terminal; binary data (DOCX, PDF, images,
...) is written to the current folder under its original filename.

```powershell
py crypto_tool.py decrypt -i text.txt.aes.json                # prints "Hello world"
py crypto_tool.py decrypt -i report.docx.des.json             # writes report.docx
py crypto_tool.py decrypt -i holiday.json -o restored.png
```

## Envelope format

```json
{
    "algorithm": "AES",
    "name": "text.txt",
    "salt": "zvwVwkdBxQggd23UcZcfZA==",
    "iv": "uAvkvuALq30rtgM392lk8A==",
    "ciphertext": "IjP0COM/XEh1/5lc9oLZ7w=="
}
```

All binary values are Base64. RC4 envelopes have no `iv`.

## Algorithms

- **AES**: AES-256-CBC with PKCS#7 padding.
- **DES**: DES-CBC with PKCS#7 padding (legacy, not secure).
- **RC4**: RC4 stream cipher (legacy, not secure).

Passwords are converted into keys using PBKDF2-HMAC-SHA256 with a random
16-byte salt and 600,000 iterations. Each encryption generates a new salt and
IV.

Because there is no MAC, a wrong password is only detected for AES/DES when
the PKCS#7 padding turns out invalid (about 255 times in 256). A wrong RC4
password is never detected and simply produces garbage.

## Python API

```python
from pathlib import Path
from crypto_tool import decryptbytes, encryptbytes

envelope = encryptbytes("Hello world".encode("utf-8"), "password", "AES", "message.txt")
Path("ciphertexts/message.txt.aes.json").write_text(envelope, encoding="utf-8")

plain, original_name = decryptbytes(Path("ciphertexts/message.txt.aes.json").read_bytes(), "password")
Path(original_name).write_bytes(plain)
```

`encryptbytes(data, password, algorithm, name)` returns the JSON envelope as a
string. `decryptbytes(envelope, password)` accepts a string or bytes and returns
`(data, original_name)`.

## Testing

```powershell
py -m unittest -v
```

The tests cover binary-data round trips for all three algorithms and an
incorrect password.
