# AES, DES, and RC4 Encryption

A simple Python program for encrypting text and **any file as bytes**:
DOCX, PDF, images, ZIP archives, binary files, and more. Encrypted data is
stored as a readable JSON envelope in the `ciphertexts/` folder, containing the
algorithm, the original filename, the salt, the IV, and the ciphertext.

> **Security warning:** this tool is for learning. There is no integrity check
> (MAC), so tampering is not detected and a wrong password is not always
> reported. DES and RC4 are insecure/deprecated. Do not use it for real data.


## CLI usage

The script must be run with a command:

```powershell
python .\crypto_tool.py <encrypt|decrypt> [options]
```

Perintah dapat dijalankan dari PowerShell setelah `.venv` diaktifkan. Menjalankan
`python .\crypto_tool.py` tanpa command akan menampilkan bantuan. Gunakan
`python .\crypto_tool.py encrypt -h` atau
`python .\crypto_tool.py decrypt -h` untuk melihat opsi masing-masing command.

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

Envelopes selalu disimpan ke `ciphertexts/` di sebelah file script. Folder
tersebut dibuat otomatis jika belum ada. File dengan nama yang sama akan
ditimpa.

```powershell
python .\crypto_tool.py encrypt -t "Hello world" -a AES -o hello-aes
# ciphertexts\hello-aes.json

python .\crypto_tool.py encrypt `
  -i ".\assets\Group 1_Report.pdf" -a DES -o report-des
# ciphertexts\report-des.json

python .\crypto_tool.py encrypt `
  -i ".\assets\313081528_1148997432708747_5910995952251052677_n.jpg" `
  -a RC4 -o image-rc4
# ciphertexts\image-rc4.json

python .\crypto_tool.py encrypt `
  -i ".\assets\hallo.txt" -a AES -o hallo-aes
# ciphertexts\hallo-aes.json
```

Gunakan `AES`, `DES`, atau `RC4` pada opsi `-a`. AES direkomendasikan untuk
demonstrasi utama; DES dan RC4 hanya digunakan untuk perbandingan algoritma
legacy.

### Decrypt

| Option | Description |
| --- | --- |
| `-i`, `--input FILE` | Envelope to decrypt; a bare filename is also looked up in `ciphertexts/` |
| `-o`, `--output FILE` | Where to write the result |
| `--password` | Password instead of the prompt |

Untuk menyimpan semua hasil decrypt di workspace ini, buat folder `results`
terlebih dahulu:

```powershell
New-Item -ItemType Directory -Force .\results
```

Opsi `-o` menentukan lokasi file hasil decrypt. Tanpa `-o`, teks dicetak ke
terminal, sedangkan file biner ditulis ke folder saat ini menggunakan nama
aslinya.

```powershell
python .\crypto_tool.py decrypt `
  -i .\ciphertexts\hello-aes.json -o .\results\hello-aes.txt

python .\crypto_tool.py decrypt `
  -i .\ciphertexts\report-des.json `
  -o ".\results\Group 1_Report.pdf"

python .\crypto_tool.py decrypt `
  -i .\ciphertexts\image-rc4.json -o .\results\image-rc4.jpg

python .\crypto_tool.py decrypt `
  -i .\ciphertexts\hallo-aes.json -o .\results\hallo-aes.txt
```

Saat decrypt, algoritma tidak perlu ditulis lagi dengan `-a`; program membaca
algoritma dari envelope JSON. Password harus sama dengan password saat encrypt.
Nama file ciphertext juga dapat diberikan tanpa path karena program otomatis
mencarinya di folder `ciphertexts/`.

Untuk memeriksa file yang dihasilkan:

```powershell
Get-ChildItem .\ciphertexts
Get-ChildItem .\results
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
