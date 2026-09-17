# Script Introduction

This is a Flask-based **universal encryption/decryption middleware** designed to work with AutoDecoder, Burp plugins, and similar tools to encrypt, decrypt, encode, and decode specified parameters in HTTP requests/responses. It supports five major algorithm categories: **symmetric encryption, asymmetric encryption, Chinese national cryptography (SM series), hashing, and HMAC**. It also supports multi-parameter, multi-layer encryption/decryption, and multiple encoding chains, with automatic detection of JSON and form data formats.

<a href="README.md"><img src="https://img.shields.io/badge/-简体中文-red.svg" alt="简体中文"></a>
<a href="README_EN.md"><img src="https://img.shields.io/badge/-English-blue.svg" alt="English"></a>

---

## 1. Overall Structure

```text
Configuration (algorithm selection / global switches / keys / parameter config)
        ↓
Algorithm Layer
    ├─ Symmetric: AES / DES / 3DES / Blowfish / CAST / RC2 / RC4 / SM4
    ├─ Asymmetric: RSA / SM2
    ├─ Hashing: MD5 / SHA1 / SHA256 / SHA512 / SM3
    └─ HMAC: hmac-md5 / hmac-sha1 / hmac-sha256 / hmac-sha512
        ↓
Encoding Layer (none / url / base64 / hex)
        ↓
Layer Parsing & Multi-layer Encryption/Decryption (multi_encrypt / multi_decrypt)
        ↓
JSON Processing / Form Processing
        ↓
Unified Entry: process_data
        ↓
Flask Routes: /encode and /decode
```

---

## 2. Supported Algorithms

### 2.1 Symmetric Encryption

| Algorithm | Config Key | Dependency | Key Length |
|---|---|---|---|
| AES | `aes` | `pycryptodome` | 16 / 24 / 32 bytes |
| DES | `des` | `pycryptodome` | 8 bytes |
| 3DES (DESede) | `3des` | `pycryptodome` | 16 / 24 bytes |
| Blowfish | `blowfish` | `pycryptodome` | 4 ~ 56 bytes |
| CAST | `cast` | `pycryptodome` | 5 ~ 16 bytes |
| RC2 | `rc2` | `pycryptodome` | 5 ~ 16 bytes |
| RC4 (stream) | `rc4` | `pycryptodome` | 5 ~ 256 bytes |
| SM4 | `sm4` | `gmssl` + `pycryptodome` (padding) | 16 bytes |

Supports `CBC` / `ECB` modes with `pkcs7` padding. RC4 is a stream cipher and requires no IV or padding.

### 2.2 Asymmetric Encryption

| Algorithm | Config Key | Dependency | Notes |
|---|---|---|---|
| RSA | `rsa` | `pycryptodome` | PKCS1 / OAEP, auto chunking |
| SM2 | `sm2` | `gmssl` | C1C2C3 / C1C3C2 |

### 2.3 Hashing (One-way)

| Algorithm | Config Key | Dependency |
|---|---|---|
| MD5 | `md5` | Built-in `hashlib` |
| SHA-1 | `sha1` | Built-in `hashlib` |
| SHA-256 | `sha256` | Built-in `hashlib` |
| SHA-512 | `sha512` | Built-in `hashlib` |
| SM3 | `sm3` | `gmssl` |

### 2.4 HMAC (One-way)

| Algorithm | Config Key | Dependency |
|---|---|---|
| HMAC-MD5 | `hmac-md5` | Built-in `hmac` + `hashlib` |
| HMAC-SHA1 | `hmac-sha1` | Built-in `hmac` + `hashlib` |
| HMAC-SHA256 | `hmac-sha256` | Built-in `hmac` + `hashlib` |
| HMAC-SHA512 | `hmac-sha512` | Built-in `hmac` + `hashlib` |

HMAC key is configured in `HMAC_CONFIG["key"]`.

### 2.5 Pure Encoding

`none`: No encryption/decryption, encoding chain only.

---

## 3. Installation

```bash
# Required
pip install flask

# Symmetric encryption + RSA + hash padding
pip install pycryptodome

# Chinese national cryptography (SM2 / SM3 / SM4)
pip install gmssl
```

| Algorithm | Required Library |
|---|---|
| AES / DES / 3DES / Blowfish / CAST / RC2 / RC4 | `pycryptodome` |
| RSA | `pycryptodome` |
| SM4 (with pkcs7 padding) | `pycryptodome` + `gmssl` |
| SM2 | `gmssl` |
| SM3 | `gmssl` |
| MD5 / SHA1 / SHA256 / SHA512 | Python built-in, no installation |
| HMAC-MD5 / SHA1 / SHA256 / SHA512 | Python built-in, no installation |

---

## 4. External Interfaces

The script listens on `0.0.0.0:8888` and provides two endpoints:

| Endpoint | Method | Purpose |
|---|---|---|
| `/encode` | POST | Encrypt parameters |
| `/decode` | POST | Decrypt parameters |

Both endpoints accept three form fields:

| Field | Description |
|---|---|
| `dataBody` | Raw request body or response body |
| `dataHeaders` | Raw request headers |
| `requestorresponse` | `"request"` or `"response"` |

Return rules:

- `requestorresponse == "request"`: returns `headers + \r\n\r\n\r\n\r\n + processed body`
- Otherwise: returns only the processed body

---

## 5. Configuration Details

### 5.1 `ALGORITHM`: Global Default Algorithm

```python
ALGORITHM = "none"   # specific algorithm name or "none"
```

- Specific algorithm: all layers without an explicit algorithm use it.
- Set to `"none"`: auto-detects which algorithm config has `enabled=True`, in the order **AES → DES → 3DES → SM4 → Blowfish → CAST → RC2 → RC4 → RSA → SM2**.

Priority:

```text
Layer explicit algorithm (including "none")  >  Global ALGORITHM  >  Auto-detect enabled
```

### 5.2 `DEBUG_PRINT`: Print Plaintext/Ciphertext

```python
DEBUG_PRINT = True
```

Can be enabled during security testing; recommended to disable in multi-user or log-collected environments.

### 5.3 `FORM_VALUE_URL_CODED`: URL Encoding Contract for Form Values

```python
FORM_VALUE_URL_CODED = True
```

- `True` (default): client URL-encodes the value of `dataBody`; the script `quote`s on encryption and `unquote`s on decryption.
- `False`: client does no extra encoding; the script does none on either side.

Both sides must match, otherwise encryption/decryption will be asymmetric.

### 5.4 Algorithm Configuration

Each algorithm has its own configuration dictionary, for example:

```python
AES_CONFIG = {
    "enabled": True,
    "key": b"1234567890123456",
    "iv": b"1234567890123456",
    "mode": "CBC",              # "CBC" / "ECB"
    "padding": "pkcs7",         # "pkcs7" / "none"
}
```

DES, 3DES, Blowfish, CAST, RC2, SM4 have similar structures with different key and IV lengths.

RC4 only needs `key`:

```python
RC4_CONFIG = {
    "enabled": False,
    "key": b"1234567890123456",
}
```

RSA and SM2 use key pairs:

```python
RSA_CONFIG = {
    "enabled": False,
    "public_key": "",       # PEM string
    "private_key": "",
    "padding": "pkcs1",     # "pkcs1" / "oaep"
}

SM2_CONFIG = {
    "enabled": False,
    "public_key": "",       # hex, 128 chars (X||Y)
    "private_key": "",      # hex, 64 chars
    "mode": 1,              # 0=C1C2C3, 1=C1C3C2
}
```

HMAC configuration:

```python
HMAC_CONFIG = {
    "enabled": False,
    "key": b"shared-secret",
    "hash_algorithm": "sha256",   # "md5" / "sha1" / "sha256" / "sha512"
}
```

### 5.5 `TARGET_PARAMS`: Parameters to Process

Two syntaxes are supported.

**Single-layer syntax (simple cases)**:

```python
TARGET_PARAMS = {
    "password": {
        "algorithm": "aes",
        "encrypt_encodings": ["base64"],
        "decrypt_decodings": ["base64"],
    },
}
```

**Multi-layer syntax (multiple encryption rounds)**:

```python
TARGET_PARAMS = {
    "encryptedData": {
        "layers": [
            # Inner layer: executed first
            {"algorithm": "aes",
             "encrypt_encodings": ["none"],
             "decrypt_decodings": ["none"]},
            # Outer layer: executed later
            {"algorithm": "rsa",
             "encrypt_encodings": ["base64"],
             "decrypt_decodings": ["base64"]},
        ],
    },
}
```

Meaning of `algorithm` inside a `layer`:

| Value | Meaning |
|---|---|
| Omitted / `None` | Use global `ALGORITHM` |
| Specific algorithm name (e.g. `"aes"`, `"des"`, `"rsa"`) | Force this algorithm |
| `"none"` | Skip encryption/decryption, only run encoding/decoding chain |

Available encodings:

| Encoding | On Encryption | On Decryption |
|---|---|---|
| `"none"` | Unchanged | Unchanged |
| `"url"` | `quote(data, safe='')` | `unquote(data)` |
| `"base64"` | Base64 encode | Base64 decode |
| `"hex"` | Hex encode | Hex decode |

### 5.6 `ENABLE_DEFAULT` and `DEFAULT_LAYERS`

For parameters not listed in `TARGET_PARAMS` that should also be processed:

```python
ENABLE_DEFAULT = True
DEFAULT_LAYERS = [
    {"algorithm": None, "encrypt_encodings": ["none"], "decrypt_decodings": ["none"]},
]
```

`algorithm` as `None` means use global `ALGORITHM`.

---

## 6. Multi-layer Execution Order

**Encryption**: the `layers` list runs **from inner to outer**, i.e. index 0 first.

```text
Plaintext
  → Layer 0 encrypt → Layer 0 encode
  → Layer 1 encrypt → Layer 1 encode
  → Final ciphertext
```

**Decryption**: the `layers` list runs **from outer to inner**, i.e. index 1 first.

```text
Final ciphertext
  → Layer 1 decode → Layer 1 decrypt
  → Layer 0 decode → Layer 0 decrypt
  → Plaintext
```

Mnemonic: **`layers` order = encryption order; decryption is the reverse.**

---

## 7. Data Format Detection

`process_data` automatically determines the type of `dataBody`:

1. **Parsable as a JSON object**: JSON processing, only top-level string values are processed.
2. **Parsable as a JSON array or scalar**: returned as-is, no processing.
3. **Otherwise**: form processing, split by `&`, find items whose `key` is in `TARGET_PARAMS`, process only the `value`.

---

## 8. Usage Steps

### 8.1 Install Dependencies

```bash
pip install flask pycryptodome gmssl
```

Unused algorithm libraries can be omitted; the script only checks them when the corresponding algorithm is invoked.

### 8.2 Configure Algorithms

Fill in keys, IVs, modes, padding, public/private keys, HMAC keys, etc., according to the target system.

### 8.3 Configure Target Parameters

Write the parameter names and encoding chains to be processed into `TARGET_PARAMS`.

### 8.4 Start the Service

```bash
python run.py
```

### 8.5 Integrate with AutoDecoder / Burp

- Encryption endpoint: `http://127.0.0.1:8888/encode`
- Decryption endpoint: `http://127.0.0.1:8888/decode`
- Request fields: `dataBody` / `dataHeaders` / `requestorresponse`

---

## 9. Typical Configuration Examples

### Example 1: Single-parameter AES + Base64

```python
ALGORITHM = "aes"
TARGET_PARAMS = {
    "encryptedData": {
        "algorithm": "aes",
        "encrypt_encodings": ["base64"],
        "decrypt_decodings": ["base64"],
    },
}
```

### Example 2: DES Encryption

```python
DES_CONFIG = {
    "enabled": True,
    "key": b"12345678",
    "iv": b"12345678",
    "mode": "CBC",
    "padding": "pkcs7",
}
ALGORITHM = "des"
```

### Example 3: 3DES Encryption

```python
DES3_CONFIG = {
    "enabled": True,
    "key": b"123456789012345678901234",
    "iv": b"12345678",
    "mode": "CBC",
    "padding": "pkcs7",
}
ALGORITHM = "3des"
```

### Example 4: Multiple Parameters with Different Algorithms

```python
TARGET_PARAMS = {
    "encryptedData": {
        "algorithm": "aes",
        "encrypt_encodings": ["url"],
        "decrypt_decodings": ["url"],
    },
    "password": {
        "algorithm": "rsa",
        "encrypt_encodings": ["base64"],
        "decrypt_decodings": ["base64"],
    },
}
```

### Example 5: Multi-layer AES → RSA → Base64

```python
TARGET_PARAMS = {
    "encryptedData": {
        "layers": [
            {"algorithm": "aes",
             "encrypt_encodings": ["none"],
             "decrypt_decodings": ["none"]},
            {"algorithm": "rsa",
             "encrypt_encodings": ["base64"],
             "decrypt_decodings": ["base64"]},
        ],
    },
}
```

### Example 6: JSON Format

`dataBody`:

```json
{"encryptedData": "xxxxx", "username": "admin"}
```

The script automatically recognizes JSON, processes only `encryptedData`, and keeps `username` unchanged.

### Example 7: Pure Encoding without Encryption/Decryption

```python
TARGET_PARAMS = {
    "token": {
        "layers": [
            {"algorithm": "none",
             "encrypt_encodings": ["base64", "url"],
             "decrypt_decodings": ["url", "base64"]},
        ],
    },
}
```

### Example 8: HMAC-SHA256 Signature

```python
HMAC_CONFIG = {
    "enabled": True,
    "key": b"shared-secret",
    "hash_algorithm": "sha256",
}
TARGET_PARAMS = {
    "sign": {
        "algorithm": "hmac-sha256",
        "encrypt_encodings": ["none"],
        "decrypt_decodings": ["none"],
    },
}
```

> HMAC is one-way: `/encode` can generate a signature, while `/decode` raises `NotImplementedError`.

---

## 10. Special Notes on Hashing and HMAC

Hashing (MD5/SHA/SM3) and HMAC are **one-way algorithms**:

| Algorithm | Encrypt (compute digest) | Decrypt |
|---|---|---|
| MD5 / SHA-1 / SHA-256 / SHA-512 / SM3 | ✅ | ❌ Irreversible |
| HMAC-MD5 / HMAC-SHA256 / ... | ✅ | ❌ Irreversible |

If a parameter is configured with hashing or HMAC in `TARGET_PARAMS`, `/decode` will directly raise `NotImplementedError`, which is expected.

---

## 11. Limitations and Notes

### Functional Limitations

1. **Only form data and JSON objects are processed**. `/decode` reads from `request.form.get('dataBody')`; the client must submit with `application/x-www-form-urlencoded`.
2. **JSON only processes top-level string values**. Nested objects like `{"data": {"token": "xxx"}}` are not processed.
3. **JSON arrays and scalars are returned as-is**, without processing.
4. **HMAC-SM3 is not implemented yet** and raises `NotImplementedError`.

### Security Notes

1. **Keys and IVs must match the target system**, otherwise `Padding is incorrect` or garbled decryption will occur.
2. **`DEBUG_PRINT` is enabled by default and prints plaintext**; recommended to disable in multi-user environments.
3. **Disable `app.debug` in production**.
4. For legally authorized security testing only.

### Encoding Conventions

1. `url` in the encoding chain uses `quote(data, safe='')` / `unquote(data)`, strictly symmetric.
2. Form-level URL encoding is controlled by `FORM_VALUE_URL_CODED`, decoupled from the encoding chain.
3. `layers` order = encryption order; decryption runs in reverse.

---

## 12. One-sentence Summary

**Modify the top configuration, start the service, and integrate with your tool.** Whether it is AES, DES, 3DES, SM4, RSA, SM2, or MD5, SHA, SM3, HMAC; whether single-layer or multi-layer, single-parameter or multi-parameter, JSON or form — all can be described via `TARGET_PARAMS` plus `layers`, and the script will automatically encrypt/decrypt according to the rules. The dependency libraries for all algorithms are annotated in the configuration section; install as needed.
