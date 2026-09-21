<a href="README.md"><img src="https://img.shields.io/badge/-简体中文-red.svg" alt="简体中文"></a>
<a href="README_EN.md"><img src="https://img.shields.io/badge/-English-blue.svg" alt="English"></a>

# Introduction

Interactive Crypto Tool is a Flask-based **interactive encryption/decryption configuration console**, designed to work with AutoDecoder, Burp plugins, and similar tools to encrypt, decrypt, encode, and decode specified parameters in HTTP requests/responses.

Unlike traditional script templates, it turns "configuration" from editing code into **running a terminal menu**: algorithms, keys, parameters, and encoding chains are all configured through a visual menu and automatically persisted to a JSON file, which is auto-loaded on the next start.

It supports five major algorithm categories: **symmetric encryption, asymmetric encryption, Chinese national cryptography (SM series), hashing, and HMAC**. It also supports multi-parameter, multi-layer encryption/decryption, and multiple encoding chains, with automatic detection of JSON and form data formats.

---

## 1. Overall Structure

```text
Interactive Terminal Layer (i18n / color menu / input prompts)
        ↓
Config Persistence Layer (crypto_tool_config.json, auto-save / auto-load)
        ↓
Algorithm Layer
    ├─ Symmetric: AES / DES / 3DES / Blowfish / CAST / RC2 / RC4 / SM4
    ├─ Asymmetric: RSA / SM2
    ├─ Hashing: MD5 / SHA1 / SHA256 / SHA512 / SM3
    └─ HMAC: hmac-md5 / hmac-sha1 / hmac-sha256 / hmac-sha512
        ↓
Encoding Layer (none / url / base64 / base64url / hex / base32 / html / unicode)
        ↓
Multi-layer Engine (multi_encrypt / multi_decrypt)
        ↓
Body Processing (JSON / form / auto)
        ↓
Flask Routes /encode and /decode
```

---

## 2. Key Features

### 2.1 Interactive Configuration — No More Code Editing

After starting the script, a colorful terminal menu is shown. All configuration is done through numeric options, without editing source code:

- **Menu 0**: One-click install / repair environment
- **Menu 1**: Configure algorithms
- **Menu 2**: Data format (auto / JSON / form)
- **Menu 3**: Configure parameters (name + layers + encoding chains)
- **Menu 4**: Advanced settings (form URL coding, default params, debug output, listen address, config file manager)
- **Menu 5**: Preview pipeline + live round-trip test
- **Menu 6**: Start server
- **Menu a**: Switch language (Chinese / English)

### 2.2 Auto-Persisted Config

All configuration is automatically saved to `crypto_tool_config.json` in the same directory and auto-loaded on next start. The path can be overridden with the `CRYPTO_TOOL_CONFIG` environment variable.

### 2.3 Multi-language

Menu `a` switches between Chinese and English at any time. The choice is also saved to the config file.

### 2.4 One-click Dependency Install

Menu `0` detects Flask / pycryptodome / gmssl and supports selecting a pip mirror (official / Tsinghua / Aliyun / Tencent / none) for one-click install.

### 2.5 Multi-layer Encryption

A single parameter can be configured with a multi-layer chain, e.g. "inner AES → outer RSA". Each layer can also have its own before-enc / after-enc encoding chains.

### 2.6 Base64 Compatibility Fix

To handle the common AutoDecoder issue where `+` in Base64 is decoded as a space, the `_b64d` function is compatible: it restores spaces to `+`, supports URL-safe variants, pads missing `=`, and strips whitespace/newlines.

### 2.7 Live Preview and Round-trip Test

Menu 5 draws the encryption/decryption pipeline for each parameter and provides a round-trip test to verify the configuration is symmetric.

---

## 3. Supported Algorithms

### 3.1 Symmetric Encryption

| Algorithm | Config Key | Dependency | Key Length | Modes |
|---|---|---|---|---|
| AES | `aes` | `pycryptodome` | 16 / 24 / 32 bytes | CBC / ECB / CFB / OFB / CTR / GCM |
| DES | `des` | `pycryptodome` | 8 bytes | CBC / ECB / CFB / OFB / CTR |
| 3DES | `3des` | `pycryptodome` | 16 / 24 bytes | CBC / ECB / CFB / OFB / CTR |
| Blowfish | `blowfish` | `pycryptodome` | 4 ~ 56 bytes | CBC / ECB / CFB / OFB / CTR |
| CAST | `cast` | `pycryptodome` | 5 ~ 16 bytes | CBC / ECB / CFB / OFB / CTR |
| RC2 | `rc2` | `pycryptodome` | 5 ~ 16 bytes | CBC / ECB / CFB / OFB / CTR |
| RC4 | `rc4` | `pycryptodome` | 5 ~ 256 bytes | Stream cipher, no IV / no padding |
| SM4 | `sm4` | `gmssl` + `pycryptodome` | 16 bytes | CBC / ECB |

Padding options: `pkcs7` / `pkcs5` / `zero` / `iso7816` / `ansiX923` / `none`.

### 3.2 Asymmetric Encryption

| Algorithm | Config Key | Dependency | Notes |
|---|---|---|---|
| RSA | `rsa` | `pycryptodome` | PKCS1_v1_5 / OAEP (sha1/sha256/sha384/sha512), auto chunking |
| SM2 | `sm2` | `gmssl` | C1C3C2 / C1C2C3 |

RSA accepts PEM-formatted keys or pure Base64 content; the script tries to parse automatically.

### 3.3 Hashing (One-way)

| Algorithm | Config Key | Dependency |
|---|---|---|
| MD5 | `md5` | Built-in `hashlib` |
| SHA-1 | `sha1` | Built-in `hashlib` |
| SHA-256 | `sha256` | Built-in `hashlib` |
| SHA-512 | `sha512` | Built-in `hashlib` |
| SM3 | `sm3` | `gmssl` |

### 3.4 HMAC (One-way)

| Algorithm | Config Key | Dependency |
|---|---|---|
| HMAC-MD5 | `hmac-md5` | Built-in `hmac` + `hashlib` |
| HMAC-SHA1 | `hmac-sha1` | Built-in `hmac` + `hashlib` |
| HMAC-SHA256 | `hmac-sha256` | Built-in `hmac` + `hashlib` |
| HMAC-SHA512 | `hmac-sha512` | Built-in `hmac` + `hashlib` |

### 3.5 Pure Encoding

Select "None" as the algorithm to only run the encoding chain without encryption.

Supported encodings: `none` / `url` / `base64` / `base64url` / `hex` / `base32` / `html` / `unicode`.

---

## 4. Installation

The script includes a one-click install menu (menu 0) that detects the following dependencies:

| Dependency | Purpose |
|---|---|
| `flask` | Web framework (for /encode and /decode endpoints) |
| `pycryptodome` | AES / DES / 3DES / Blowfish / CAST / RC2 / RC4 / RSA and various paddings |
| `gmssl` | SM2 / SM3 / SM4 Chinese national algorithms |

Manual install:

```bash
pip install flask pycryptodome gmssl
```

Unused libraries can be omitted; the script only checks them when the corresponding algorithm is invoked.

---

## 5. External Interfaces

The script listens on `0.0.0.0:8888` (configurable in menu 4) and provides two endpoints:

| Endpoint | Method | Purpose |
|---|---|---|
| `/encode` | POST | Encrypt parameters |
| `/decode` | POST | Decrypt parameters |

Both accept three form fields:

| Field | Description |
|---|---|
| `dataBody` | Raw request or response body |
| `dataHeaders` | Raw request headers |
| `requestorresponse` | `"request"` or `"response"` |

Return rules:

- `requestorresponse == "request"`: returns `headers + \r\n\r\n\r\n\r\n + processed body`
- Otherwise: returns only the processed body

### Integrating with AutoDecoder / Burp

- Encryption: `http://127.0.0.1:8888/encode`
- Decryption: `http://127.0.0.1:8888/decode`

> Tip: even if the server listens on `0.0.0.0`, using `127.0.0.1` in AutoDecoder works.

---

## 6. Quick Start

### 6.1 Start the Script

```bash
python Template_v2.0.py
```

The main menu appears. If dependencies are missing, pick `0` first.

### 6.2 Configure Algorithms (Menu 1)

Algorithms are grouped by category, showing their dependency and configuration status.

- Pick any `○ unconfigured` algorithm to enter details
- Edit key / IV / mode / padding / public key / private key, etc.
- Use `r` to restore sample defaults, `c` to clear

### 6.3 Configure Data Format (Menu 2)

Choose `auto` / `json` / `form`.

### 6.4 Configure Parameters (Menu 3)

- Add a parameter (e.g. `password` / `token` / `encryptedData`)
- Add one or more layers to it
- Each layer can have its own algorithm and before/after encoding chains

### 6.5 Advanced Settings (Menu 4)

- Auto URL encode/decode form values (`FORM_VALUE_URL_CODED`)
- Default handling for unconfigured params (`ENABLE_DEFAULT` + `DEFAULT_LAYERS`)
- Debug output toggle
- Listen host / port
- Config file manager (save / load / factory reset / delete)

### 6.6 Preview Pipeline (Menu 5)

Draws the encryption/decryption pipeline and runs a round-trip test.

### 6.7 Start Server (Menu 6)

Starts the Flask server, prints all reachable URLs, and stops on Enter.

---

## 7. Encoding Chains and Layer Order

### 7.1 Encodings

| Encoding | On Encryption | On Decryption |
|---|---|---|
| `none` | Unchanged | Unchanged |
| `url` | `quote(data, safe='')` | `unquote(data)` |
| `base64` | Base64 encode | Base64 decode |
| `base64url` | Base64URL encode (without `=`) | Base64URL decode |
| `hex` | Hex encode | Hex decode |
| `base32` | Base32 encode | Base32 decode |
| `html` | HTML escape | HTML unescape |
| `unicode` | Unicode escape | Unicode unescape |

### 7.2 Multi-layer Order

**Encryption**: layers run **top-down**, i.e. index 0 first.

```text
Plaintext
  → Layer 0: encode(pre) → encrypt → encode(post)
  → Layer 1: encode(pre) → encrypt → encode(post)
  → Final ciphertext
```

**Decryption**: layers run **bottom-up**, i.e. the last layer first.

```text
Final ciphertext
  → Layer 1: decode(post) → decrypt → decode(pre)
  → Layer 0: decode(post) → decrypt → decode(pre)
  → Plaintext
```

Mnemonic: **layer order = encryption order; decryption is the reverse.**

---

## 8. Data Format Detection

`process_payload` decides based on `data_mode`:

1. **`auto`**: try JSON first, fall back to form.
2. **`json`**: force JSON, only top-level string values are processed.
3. **`form`**: force form, split by `&`, process only values whose `key` is in the parameter list.

JSON arrays and scalars are returned as-is.

---

## 9. Config File

Default path: `crypto_tool_config.json` in the script's directory.

Override with an environment variable:

```bash
export CRYPTO_TOOL_CONFIG=/path/to/your_config.json
```

Structure:

```json
{
  "_meta": {
    "tool": "interactive-crypto-tool",
    "version": "1.3.0",
    "saved_at": "2024-01-01 12:00:00"
  },
  "lang": "zh",
  "settings": { ... },
  "algo": { ... },
  "params": { ... }
}
```

Any change is auto-saved, and a final save happens on exit.

---

## 10. Typical Scenarios

### Scenario 1: Single-param AES-CBC + Base64

1. Menu 1 → AES → fill Key / IV → CBC / pkcs7
2. Menu 3 → add `encryptedData` → add one layer → AES → after-enc = `base64`
3. Menu 6 → start server
4. Use `http://127.0.0.1:8888/encode` and `/decode` in AutoDecoder

### Scenario 2: Multi-layer AES → RSA

Menu 3 → add two layers:
- Layer 1: AES, no before/after encodings
- Layer 2: RSA, after-enc = `base64`

### Scenario 3: Encoding Only

Menu 3 → add one layer → algorithm = None → after-enc = `base64,url` (decryption reverses automatically)

### Scenario 4: HMAC-SHA256 Signature

Menu 1 → configure HMAC-SHA256 key
Menu 3 → add `sign` → one layer → HMAC-SHA256

> HMAC is one-way; `/encode` generates a signature and `/decode` raises `NotImplementedError`, which is expected.

### Scenario 5: JSON Body

If the body is:

```json
{"encryptedData": "xxxxx", "username": "admin"}
```

Choose `json` or `auto` in menu 2; the script processes only `encryptedData` and keeps `username` unchanged.

---

## 11. Hashing and HMAC

Hashing and HMAC are **one-way algorithms**:

| Algorithm | Encrypt (digest) | Decrypt |
|---|---|---|
| MD5 / SHA-1 / SHA-256 / SHA-512 / SM3 | ✅ | ❌ Irreversible |
| HMAC-MD5 / HMAC-SHA256 / ... | ✅ | ❌ Irreversible |

If a parameter is configured with hashing or HMAC, `/decode` will raise `NotImplementedError`.

---

## 12. Limitations and Notes

### Functional

1. **Only form data and JSON objects are processed**. `/decode` reads from `request.form.get('dataBody')`; the client must submit with `application/x-www-form-urlencoded`.
2. **JSON only processes top-level string values**. Nested objects are not processed.
3. **JSON arrays and scalars are returned as-is**.
4. **HMAC-SM3 is not implemented**.

### Security

1. **Keys and IVs must match the target system**, otherwise `Padding is incorrect` or garbled output occurs.
2. **`DEBUG_PRINT` is enabled by default and prints plaintext**; disable in multi-user environments.
3. **Do not enable debug in production** (Flask debug is off by default in the script).
4. **For legally authorized security testing only**.

### FAQ

**Q: `Padding is incorrect` on decryption?**

A: Check Key / IV / Mode / Padding against the target system. The script prints the ciphertext length, decrypted length, and last byte in the exception message for easy diagnosis.

**Q: `+` in Base64 becomes a space and decryption fails?**

A: `_b64d` already handles this — it restores spaces to `+`, supports URL-safe variants, and pads missing `=`.

**Q: Where is the config file?**

A: `crypto_tool_config.json` in the same directory, or the path specified by `CRYPTO_TOOL_CONFIG`.

**Q: How to clear the config?**

A: Menu 4 → Config file manager → Factory reset, or delete `crypto_tool_config.json`.

---

## 13. One-sentence Summary

**Run it → configure in the menu → start server → integrate with your tool.**  
Whether it is AES / DES / 3DES / SM4 / RSA / SM2, or MD5 / SHA / SM3 / HMAC; single-layer or multi-layer, single-parameter or multi-parameter, JSON or form — everything is configurable through the visual menu, and the script applies the rules automatically. The config is saved on the fly and auto-loaded on next start.
