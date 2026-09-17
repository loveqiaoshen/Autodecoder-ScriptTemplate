# -*- coding:utf-8 -*-
# author:f0ngf0ng

from flask import Flask, Response, request
from urllib.parse import quote, unquote
import base64
import binascii
import json
import hmac as _hmac
import hashlib

# ==================================================================
# ============================ 算法选择 ============================
# ==================================================================
# 全局默认算法，当某层未指定 algorithm（即 None）时使用
#
# 【对称加密】"aes" | "des" | "3des" | "sm4" | "blowfish" | "cast" | "rc2" | "rc4"
# 【非对称加密】"rsa" | "sm2"
# 【哈希（不可逆）】"md5" | "sha1" | "sha256" | "sha512" | "sm3"
# 【HMAC】"hmac-md5" | "hmac-sha1" | "hmac-sha256" | "hmac-sha512" | "hmac-sm3"
# 【纯编码】"none"
#
# 算法名大小写不敏感，支持常见别名：
#   "AES"/"aes"/"Aes"            → "aes"
#   "DESede"/"3DES"/"TripleDES"  → "3des"
#   "SHA-256"/"SHA256"/"sha256"  → "sha256"
#   "HMAC-SHA256"/"hmac-sha-256" → "hmac-sha256"
#   "NONE"/"None"/"none"         → "none"
#
# "none" 时脚本自动检测哪个算法 enabled=True
ALGORITHM = "none"

# ==================================================================
# ============================ 通用开关 ============================
# ==================================================================
DEBUG_PRINT = True
FORM_VALUE_URL_CODED = True

# ==================================================================
# ============================ 算法配置 ============================
# ==================================================================
# ---------------- AES ----------------
# 依赖：pycryptodome
AES_CONFIG = {
    "enabled": True,
    "key": b"1234567890123456",       # 16 / 24 / 32 字节
    "iv": b"1234567890123456",        # 16 字节，ECB 可忽略
    "mode": "CBC",                    # "CBC" / "ECB"
    "padding": "pkcs7",               # "pkcs7" / "none"
}

# ---------------- DES ----------------
# 依赖：pycryptodome
DES_CONFIG = {
    "enabled": False,
    "key": b"12345678",               # 8 字节
    "iv": b"12345678",                # 8 字节，ECB 可忽略
    "mode": "CBC",                    # "CBC" / "ECB"
    "padding": "pkcs7",
}

# ---------------- 3DES / DESede ----------------
# 依赖：pycryptodome
DES3_CONFIG = {
    "enabled": False,
    "key": b"123456789012345678901234",  # 16 或 24 字节
    "iv": b"12345678",                   # 8 字节，ECB 可忽略
    "mode": "CBC",
    "padding": "pkcs7",
}

# ---------------- Blowfish ----------------
# 依赖：pycryptodome
BLOWFISH_CONFIG = {
    "enabled": False,
    "key": b"1234567890123456",       # 4 ~ 56 字节
    "iv": b"12345678",                # 8 字节，ECB 可忽略
    "mode": "CBC",
    "padding": "pkcs7",
}

# ---------------- CAST ----------------
# 依赖：pycryptodome
CAST_CONFIG = {
    "enabled": False,
    "key": b"1234567890123456",       # 5 ~ 16 字节
    "iv": b"12345678",                # 8 字节
    "mode": "CBC",
    "padding": "pkcs7",
}

# ---------------- RC2 ----------------
# 依赖：pycryptodome
RC2_CONFIG = {
    "enabled": False,
    "key": b"1234567890123456",       # 5 ~ 16 字节
    "iv": b"12345678",                # 8 字节
    "mode": "CBC",
    "padding": "pkcs7",
}

# ---------------- RC4（流加密，无需 IV 和填充） ----------------
# 依赖：pycryptodome
RC4_CONFIG = {
    "enabled": False,
    "key": b"1234567890123456",       # 5 ~ 256 字节
}

# ---------------- SM4 ----------------
# 依赖：gmssl（pkcs7 填充还需 pycryptodome）
SM4_CONFIG = {
    "enabled": False,
    "key": b"1234567890123456",       # 16 字节
    "iv": b"1234567890123456",        # 16 字节，ECB 可忽略
    "mode": "CBC",                    # "CBC" / "ECB"
    "padding": "pkcs7",
}

# ---------------- RSA ----------------
# 依赖：pycryptodome
RSA_CONFIG = {
    "enabled": False,
    "public_key": "",                 # PEM 字符串
    "private_key": "",
    "padding": "pkcs1",               # "pkcs1" / "oaep"
}

# ---------------- SM2 ----------------
# 依赖：gmssl
SM2_CONFIG = {
    "enabled": False,
    "public_key": "",                 # hex，128 字符（X||Y）
    "private_key": "",                # hex，64 字符
    "mode": 1,                        # 0=C1C2C3, 1=C1C3C2
}

# ---------------- HMAC ----------------
# 依赖：内置 hmac + hashlib（HMAC-SM3 需 gmssl，当前暂未实现）
HMAC_CONFIG = {
    "enabled": False,
    "key": b"shared-secret",
    "hash_algorithm": "sha256",       # "md5" / "sha1" / "sha256" / "sha512"
}

# ==================================================================
# ============================ 参数配置 ============================
# ==================================================================
# 单层写法：
# "param": {"algorithm": "aes", "encrypt_encodings": ["url"], "decrypt_decodings": ["url"]}
#
# 多层写法：
# "param": {"layers": [
#     {"algorithm": "aes", "encrypt_encodings": ["none"], "decrypt_decodings": ["none"]},
#     {"algorithm": "rsa", "encrypt_encodings": ["base64"], "decrypt_decodings": ["base64"]},
# ]}
#
# layer 中 algorithm：
#   - 未写 / None：走全局 ALGORITHM
#   - 具体算法名：强制用该算法（大小写不敏感，支持别名）
#   - "none"：跳过加解密，只做编码/解码链
#
# 编码方式可选："none" | "url" | "base64" | "hex"
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
    "password": {
        "algorithm": "aes",
        "encrypt_encodings": ["base64"],
        "decrypt_decodings": ["base64"],
    },
    "token": {
        "layers": [
            {"algorithm": "none",
             "encrypt_encodings": ["base64"],
             "decrypt_decodings": ["base64"]},
        ],
    },
}

# 未在 TARGET_PARAMS 中列出的参数是否也处理
ENABLE_DEFAULT = False
DEFAULT_LAYERS = [
    {"algorithm": None,
     "encrypt_encodings": ["none"],
     "decrypt_decodings": ["none"]},
]

PARAM_SEPARATOR = '&'

# ==================================================================
# ====================== 算法依赖的懒加载 ==========================
# ==================================================================
try:
    from Crypto.Cipher import (
        AES as _AES, DES as _DES, DES3 as _DES3,
        Blowfish as _Blowfish, CAST as _CAST,
        ARC2 as _RC2, ARC4 as _RC4,
    )
    from Crypto.Util.Padding import pad as _pkcs7_pad, unpad as _pkcs7_unpad
    PYCRYPTODOME_AVAILABLE = True
except ImportError:
    PYCRYPTODOME_AVAILABLE = False

try:
    from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT
    from gmssl import sm2 as _gmssl_sm2
    from gmssl import sm3 as _gmssl_sm3
    GMSSL_AVAILABLE = True
except ImportError:
    GMSSL_AVAILABLE = False


# ==================================================================
# ======================= 算法名归一化 =============================
# ==================================================================
# 常见别名表：统一映射为内部使用的小写标准名
_ALGORITHM_ALIASES = {
    # 对称
    "desede": "3des",
    "tripledes": "3des",
    "triple-des": "3des",
    "3-des": "3des",
    "3des-ede": "3des",
    # 哈希
    "sha-1": "sha1",
    "sha-256": "sha256",
    "sha-384": "sha384",
    "sha-512": "sha512",
    # HMAC
    "hmac-sha-1": "hmac-sha1",
    "hmac-sha-256": "hmac-sha256",
    "hmac-sha-384": "hmac-sha384",
    "hmac-sha-512": "hmac-sha512",
    "hmac-sm-3": "hmac-sm3",
}


def _normalize_algorithm(name):
    """
    把算法名统一为小写标准形式，并解析常见别名。
    - None / 非字符串 原样返回
    - "AES" / "Aes" / "aes"          → "aes"
    - "DESede" / "3DES" / "TripleDES"→ "3des"
    - "SHA-256" / "SHA256"           → "sha256"
    - "HMAC-SHA256" / "hmac-sha-256" → "hmac-sha256"
    - "NONE" / "None" / "none"       → "none"
    """
    if name is None:
        return None
    if not isinstance(name, str):
        return name
    key = name.strip().lower()
    if not key:
        return key
    return _ALGORITHM_ALIASES.get(key, key)


# ==================================================================
# ========================= 算法解析 ===============================
# ==================================================================
def _resolve_algorithm(param_algorithm=None):
    """
    1. 层内显式指定 algorithm（含 "none"）优先
    2. 未指定时使用全局 ALGORITHM
    3. 全局也是 "none" 时自动检测已启用的算法
    返回的算法名一律为小写标准名
    """
    # 1. 层内显式指定
    if param_algorithm is not None:
        return _normalize_algorithm(param_algorithm)

    # 2. 全局 ALGORITHM
    if ALGORITHM and _normalize_algorithm(ALGORITHM) != "none":
        return _normalize_algorithm(ALGORITHM)

    # 3. 自动检测已启用算法
    for name, cfg in (
        ("aes", AES_CONFIG), ("des", DES_CONFIG), ("3des", DES3_CONFIG),
        ("sm4", SM4_CONFIG), ("blowfish", BLOWFISH_CONFIG),
        ("cast", CAST_CONFIG), ("rc2", RC2_CONFIG), ("rc4", RC4_CONFIG),
        ("rsa", RSA_CONFIG), ("sm2", SM2_CONFIG),
    ):
        if cfg.get("enabled"):
            return name
    raise ValueError("没有启用任何加密算法")


# ==================================================================
# ========================= 对称加密实现 ==========================
# ==================================================================
def _symmetric_encrypt(s, cfg, cipher_module, block_size):
    if not PYCRYPTODOME_AVAILABLE:
        raise RuntimeError("需要 pycryptodome：pip install pycryptodome")
    key, iv = cfg["key"], cfg.get("iv")
    mode = cfg["mode"].upper()
    if mode == "CBC":
        cipher = cipher_module.new(key, cipher_module.MODE_CBC, iv)
    elif mode == "ECB":
        cipher = cipher_module.new(key, cipher_module.MODE_ECB)
    else:
        raise ValueError(f"不支持的模式：{mode}")
    data = s.encode("utf-8")
    if cfg.get("padding") == "pkcs7":
        data = _pkcs7_pad(data, block_size)
    return base64.b64encode(cipher.encrypt(data)).decode("utf-8")


def _symmetric_decrypt(s, cfg, cipher_module, block_size):
    if not PYCRYPTODOME_AVAILABLE:
        raise RuntimeError("需要 pycryptodome：pip install pycryptodome")
    key, iv = cfg["key"], cfg.get("iv")
    mode = cfg["mode"].upper()
    if mode == "CBC":
        cipher = cipher_module.new(key, cipher_module.MODE_CBC, iv)
    elif mode == "ECB":
        cipher = cipher_module.new(key, cipher_module.MODE_ECB)
    else:
        raise ValueError(f"不支持的模式：{mode}")
    data = cipher.decrypt(base64.b64decode(s))
    if cfg.get("padding") == "pkcs7":
        data = _pkcs7_unpad(data, block_size)
    return data.decode("utf-8")


def _aes_encrypt(s):
    return _symmetric_encrypt(s, AES_CONFIG, _AES, 16)

def _aes_decrypt(s):
    return _symmetric_decrypt(s, AES_CONFIG, _AES, 16)

def _des_encrypt(s):
    return _symmetric_encrypt(s, DES_CONFIG, _DES, 8)

def _des_decrypt(s):
    return _symmetric_decrypt(s, DES_CONFIG, _DES, 8)

def _des3_encrypt(s):
    return _symmetric_encrypt(s, DES3_CONFIG, _DES3, 8)

def _des3_decrypt(s):
    return _symmetric_decrypt(s, DES3_CONFIG, _DES3, 8)

def _blowfish_encrypt(s):
    return _symmetric_encrypt(s, BLOWFISH_CONFIG, _Blowfish, 8)

def _blowfish_decrypt(s):
    return _symmetric_decrypt(s, BLOWFISH_CONFIG, _Blowfish, 8)

def _cast_encrypt(s):
    return _symmetric_encrypt(s, CAST_CONFIG, _CAST, 8)

def _cast_decrypt(s):
    return _symmetric_decrypt(s, CAST_CONFIG, _CAST, 8)

def _rc2_encrypt(s):
    return _symmetric_encrypt(s, RC2_CONFIG, _RC2, 8)

def _rc2_decrypt(s):
    return _symmetric_decrypt(s, RC2_CONFIG, _RC2, 8)


def _rc4_encrypt(s):
    if not PYCRYPTODOME_AVAILABLE:
        raise RuntimeError("需要 pycryptodome：pip install pycryptodome")
    cipher = _RC4.new(RC4_CONFIG["key"])
    return base64.b64encode(cipher.encrypt(s.encode("utf-8"))).decode("utf-8")


def _rc4_decrypt(s):
    if not PYCRYPTODOME_AVAILABLE:
        raise RuntimeError("需要 pycryptodome：pip install pycryptodome")
    cipher = _RC4.new(RC4_CONFIG["key"])
    return cipher.decrypt(base64.b64decode(s)).decode("utf-8")


def _sm4_pad_check():
    if not PYCRYPTODOME_AVAILABLE:
        raise RuntimeError("SM4 的 pkcs7 填充需要 pycryptodome：pip install pycryptodome")


def _sm4_encrypt(s):
    if not GMSSL_AVAILABLE:
        raise RuntimeError("需要 gmssl：pip install gmssl")
    c = CryptSM4()
    c.set_key(SM4_CONFIG["key"], SM4_ENCRYPT)
    data = s.encode("utf-8")
    if SM4_CONFIG["padding"] == "pkcs7":
        _sm4_pad_check()
        data = _pkcs7_pad(data, 16)
    mode = SM4_CONFIG["mode"].upper()
    if mode == "CBC":
        ct = c.crypt_cbc(SM4_CONFIG["iv"], data)
    elif mode == "ECB":
        ct = c.crypt_ecb(data)
    else:
        raise ValueError(f"不支持的 SM4 模式：{mode}")
    return base64.b64encode(ct).decode("utf-8")


def _sm4_decrypt(s):
    if not GMSSL_AVAILABLE:
        raise RuntimeError("需要 gmssl：pip install gmssl")
    c = CryptSM4()
    c.set_key(SM4_CONFIG["key"], SM4_DECRYPT)
    ct = base64.b64decode(s)
    mode = SM4_CONFIG["mode"].upper()
    if mode == "CBC":
        data = c.crypt_cbc(SM4_CONFIG["iv"], ct)
    elif mode == "ECB":
        data = c.crypt_ecb(ct)
    else:
        raise ValueError(f"不支持的 SM4 模式：{mode}")
    if SM4_CONFIG["padding"] == "pkcs7":
        _sm4_pad_check()
        data = _pkcs7_unpad(data, 16)
    return data.decode("utf-8")


# ==================================================================
# ========================= 非对称加密实现 ========================
# ==================================================================
def _rsa_encrypt(s):
    if not PYCRYPTODOME_AVAILABLE:
        raise RuntimeError("需要 pycryptodome：pip install pycryptodome")
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_v1_5, PKCS1_OAEP
    key = RSA.import_key(RSA_CONFIG["public_key"])
    if RSA_CONFIG["padding"] == "oaep":
        cipher = PKCS1_OAEP.new(key)
        max_chunk = key.size_in_bytes() - 42
    else:
        cipher = PKCS1_v1_5.new(key)
        max_chunk = key.size_in_bytes() - 11
    data = s.encode("utf-8")
    chunks = [data[i:i + max_chunk] for i in range(0, len(data), max_chunk)]
    return base64.b64encode(b"".join(cipher.encrypt(c) for c in chunks)).decode("utf-8")


def _rsa_decrypt(s):
    if not PYCRYPTODOME_AVAILABLE:
        raise RuntimeError("需要 pycryptodome：pip install pycryptodome")
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_v1_5, PKCS1_OAEP
    key = RSA.import_key(RSA_CONFIG["private_key"])
    if RSA_CONFIG["padding"] == "oaep":
        cipher = PKCS1_OAEP.new(key)
    else:
        cipher = PKCS1_v1_5.new(key)
    ct = base64.b64decode(s)
    ks = key.size_in_bytes()
    chunks = [ct[i:i + ks] for i in range(0, len(ct), ks)]
    result = []
    for c in chunks:
        if RSA_CONFIG["padding"] == "oaep":
            d = cipher.decrypt(c)
        else:
            d = cipher.decrypt(c, None)
            if d is None:
                raise ValueError("RSA 解密失败：密钥不匹配或密文损坏")
        result.append(d)
    return b"".join(result).decode("utf-8")


def _sm2_encrypt(s):
    if not GMSSL_AVAILABLE:
        raise RuntimeError("需要 gmssl：pip install gmssl")
    c = _gmssl_sm2.CryptSM2(
        public_key=SM2_CONFIG["public_key"],
        private_key=SM2_CONFIG["private_key"],
        mode=SM2_CONFIG["mode"],
    )
    return base64.b64encode(c.encrypt(s.encode("utf-8"))).decode("utf-8")


def _sm2_decrypt(s):
    if not GMSSL_AVAILABLE:
        raise RuntimeError("需要 gmssl：pip install gmssl")
    c = _gmssl_sm2.CryptSM2(
        public_key=SM2_CONFIG["public_key"],
        private_key=SM2_CONFIG["private_key"],
        mode=SM2_CONFIG["mode"],
    )
    return c.decrypt(base64.b64decode(s)).decode("utf-8")


# ==================================================================
# ========================= 哈希 与 HMAC ==========================
# ==================================================================
def _hash_encrypt(s, algorithm):
    """哈希：单向，计算摘要"""
    if algorithm == "sm3":
        if not GMSSL_AVAILABLE:
            raise RuntimeError("SM3 需要 gmssl：pip install gmssl")
        return _gmssl_sm3.sm3_hash(s.encode("utf-8"))
    h = hashlib.new(algorithm)
    h.update(s.encode("utf-8"))
    return h.hexdigest()


def _hash_decrypt(s, algorithm):
    raise NotImplementedError(f"{algorithm} 是哈希算法，不可逆，无法解密")


def _hmac_encrypt(s, hash_algorithm):
    """HMAC：单向，计算带密钥摘要"""
    if hash_algorithm == "sm3":
        raise NotImplementedError("HMAC-SM3 暂未实现，请使用 hmac-sha256 等")
    h = _hmac.new(HMAC_CONFIG["key"], s.encode("utf-8"), getattr(hashlib, hash_algorithm))
    return h.hexdigest()


def _hmac_decrypt(s, hash_algorithm):
    raise NotImplementedError("HMAC 是单向的，不可逆，无法解密")


# ==================================================================
# ======================= 加解密分发 ===============================
# ==================================================================
ENCRYPTORS = {
    # 对称
    "aes": _aes_encrypt, "des": _des_encrypt, "3des": _des3_encrypt,
    "blowfish": _blowfish_encrypt, "cast": _cast_encrypt,
    "rc2": _rc2_encrypt, "rc4": _rc4_encrypt, "sm4": _sm4_encrypt,
    # 非对称
    "rsa": _rsa_encrypt, "sm2": _sm2_encrypt,
}
DECRYPTORS = {
    "aes": _aes_decrypt, "des": _des_decrypt, "3des": _des3_decrypt,
    "blowfish": _blowfish_decrypt, "cast": _cast_decrypt,
    "rc2": _rc2_decrypt, "rc4": _rc4_decrypt, "sm4": _sm4_decrypt,
    "rsa": _rsa_decrypt, "sm2": _sm2_decrypt,
}

# 哈希 / HMAC 单独处理（单向，无解密）
HASH_ALGORITHMS = {"md5", "sha1", "sha256", "sha512", "sm3"}
HMAC_ALGORITHMS = {"hmac-md5", "hmac-sha1", "hmac-sha256", "hmac-sha512", "hmac-sm3"}


def _encrypt_by_algorithm(s, algorithm):
    algorithm = _normalize_algorithm(algorithm)
    if algorithm == "none":
        return s
    if algorithm in HASH_ALGORITHMS:
        return _hash_encrypt(s, algorithm)
    if algorithm in HMAC_ALGORITHMS:
        hash_alg = algorithm.replace("hmac-", "")
        return _hmac_encrypt(s, hash_alg)
    if algorithm not in ENCRYPTORS:
        raise ValueError(f"不支持的加密算法：{algorithm}")
    return ENCRYPTORS[algorithm](s)


def _decrypt_by_algorithm(s, algorithm):
    algorithm = _normalize_algorithm(algorithm)
    if algorithm == "none":
        return s
    if algorithm in HASH_ALGORITHMS:
        raise NotImplementedError(f"{algorithm} 是哈希算法，不可逆")
    if algorithm in HMAC_ALGORITHMS:
        raise NotImplementedError("HMAC 是单向的，不可逆")
    if algorithm not in DECRYPTORS:
        raise ValueError(f"不支持的解密算法：{algorithm}")
    return DECRYPTORS[algorithm](s)


# ==================================================================
# ========================== 编码 / 解码 ==========================
# ==================================================================
def encode_step(data, method):
    if method == "none":
        return data
    elif method == "url":
        return quote(data, safe='')
    elif method == "base64":
        return base64.b64encode(data.encode("utf-8")).decode("utf-8")
    elif method == "hex":
        return binascii.hexlify(data.encode("utf-8")).decode("utf-8")
    raise ValueError(f"不支持的编码方式：{method}")


def decode_step(data, method):
    if method == "none":
        return data
    elif method == "url":
        return unquote(data)
    elif method == "base64":
        return base64.b64decode(data).decode("utf-8")
    elif method == "hex":
        return binascii.unhexlify(data).decode("utf-8")
    raise ValueError(f"不支持的解码方式：{method}")


def encode_chain(data, methods):
    result = data
    for m in methods:
        result = encode_step(result, m)
    return result


def decode_chain(data, methods):
    result = data
    for m in methods:
        result = decode_step(result, m)
    return result


# ==================================================================
# ====================== 层解析与多层加解密 =======================
# ==================================================================
def _normalize_layers(cfg):
    if cfg is None:
        return None
    if "layers" in cfg:
        return cfg["layers"]
    return [{
        "algorithm": cfg.get("algorithm"),
        "encrypt_encodings": cfg.get("encrypt_encodings", ["none"]),
        "decrypt_decodings": cfg.get("decrypt_decodings", ["none"]),
    }]


def multi_encrypt(plaintext, layers):
    result = plaintext
    for layer in layers:
        alg = _resolve_algorithm(layer.get("algorithm"))
        encodings = layer.get("encrypt_encodings", ["none"])
        result = _encrypt_by_algorithm(result, alg)
        result = encode_chain(result, encodings)
    return result


def multi_decrypt(ciphertext, layers):
    result = ciphertext
    for layer in reversed(layers):
        alg = _resolve_algorithm(layer.get("algorithm"))
        decodings = layer.get("decrypt_decodings", ["none"])
        result = decode_chain(result, decodings)
        result = _decrypt_by_algorithm(result, alg)
    return result


def get_layers(key):
    if key in TARGET_PARAMS:
        return _normalize_layers(TARGET_PARAMS[key])
    if ENABLE_DEFAULT:
        return _normalize_layers({"layers": DEFAULT_LAYERS})
    return None


# ==================================================================
# ========================= JSON / 表单处理 ========================
# ==================================================================
def process_json_data(json_data, mode):
    new_data = json_data.copy()
    found = False
    for key, value in json_data.items():
        if isinstance(value, str):
            layers = get_layers(key)
            if layers is not None:
                if mode == "encrypt":
                    new_data[key] = multi_encrypt(value, layers)
                else:
                    new_data[key] = multi_decrypt(value, layers)
                found = True
    if not found and not TARGET_PARAMS:
        return json.dumps(json_data, ensure_ascii=False)
    return json.dumps(new_data, ensure_ascii=False)


def process_form_data(data, mode):
    if not data:
        return data
    parts = data.split(PARAM_SEPARATOR)
    new_parts = []
    found = False
    for part in parts:
        if '=' in part:
            key, value = part.split('=', 1)
            layers = get_layers(key)
            if layers is not None:
                if mode == "encrypt":
                    new_value = multi_encrypt(value, layers)
                    if FORM_VALUE_URL_CODED:
                        new_value = quote(new_value, safe='')
                else:
                    if FORM_VALUE_URL_CODED:
                        value = unquote(value)
                    new_value = multi_decrypt(value, layers)
                new_parts.append(f"{key}={new_value}")
                found = True
            else:
                new_parts.append(part)
        else:
            new_parts.append(part)
    if not found and ENABLE_DEFAULT:
        layers = _normalize_layers({"layers": DEFAULT_LAYERS})
        if mode == "encrypt":
            v = multi_encrypt(data, layers)
            return quote(v, safe='') if FORM_VALUE_URL_CODED else v
        else:
            v = unquote(data) if FORM_VALUE_URL_CODED else data
            return multi_decrypt(v, layers)
    return PARAM_SEPARATOR.join(new_parts)


def process_data(data, mode):
    if not data:
        return data
    try:
        json_data = json.loads(data)
    except (json.JSONDecodeError, RecursionError):
        is_json = False
    else:
        is_json = True
    if is_json:
        if isinstance(json_data, dict):
            return process_json_data(json_data, mode)
        return data
    return process_form_data(data, mode)


# ==================================================================
# =========================== Flask ===============================
# ==================================================================
app = Flask(__name__)


@app.route('/encode', methods=["POST"])
def encrypt():
    param = request.form.get('dataBody') or ""
    param_headers = request.form.get('dataHeaders') or ""
    param_requestorresponse = request.form.get('requestorresponse') or ""
    encry_param = process_data(param.strip("\n"), "encrypt")
    if DEBUG_PRINT:
        print("Original dataBody:", param)
        print("Encrypted dataBody:", encry_param)
    if param_requestorresponse == "request":
        return param_headers + "\r\n\r\n\r\n\r\n" + encry_param
    return encry_param


@app.route('/decode', methods=["POST"])
def decrypt():
    param = request.form.get('dataBody') or ""
    param_headers = request.form.get('dataHeaders') or ""
    param_requestorresponse = request.form.get('requestorresponse') or ""
    decrypt_param = process_data(param.strip("\n"), "decrypt")
    if DEBUG_PRINT:
        print("Decrypted dataBody:", decrypt_param)
        print("Headers:", param_headers)
        print("RequestOrResponse:", param_requestorresponse)
    if param_requestorresponse == "request":
        return param_headers + "\r\n\r\n\r\n\r\n" + decrypt_param
    else:
        return decrypt_param


if __name__ == '__main__':
    app.debug = True   # 生产模式请关闭 debug
    app.run(host="0.0.0.0", port="8888")