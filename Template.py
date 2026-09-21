#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Interactive Crypto Tool —— 交互式加解密配置控制台
"""

import os
import sys
import json
import time
import base64
import binascii
import hashlib
import hmac as _hmac
import subprocess
import threading
import importlib
import html as _html
import traceback

from urllib.parse import quote, unquote

VERSION = "1.3.0"

# =====================================================================
# 多语言
# =====================================================================
current_lang = "zh"


def t(zh, en):
    return en if current_lang == "en" else zh


# =====================================================================
# 终端 UI 工具
# =====================================================================
if os.name == "nt":
    os.system("")


class C:
    R = "\033[0m"
    B = "\033[1m"
    D = "\033[2m"
    RED = "\033[31m"
    GRN = "\033[32m"
    YEL = "\033[33m"
    BLU = "\033[34m"
    MAG = "\033[35m"
    CYA = "\033[36m"
    GRY = "\033[90m"


if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
    for _k in list(vars(C)):
        if not _k.startswith("_"):
            setattr(C, _k, "")


def clear():
    if state.settings.get("clear_on_menu", True):
        os.system("cls" if os.name == "nt" else "clear")


def hr(ch="─", width=70, color=None):
    print((color or C.GRY) + ch * width + C.R)


def title(text):
    print()
    hr("═")
    print(f"  {C.B}{C.CYA}{text}{C.R}")
    hr("═")


def ok(msg):
    print(f"  {C.GRN}✔{C.R} {msg}")


def err(msg):
    print(f"  {C.RED}✘{C.R} {msg}")


def warn(msg):
    print(f"  {C.YEL}!{C.R} {msg}")


def info(msg):
    print(f"  {C.CYA}ℹ{C.R} {msg}")


def render_items(items):
    for key, label, hint in items:
        k = f"{C.YEL}{str(key).rjust(2)}{C.R}"
        h = f"  {C.GRY}{hint}{C.R}" if hint else ""
        print(f"   {k}  {label}{h}")


def prompt_choice(valid=None, tip=None):
    if tip is None:
        tip = t("请选择", "Select")
    while True:
        try:
            raw = input(f"\n  {C.CYA}❯{C.R} {tip}: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return ""
        if not valid or raw in valid:
            return raw
        err(t("无效选择，请重新输入", "Invalid choice, try again"))


def ask(prompt, default=None):
    hint = f" {C.GRY}[{default}]{C.R}" if default is not None else ""
    try:
        raw = input(f"  {C.CYA}❯{C.R} {prompt}{hint}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return default if default is not None else ""
    return raw if raw else (default if default is not None else "")


def ask_inline(prompt, options, default=None):
    opts = "  ".join(f"{C.GRY}[{i}]{C.R}{o}" for i, o in enumerate(options, 1))
    hint = ""
    if default is not None and default in options:
        hint = f" {C.GRY}({'默认' if current_lang == 'zh' else 'default'} {options.index(default) + 1}){C.R}"
    while True:
        try:
            raw = input(f"  {C.CYA}❯{C.R} {prompt}  {opts}{hint}: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return default
        if not raw:
            if default is not None:
                return default
            err(t("请输入编号", "Please enter a number"))
            continue
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return options[int(raw) - 1]
        if raw in options:
            return raw
        err(t("无效输入", "Invalid input"))


def ask_block(prompt, default=None):
    print(f"  {C.CYA}❯{C.R} {prompt}")
    print(f"    {C.GRY}"
          + t("可粘贴多行内容，输入完成后单独一行输入 EOF 结束；直接回车保持当前值",
              "Paste multiline content. Type EOF on its own line to finish; "
              "empty line keeps current value")
          + C.R)
    if default:
        preview = default if len(default) < 60 else default[:57] + "..."
        print(f"    {C.GRY}{t('当前值', 'Current')}: {preview}{C.R}")
    lines = []
    while True:
        try:
            line = input("      ")
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if line.strip() == "EOF":
            break
        if line.strip() == "":
            if not lines:
                return default
            break
        if not lines and line.startswith("@"):
            path = line[1:].strip()
            if os.path.isfile(path):
                try:
                    with open(path, "r", encoding="utf-8") as fh:
                        return fh.read().strip()
                except Exception as e:
                    err(t(f"读取文件失败: {e}", f"Failed to read file: {e}"))
                    continue
        lines.append(line)
    return "\n".join(lines) if lines else default


def confirm(prompt, default=False):
    d = "Y/n" if default else "y/N"
    try:
        raw = input(f"  {C.CYA}❯{C.R} {prompt} {C.GRY}[{d}]{C.R}: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return default
    if not raw:
        return default
    return raw in ("y", "yes", "是", "1", "true")


def pause(msg=None):
    if msg is None:
        msg = t("按回车继续...", "Press Enter to continue...")
    try:
        input(f"\n  {C.GRY}{msg}{C.R}")
    except (EOFError, KeyboardInterrupt):
        print()


# =====================================================================
# 算法元数据
# =====================================================================
CAT_SYM = "对称加密"
CAT_ASYM = "非对称加密"
CAT_HASH = "哈希 / HMAC"


def cat_label(cat):
    if cat == CAT_SYM:
        return t("对称加密", "Symmetric")
    if cat == CAT_ASYM:
        return t("非对称加密", "Asymmetric")
    if cat == CAT_HASH:
        return t("哈希 / HMAC", "Hash / HMAC")
    return cat


BLOCK_MODES = ["CBC", "ECB", "CFB", "OFB", "CTR"]
BLOCK_MODES_AES = ["CBC", "ECB", "CFB", "OFB", "CTR", "GCM"]
BLOCK_MODES_SM4 = ["CBC", "ECB"]
PADDINGS = ["pkcs7", "pkcs5", "zero", "iso7816", "ansiX923", "none"]
PADDINGS_SM4 = ["pkcs7", "pkcs5", "zero", "none"]
RSA_PADS = ["pkcs1_v1_5", "oaep"]
RSA_OAEP_HASH = ["sha1", "sha256", "sha384", "sha512"]
SM2_MODES = ["C1C3C2", "C1C2C3"]
STREAM_MODES = {"CFB", "OFB", "CTR", "GCM"}


def _bf(key, label_zh, label_en, default="", multiline=False):
    return {"key": key, "label_zh": label_zh, "label_en": label_en, "kind": "bytes",
            "default": default, "default_encoding": "text", "multiline": multiline}


def _ch(key, label_zh, label_en, choices, default):
    return {"key": key, "label_zh": label_zh, "label_en": label_en,
            "kind": "choice", "choices": choices, "default": default}


def _pem(key, label_zh, label_en):
    return {"key": key, "label_zh": label_zh, "label_en": label_en,
            "kind": "pem", "default": ""}


def _txt(key, label_zh, label_en, default=""):
    return {"key": key, "label_zh": label_zh, "label_en": label_en,
            "kind": "text", "default": default}


def _flabel(f):
    return f["label_en"] if current_lang == "en" else f["label_zh"]


ALGO_DEFS = {
    "aes": {
        "label": "AES", "category": CAT_SYM, "block_size": 16,
        "cipher": "AES", "dep": "pycryptodome",
        "fields": [
            _bf("key", "密钥 Key", "Key"),
            _bf("iv", "初始向量 IV / Nonce", "IV / Nonce"),
            _ch("mode", "加密模式", "Mode", BLOCK_MODES_AES, "CBC"),
            _ch("padding", "填充方式", "Padding", PADDINGS, "pkcs7"),
        ],
    },
    "des": {
        "label": "DES", "category": CAT_SYM, "block_size": 8,
        "cipher": "DES", "dep": "pycryptodome",
        "fields": [
            _bf("key", "密钥 Key", "Key"),
            _bf("iv", "初始向量 IV", "IV"),
            _ch("mode", "加密模式", "Mode", BLOCK_MODES, "CBC"),
            _ch("padding", "填充方式", "Padding", PADDINGS, "pkcs7"),
        ],
    },
    "3des": {
        "label": "3DES (DESede)", "category": CAT_SYM, "block_size": 8,
        "cipher": "DES3", "dep": "pycryptodome",
        "fields": [
            _bf("key", "密钥 Key", "Key"),
            _bf("iv", "初始向量 IV", "IV"),
            _ch("mode", "加密模式", "Mode", BLOCK_MODES, "CBC"),
            _ch("padding", "填充方式", "Padding", PADDINGS, "pkcs7"),
        ],
    },
    "blowfish": {
        "label": "Blowfish", "category": CAT_SYM, "block_size": 8,
        "cipher": "Blowfish", "dep": "pycryptodome",
        "fields": [
            _bf("key", "密钥 Key", "Key"),
            _bf("iv", "初始向量 IV", "IV"),
            _ch("mode", "加密模式", "Mode", BLOCK_MODES, "CBC"),
            _ch("padding", "填充方式", "Padding", PADDINGS, "pkcs7"),
        ],
    },
    "cast": {
        "label": "CAST", "category": CAT_SYM, "block_size": 8,
        "cipher": "CAST", "dep": "pycryptodome",
        "fields": [
            _bf("key", "密钥 Key", "Key"),
            _bf("iv", "初始向量 IV", "IV"),
            _ch("mode", "加密模式", "Mode", BLOCK_MODES, "CBC"),
            _ch("padding", "填充方式", "Padding", PADDINGS, "pkcs7"),
        ],
    },
    "rc2": {
        "label": "RC2", "category": CAT_SYM, "block_size": 8,
        "cipher": "ARC2", "dep": "pycryptodome",
        "fields": [
            _bf("key", "密钥 Key", "Key"),
            _bf("iv", "初始向量 IV", "IV"),
            _ch("mode", "加密模式", "Mode", BLOCK_MODES, "CBC"),
            _ch("padding", "填充方式", "Padding", PADDINGS, "pkcs7"),
        ],
    },
    "rc4": {
        "label": "RC4", "category": CAT_SYM, "block_size": 1,
        "cipher": "ARC4", "dep": "pycryptodome",
        "fields": [
            _bf("key", "密钥 Key", "Key"),
        ],
    },
    "sm4": {
        "label": "SM4", "category": CAT_SYM, "block_size": 16,
        "cipher": None, "dep": "gmssl+pycryptodome",
        "fields": [
            _bf("key", "密钥 Key", "Key"),
            _bf("iv", "初始向量 IV", "IV"),
            _ch("mode", "加密模式", "Mode", BLOCK_MODES_SM4, "CBC"),
            _ch("padding", "填充方式", "Padding", PADDINGS_SM4, "pkcs7"),
        ],
    },
    "rsa": {
        "label": "RSA", "category": CAT_ASYM, "dep": "pycryptodome",
        "fields": [
            _pem("public_key", "公钥（PEM 或纯 Base64 均可）",
                 "Public Key (PEM or pure Base64)"),
            _pem("private_key", "私钥（PEM 或纯 Base64 均可）",
                 "Private Key (PEM or pure Base64)"),
            _ch("padding", "填充方式", "Padding", RSA_PADS, "pkcs1_v1_5"),
            _ch("oaep_hash", "OAEP Hash（仅 oaep 生效）",
                "OAEP Hash (for oaep only)", RSA_OAEP_HASH, "sha1"),
        ],
    },
    "sm2": {
        "label": "SM2", "category": CAT_ASYM, "dep": "gmssl",
        "fields": [
            _txt("public_key", "公钥（hex，128 字符 X||Y）",
                 "Public Key (hex, 128 chars X||Y)", ""),
            _txt("private_key", "私钥（hex，64 字符）",
                 "Private Key (hex, 64 chars)", ""),
            _ch("mode", "密文顺序", "Cipher Order", SM2_MODES, "C1C3C2"),
        ],
    },
    "md5": {"label": "MD5", "category": CAT_HASH, "oneway": True, "dep": None, "fields": []},
    "sha1": {"label": "SHA-1", "category": CAT_HASH, "oneway": True, "dep": None, "fields": []},
    "sha256": {"label": "SHA-256", "category": CAT_HASH, "oneway": True, "dep": None, "fields": []},
    "sha512": {"label": "SHA-512", "category": CAT_HASH, "oneway": True, "dep": None, "fields": []},
    "sm3": {"label": "SM3", "category": CAT_HASH, "oneway": True, "dep": "gmssl", "fields": []},
    "hmac-md5": {
        "label": "HMAC-MD5", "category": CAT_HASH, "oneway": True,
        "dep": None, "hmac_hash": "md5",
        "fields": [_bf("key", "HMAC 密钥", "HMAC Key")],
    },
    "hmac-sha1": {
        "label": "HMAC-SHA1", "category": CAT_HASH, "oneway": True,
        "dep": None, "hmac_hash": "sha1",
        "fields": [_bf("key", "HMAC 密钥", "HMAC Key")],
    },
    "hmac-sha256": {
        "label": "HMAC-SHA256", "category": CAT_HASH, "oneway": True,
        "dep": None, "hmac_hash": "sha256",
        "fields": [_bf("key", "HMAC 密钥", "HMAC Key")],
    },
    "hmac-sha512": {
        "label": "HMAC-SHA512", "category": CAT_HASH, "oneway": True,
        "dep": None, "hmac_hash": "sha512",
        "fields": [_bf("key", "HMAC 密钥", "HMAC Key")],
    },
}

ALGO_ORDER = [
    "aes", "des", "3des", "blowfish", "cast", "rc2", "rc4", "sm4",
    "rsa", "sm2",
    "md5", "sha1", "sha256", "sha512", "sm3",
    "hmac-md5", "hmac-sha1", "hmac-sha256", "hmac-sha512",
]

ENC_LABEL = {
    "none": "无",
    "url": "URL",
    "base64": "Base64",
    "base64url": "Base64URL",
    "hex": "Hex",
    "base32": "Base32",
    "html": "HTML",
    "unicode": "Unicode",
}
ENC_LABEL_EN = {
    "none": "none",
    "url": "URL",
    "base64": "Base64",
    "base64url": "Base64URL",
    "hex": "Hex",
    "base32": "Base32",
    "html": "HTML",
    "unicode": "Unicode",
}
ENC_CHOICES = list(ENC_LABEL.keys())

_MODULE_OF_DEP = {"pycryptodome": "Crypto", "gmssl": "gmssl", "flask": "flask"}


def enc_label(m):
    if current_lang == "en":
        return ENC_LABEL_EN.get(m, m)
    return ENC_LABEL.get(m, m)


def algo_label(key):
    if key in (None, "none"):
        return t("不加密", "None")
    return ALGO_DEFS.get(key, {}).get("label", key)


# =====================================================================
# 全局状态
# =====================================================================
def empty_algo_config(key):
    cfg = {}
    for f in ALGO_DEFS[key]["fields"]:
        if f["kind"] == "bytes":
            cfg[f["key"]] = {"value": "", "encoding": "text"}
        else:
            cfg[f["key"]] = ""
    return cfg


def default_algo_config(key):
    cfg = {}
    samples = {
        "aes": {"key": "1234567890123456", "iv": "1234567890123456"},
        "des": {"key": "12345678", "iv": "12345678"},
        "3des": {"key": "123456789012345678901234", "iv": "12345678"},
        "blowfish": {"key": "1234567890123456", "iv": "12345678"},
        "cast": {"key": "1234567890123456", "iv": "12345678"},
        "rc2": {"key": "1234567890123456", "iv": "12345678"},
        "rc4": {"key": "1234567890123456"},
        "sm4": {"key": "1234567890123456", "iv": "1234567890123456"},
        "hmac-md5": {"key": "shared-secret"},
        "hmac-sha1": {"key": "shared-secret"},
        "hmac-sha256": {"key": "shared-secret"},
        "hmac-sha512": {"key": "shared-secret"},
    }
    smp = samples.get(key, {})
    for f in ALGO_DEFS[key]["fields"]:
        fk = f["key"]
        if f["kind"] == "bytes":
            cfg[fk] = {"value": smp.get(fk, ""), "encoding": "text"}
        elif f["kind"] == "choice":
            cfg[fk] = f["default"]
        else:
            cfg[fk] = ""
    return cfg


class Config:
    def __init__(self):
        self.algo = {k: empty_algo_config(k) for k in ALGO_ORDER}
        self.params = {}
        self.settings = {
            "data_mode": "auto",
            "form_url_coded": True,
            "enable_default": False,
            "default_layers": [],
            "debug_print": True,
            "host": "0.0.0.0",
            "port": 8888,
            "clear_on_menu": True,
        }


state = Config()


# =====================================================================
# 配置持久化（新增）
# =====================================================================
CONFIG_ENV_VAR = "CRYPTO_TOOL_CONFIG"
CONFIG_FILENAME = "crypto_tool_config.json"

_save_error_shown = False


def config_path():
    """配置文件路径：优先环境变量，其次脚本同目录"""
    override = os.environ.get(CONFIG_ENV_VAR)
    if override:
        return os.path.abspath(os.path.expanduser(override))
    base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, CONFIG_FILENAME)


def _coerce_bytes_field(saved, current):
    """把读到的 bytes 字段规范化为 {'value':..., 'encoding':...}"""
    if isinstance(saved, dict):
        enc = saved.get("encoding", "text")
        if enc not in ("text", "hex", "base64"):
            enc = "text"
        val = saved.get("value", "")
        return {"value": str(val) if val is not None else "", "encoding": enc}
    if isinstance(saved, str):
        return {"value": saved, "encoding": "text"}
    if isinstance(current, dict):
        return dict(current)
    return {"value": "", "encoding": "text"}


def _coerce_layers(raw):
    """把读到的层列表规范化"""
    out = []
    if not isinstance(raw, list):
        return out
    for l in raw:
        if not isinstance(l, dict):
            continue
        alg = l.get("algorithm", "none")
        if alg not in ALGO_DEFS:
            alg = "none"

        def _chain(key):
            vals = l.get(key) or []
            if not isinstance(vals, list):
                return []
            return [v for v in vals
                    if isinstance(v, str) and v in ENC_CHOICES and v != "none"]

        out.append({
            "algorithm": alg,
            "encode_before": _chain("encode_before"),
            "encode_after": _chain("encode_after"),
        })
    return out


def load_config(verbose=False):
    """从磁盘加载配置，成功返回 True"""
    global current_lang
    path = config_path()
    if not os.path.isfile(path):
        if verbose:
            info(t(f"未找到配置文件：{path}（将使用默认配置）",
                   f"No config file found: {path} (using defaults)"))
        return False
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception as e:
        if verbose:
            err(t(f"配置文件读取失败：{e}", f"Failed to read config: {e}"))
        return False
    if not isinstance(data, dict):
        if verbose:
            err(t("配置文件格式不正确", "Config file format is invalid"))
        return False

    # ---- 语言 ----
    lang = data.get("lang")
    if lang in ("zh", "en"):
        current_lang = lang

    # ---- 进阶设置 ----
    saved_settings = data.get("settings")
    if isinstance(saved_settings, dict):
        for k in list(state.settings.keys()):
            if k not in saved_settings:
                continue
            default = state.settings[k]
            v = saved_settings[k]
            if isinstance(default, bool):
                if isinstance(v, bool):
                    state.settings[k] = v
            elif isinstance(default, int):
                try:
                    state.settings[k] = int(v)
                except (TypeError, ValueError):
                    pass
            elif isinstance(default, str):
                if isinstance(v, str):
                    state.settings[k] = v
            elif isinstance(default, list):
                if k == "default_layers":
                    state.settings[k] = _coerce_layers(v)
        if not (1 <= state.settings.get("port", 8888) <= 65535):
            state.settings["port"] = 8888
        if state.settings.get("data_mode") not in ("auto", "json", "form"):
            state.settings["data_mode"] = "auto"
        if not isinstance(state.settings.get("host"), str) or not state.settings["host"]:
            state.settings["host"] = "0.0.0.0"

    # ---- 算法配置 ----
    saved_algo = data.get("algo")
    if isinstance(saved_algo, dict):
        for key in ALGO_ORDER:
            saved = saved_algo.get(key)
            if not isinstance(saved, dict):
                continue
            cfg = empty_algo_config(key)
            for f in ALGO_DEFS[key]["fields"]:
                fk = f["key"]
                if fk not in saved:
                    continue
                v = saved[fk]
                if f["kind"] == "bytes":
                    cfg[fk] = _coerce_bytes_field(v, cfg[fk])
                elif f["kind"] == "choice":
                    if isinstance(v, str) and v in f["choices"]:
                        cfg[fk] = v
                else:
                    cfg[fk] = v if isinstance(v, str) else str(v)
            state.algo[key] = cfg

    # ---- 参数层配置 ----
    saved_params = data.get("params")
    if isinstance(saved_params, dict):
        clean = {}
        for name, pcfg in saved_params.items():
            if not isinstance(pcfg, dict):
                continue
            clean[str(name)] = {"layers": _coerce_layers(pcfg.get("layers"))}
        state.params = clean

    if verbose:
        ok(t(f"已加载配置：{path}", f"Config loaded: {path}"))
    return True


def save_config(verbose=False):
    """把当前配置写盘，成功返回 True"""
    global _save_error_shown
    path = config_path()
    data = {
        "_meta": {
            "tool": "interactive-crypto-tool",
            "version": VERSION,
            "saved_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        },
        "lang": current_lang,
        "settings": state.settings,
        "algo": state.algo,
        "params": state.params,
    }
    try:
        folder = os.path.dirname(path)
        if folder and not os.path.isdir(folder):
            os.makedirs(folder, exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
        _save_error_shown = False
        if verbose:
            ok(t(f"配置已保存：{path}", f"Config saved: {path}"))
        return True
    except Exception as e:
        if verbose or not _save_error_shown:
            _save_error_shown = True
            err(t(f"配置保存失败：{e}", f"Failed to save config: {e}"))
        return False


# =====================================================================
# 依赖检测
# =====================================================================
_DEP_CACHE = {}


def dep_available(module_name):
    if module_name not in _DEP_CACHE:
        try:
            __import__(module_name)
            _DEP_CACHE[module_name] = True
        except Exception:
            _DEP_CACHE[module_name] = False
    return _DEP_CACHE[module_name]


def clear_dep_cache():
    _DEP_CACHE.clear()


def algo_deps_ok(key):
    d = ALGO_DEFS.get(key)
    if not d:
        return False
    dep = d.get("dep")
    if not dep:
        return True
    for part in dep.split("+"):
        if not dep_available(_MODULE_OF_DEP.get(part, part)):
            return False
    return True


def algo_configured(key):
    d = ALGO_DEFS.get(key)
    if not d:
        return False
    if d.get("category") == CAT_HASH and not d.get("hmac_hash"):
        return True
    cfg = state.algo.get(key, {})
    if key == "rsa":
        return bool((cfg.get("public_key") or "").strip()
                    or (cfg.get("private_key") or "").strip())
    if key == "sm2":
        return bool((cfg.get("public_key") or "").strip()
                    and (cfg.get("private_key") or "").strip())
    if d.get("hmac_hash"):
        return bool(cfg.get("key", {}).get("value", "").strip())
    if d.get("category") == CAT_SYM:
        return bool(cfg.get("key", {}).get("value", "").strip())
    return True


# =====================================================================
# Base64 兼容编解码（核心修复）
# =====================================================================
def _b64d(s):
    """
    通用 base64 解码，兼容：
      1. 标准 base64 的 + / =
      2. URL/Form 传输中 + 被解析成空格的情况  ← 关键修复点
      3. URL-safe 变体（- _）
      4. 缺失 padding（自动补齐）
      5. 字符串中的换行/空白字符
    """
    if isinstance(s, bytes):
        try:
            s = s.decode('utf-8')
        except UnicodeDecodeError:
            s = s.decode('latin-1')
    s = str(s)
    # 先把空格还原成 +（Form/URL 里 + 常被当成空格）
    s = s.replace(' ', '+')
    # URL-safe 兼容
    s = s.replace('-', '+').replace('_', '/')
    # 去掉所有空白（含换行、Tab）
    s = ''.join(s.split())
    # 补齐 padding
    s = s + '=' * (-len(s) % 4)
    return base64.b64decode(s)


def _b64e(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return base64.b64encode(data).decode('utf-8')


# 兼容旧名（被旧代码调用）
def b64d(s):
    return _b64d(s)


# =====================================================================
# 字节 / 密钥辅助
# =====================================================================
def _b(v):
    if v is None:
        return b""
    if isinstance(v, bytes):
        return v
    if isinstance(v, dict):
        raw = v.get("value", "") or ""
        enc = v.get("encoding", "text")
    else:
        raw, enc = str(v), "text"
    raw = raw.strip()
    if enc == "hex":
        return bytes.fromhex("".join(raw.split()))
    if enc == "base64":
        return _b64d(raw)
    return raw.encode("utf-8")


def _load_rsa_key(text, private=True):
    from Crypto.PublicKey import RSA
    text = (text or "").strip()
    if not text:
        raise ValueError(t("RSA 密钥为空", "RSA key is empty"))
    if "-----BEGIN" in text:
        return RSA.import_key(text)
    compact = "".join(text.split())
    try:
        return RSA.import_key(_b64d(compact))
    except Exception:
        pass
    labels = (["PRIVATE KEY", "RSA PRIVATE KEY"] if private
              else ["PUBLIC KEY", "RSA PUBLIC KEY"])
    last = None
    for lab in labels:
        pem = f"-----BEGIN {lab}-----\n{compact}\n-----END {lab}-----"
        try:
            return RSA.import_key(pem)
        except Exception as e:
            last = e
    raise ValueError(t(f"无法解析 RSA 密钥：{last}", f"Cannot parse RSA key: {last}"))


# =====================================================================
# 填充
# =====================================================================
def _pad(data, bs, style):
    style = (style or "pkcs7").lower()
    if style in ("none", ""):
        return data
    if style == "pkcs5":
        style = "pkcs7"
    if style == "zero":
        pad_len = (bs - len(data) % bs) % bs
        return data + b"\x00" * pad_len
    if style == "ansix923":
        style = "x923"
    from Crypto.Util.Padding import pad
    if style == "pkcs7":
        return pad(data, bs, style="pkcs7")
    if style == "iso7816":
        return pad(data, bs, style="iso7816")
    if style == "x923":
        return pad(data, bs, style="x923")
    raise ValueError(t(f"不支持的填充方式：{style}", f"Unsupported padding: {style}"))


def _unpad(data, bs, style):
    style = (style or "pkcs7").lower()
    if style in ("none", ""):
        return data
    if style == "pkcs5":
        style = "pkcs7"
    if style == "zero":
        return data.rstrip(b"\x00")
    if style == "ansix923":
        style = "x923"
    from Crypto.Util.Padding import unpad
    if style == "pkcs7":
        return unpad(data, bs, style="pkcs7")
    if style == "iso7816":
        return unpad(data, bs, style="iso7816")
    if style == "x923":
        return unpad(data, bs, style="x923")
    raise ValueError(t(f"不支持的填充方式：{style}", f"Unsupported padding: {style}"))


# =====================================================================
# 加密引擎
# =====================================================================
def _cipher_module(key):
    name = ALGO_DEFS[key]["cipher"]
    return importlib.import_module(f"Crypto.Cipher.{name}")


def _make_cipher(mod, key_b, mode, iv, algo):
    mode = mode.upper()
    if mode == "CBC":
        return mod.new(key_b, mod.MODE_CBC, iv)
    if mode == "ECB":
        return mod.new(key_b, mod.MODE_ECB)
    if mode == "CFB":
        return mod.new(key_b, mod.MODE_CFB, iv, segment_size=128)
    if mode == "OFB":
        return mod.new(key_b, mod.MODE_OFB, iv)
    if mode == "CTR":
        from Crypto.Util import Counter
        iv16 = (iv + b"\x00" * 16)[:16]
        ctr = Counter.new(128, initial_value=int.from_bytes(iv16, "big"))
        return mod.new(key_b, mod.MODE_CTR, counter=ctr)
    if mode == "GCM":
        return mod.new(key_b, mod.MODE_GCM, nonce=iv)
    raise ValueError(t(f"不支持的加密模式：{mode}", f"Unsupported mode: {mode}"))


def _sym_encrypt(algo, text):
    cfg = state.algo[algo]
    mod = _cipher_module(algo)
    key_b = _b(cfg.get("key"))
    data = text.encode("utf-8")
    if algo == "rc4":
        return _b64e(mod.new(key_b).encrypt(data))
    bs = ALGO_DEFS[algo]["block_size"]
    mode = str(cfg.get("mode", "CBC")).upper()
    iv = _b(cfg.get("iv"))
    cipher = _make_cipher(mod, key_b, mode, iv, algo)
    if mode == "GCM":
        ct, tag = cipher.encrypt_and_digest(data)
        return _b64e(ct + tag)
    if mode not in STREAM_MODES and cfg.get("padding") != "none":
        data = _pad(data, bs, cfg.get("padding", "pkcs7"))
    return _b64e(cipher.encrypt(data))


def _sym_decrypt(algo, text):
    cfg = state.algo[algo]
    mod = _cipher_module(algo)
    key_b = _b(cfg.get("key"))
    # 核心修复：使用兼容解码
    raw = _b64d(text)
    if algo == "rc4":
        return mod.new(key_b).decrypt(raw).decode("utf-8")
    bs = ALGO_DEFS[algo]["block_size"]
    mode = str(cfg.get("mode", "CBC")).upper()
    iv = _b(cfg.get("iv"))
    cipher = _make_cipher(mod, key_b, mode, iv, algo)
    if mode == "GCM":
        if len(raw) < 16:
            raise ValueError(t("GCM 密文过短（应包含 16 字节 tag）",
                               "GCM ciphertext too short (should include 16-byte tag)"))
        ct, tag = raw[:-16], raw[-16:]
        return cipher.decrypt_and_verify(ct, tag).decode("utf-8")
    data = cipher.decrypt(raw)
    if mode not in STREAM_MODES and cfg.get("padding") != "none":
        try:
            data = _unpad(data, bs, cfg.get("padding", "pkcs7"))
        except ValueError as e:
            # 诊断信息
            tail = ("0x%02x" % data[-1]) if data else "N/A"
            raise ValueError(
                t(f"{e}；当前密文 {len(raw)} 字节，解密后 {len(data)} 字节，"
                  f"末字节 {tail}。请检查 Key/IV/Mode/Padding 是否与服务器一致",
                  f"{e}; ciphertext={len(raw)}B, decrypted={len(data)}B, "
                  f"last byte={tail}. Check Key/IV/Mode/Padding")
            )
    return data.decode("utf-8")


def _sm4_encrypt(text):
    from gmssl.sm4 import CryptSM4, SM4_ENCRYPT
    cfg = state.algo["sm4"]
    c = CryptSM4()
    c.set_key(_b(cfg.get("key")), SM4_ENCRYPT)
    data = text.encode("utf-8")
    if cfg.get("padding") != "none":
        data = _pad(data, 16, cfg.get("padding", "pkcs7"))
    if str(cfg.get("mode", "CBC")).upper() == "CBC":
        ct = c.crypt_cbc(_b(cfg.get("iv")), data)
    else:
        ct = c.crypt_ecb(data)
    return _b64e(ct)


def _sm4_decrypt(text):
    from gmssl.sm4 import CryptSM4, SM4_DECRYPT
    cfg = state.algo["sm4"]
    c = CryptSM4()
    c.set_key(_b(cfg.get("key")), SM4_DECRYPT)
    ct = _b64d(text)
    if str(cfg.get("mode", "CBC")).upper() == "CBC":
        data = c.crypt_cbc(_b(cfg.get("iv")), ct)
    else:
        data = c.crypt_ecb(ct)
    if cfg.get("padding") != "none":
        data = _unpad(data, 16, cfg.get("padding", "pkcs7"))
    return data.decode("utf-8")


def _rsa_encrypt(text):
    from Crypto.Cipher import PKCS1_v1_5, PKCS1_OAEP
    from Crypto.Hash import SHA1, SHA256, SHA384, SHA512
    cfg = state.algo["rsa"]
    key = _load_rsa_key(cfg.get("public_key", ""), private=False)
    if cfg.get("padding") == "oaep":
        hashes = {"sha1": SHA1, "sha256": SHA256, "sha384": SHA384, "sha512": SHA512}
        h = hashes.get((cfg.get("oaep_hash") or "sha1").lower(), SHA1)
        cipher = PKCS1_OAEP.new(key, hashAlgo=h)
        chunk = key.size_in_bytes() - 2 * h.digest_size - 2
    else:
        cipher, chunk = PKCS1_v1_5.new(key), key.size_in_bytes() - 11
    data = text.encode("utf-8")
    blocks = [data[i:i + chunk] for i in range(0, len(data), chunk)]
    return _b64e(b"".join(cipher.encrypt(b) for b in blocks))


def _rsa_decrypt(text):
    from Crypto.Cipher import PKCS1_v1_5, PKCS1_OAEP
    from Crypto.Hash import SHA1, SHA256, SHA384, SHA512
    cfg = state.algo["rsa"]
    key = _load_rsa_key(cfg.get("private_key", ""), private=True)
    if cfg.get("padding") == "oaep":
        hashes = {"sha1": SHA1, "sha256": SHA256, "sha384": SHA384, "sha512": SHA512}
        h = hashes.get((cfg.get("oaep_hash") or "sha1").lower(), SHA1)
        cipher = PKCS1_OAEP.new(key, hashAlgo=h)
    else:
        cipher = PKCS1_v1_5.new(key)
    ct = _b64d(text)
    ks = key.size_in_bytes()
    out = []
    for i in range(0, len(ct), ks):
        block = ct[i:i + ks]
        if cfg.get("padding") == "oaep":
            out.append(cipher.decrypt(block))
        else:
            d = cipher.decrypt(block, None)
            if d is None:
                raise ValueError(t("RSA 解密失败：密钥不匹配或密文损坏",
                                   "RSA decrypt failed: key mismatch or corrupted ciphertext"))
            out.append(d)
    return b"".join(out).decode("utf-8")


def _sm2_encrypt(text):
    from gmssl import sm2 as gsm2
    cfg = state.algo["sm2"]
    c = gsm2.CryptSM2(public_key=cfg.get("public_key", ""),
                      private_key=cfg.get("private_key", ""),
                      mode=1 if cfg.get("mode") == "C1C3C2" else 0)
    return _b64e(c.encrypt(text.encode("utf-8")))


def _sm2_decrypt(text):
    from gmssl import sm2 as gsm2
    cfg = state.algo["sm2"]
    c = gsm2.CryptSM2(public_key=cfg.get("public_key", ""),
                      private_key=cfg.get("private_key", ""),
                      mode=1 if cfg.get("mode") == "C1C3C2" else 0)
    return c.decrypt(_b64d(text)).decode("utf-8")


def _hash_encrypt(algo, text):
    if algo == "sm3":
        from gmssl import sm3 as gsm3
        return gsm3.sm3_hash(list(text.encode("utf-8")))
    h = hashlib.new(algo)
    h.update(text.encode("utf-8"))
    return h.hexdigest()


def _hmac_encrypt(algo, text):
    cfg = state.algo[algo]
    h = _hmac.new(_b(cfg.get("key")), text.encode("utf-8"),
                  getattr(hashlib, ALGO_DEFS[algo]["hmac_hash"]))
    return h.hexdigest()


def encrypt_by_algo(algo, text):
    if algo in (None, "none"):
        return text
    d = ALGO_DEFS.get(algo)
    if not d:
        raise ValueError(t(f"未知算法：{algo}", f"Unknown algorithm: {algo}"))
    if d.get("hmac_hash"):
        return _hmac_encrypt(algo, text)
    if algo in ("md5", "sha1", "sha256", "sha512", "sm3"):
        return _hash_encrypt(algo, text)
    if algo == "sm4":
        return _sm4_encrypt(text)
    if algo == "rsa":
        return _rsa_encrypt(text)
    if algo == "sm2":
        return _sm2_encrypt(text)
    return _sym_encrypt(algo, text)


def decrypt_by_algo(algo, text):
    if algo in (None, "none"):
        return text
    d = ALGO_DEFS.get(algo)
    if not d:
        raise ValueError(t(f"未知算法：{algo}", f"Unknown algorithm: {algo}"))
    if d.get("oneway"):
        raise NotImplementedError(t(f"{algo_label(algo)} 是单向算法，不可逆",
                                    f"{algo_label(algo)} is one-way, not reversible"))
    if algo == "sm4":
        return _sm4_decrypt(text)
    if algo == "rsa":
        return _rsa_decrypt(text)
    if algo == "sm2":
        return _sm2_decrypt(text)
    return _sym_decrypt(algo, text)


# =====================================================================
# 编码 / 解码
# =====================================================================
def encode_step(data, method):
    if method in (None, "none"):
        return data
    if method == "url":
        return quote(data, safe="")
    if method == "base64":
        return _b64e(data)
    if method == "base64url":
        return base64.urlsafe_b64encode(data.encode("utf-8")).decode().rstrip("=")
    if method == "hex":
        return binascii.hexlify(data.encode("utf-8")).decode()
    if method == "base32":
        return base64.b32encode(data.encode("utf-8")).decode()
    if method == "html":
        return _html.escape(data, quote=True)
    if method == "unicode":
        return data.encode("unicode_escape").decode("ascii")
    raise ValueError(t(f"不支持的编码方式：{method}", f"Unsupported encoding: {method}"))


def decode_step(data, method):
    if method in (None, "none"):
        return data
    if method == "url":
        return unquote(data)
    if method == "base64":
        return _b64d(data).decode("utf-8")
    if method == "base64url":
        s = data.replace("-", "+").replace("_", "/")
        s += "=" * (-len(s) % 4)
        return base64.urlsafe_b64decode(s).decode("utf-8")
    if method == "hex":
        return binascii.unhexlify("".join(data.split())).decode("utf-8")
    if method == "base32":
        s = data + "=" * (-len(data) % 8)
        return base64.b32decode(s).decode("utf-8")
    if method == "html":
        return _html.unescape(data)
    if method == "unicode":
        return data.encode("ascii").decode("unicode_escape")
    raise ValueError(t(f"不支持的编码方式：{method}", f"Unsupported decoding: {method}"))


def encode_chain(data, methods):
    for m in methods or []:
        data = encode_step(data, m)
    return data


def decode_chain(data, methods):
    for m in methods or []:
        data = decode_step(data, m)
    return data


# =====================================================================
# 多层加解密
# =====================================================================
def multi_encrypt(plaintext, layers):
    result = plaintext
    for layer in layers or []:
        algo = layer.get("algorithm", "none")
        result = encode_chain(result, layer.get("encode_before", []))
        result = encrypt_by_algo(algo, result)
        result = encode_chain(result, layer.get("encode_after", []))
    return result


def multi_decrypt(ciphertext, layers):
    result = ciphertext
    for layer in reversed(layers or []):
        algo = layer.get("algorithm", "none")
        result = decode_chain(result, list(reversed(layer.get("encode_after", []))))
        result = decrypt_by_algo(algo, result)
        result = decode_chain(result, list(reversed(layer.get("encode_before", []))))
    return result


# =====================================================================
# 数据体处理
# =====================================================================
def get_layers(param_name):
    if param_name in state.params:
        return state.params[param_name]["layers"]
    if state.settings["enable_default"] and state.settings["default_layers"]:
        return state.settings["default_layers"]
    return None


def process_json(obj, mode):
    out = dict(obj)
    for k, v in obj.items():
        if not isinstance(v, str):
            continue
        layers = get_layers(k)
        if layers is None:
            continue
        try:
            out[k] = multi_encrypt(v, layers) if mode == "encrypt" else multi_decrypt(v, layers)
        except Exception as e:
            out[k] = v
            if state.settings["debug_print"]:
                print(f"  [!] {t('参数', 'param')} {k} "
                      + t(f"处理失败：{e}", f"failed: {e}"))
    return json.dumps(out, ensure_ascii=False)


def process_form(data, mode):
    parts = data.split("&")
    out = []
    for part in parts:
        if "=" not in part:
            out.append(part)
            continue
        key, _, value = part.partition("=")
        layers = get_layers(key)
        if layers is None:
            out.append(part)
            continue
        try:
            if mode == "encrypt":
                nv = multi_encrypt(value, layers)
                if state.settings["form_url_coded"]:
                    nv = quote(nv, safe="")
            else:
                v = unquote(value) if state.settings["form_url_coded"] else value
                nv = multi_decrypt(v, layers)
            out.append(f"{key}={nv}")
        except Exception as e:
            out.append(part)
            if state.settings["debug_print"]:
                print(f"  [!] {t('参数', 'param')} {key} "
                      + t(f"处理失败：{e}", f"failed: {e}"))
    return "&".join(out)


def process_payload(data, mode):
    if not data:
        return data
    dm = state.settings["data_mode"]
    if dm in ("auto", "json"):
        try:
            parsed = json.loads(data)
        except Exception:
            if dm == "json":
                return data
        else:
            if isinstance(parsed, dict):
                return process_json(parsed, mode)
            if dm == "json":
                return data
    return process_form(data, mode)


# =====================================================================
# 环境安装
# =====================================================================
MIRRORS = [
    ("官方 PyPI", "https://pypi.org/simple"),
    ("清华 TUNA", "https://pypi.tuna.tsinghua.edu.cn/simple"),
    ("阿里云", "https://mirrors.aliyun.com/pypi/simple/"),
    ("腾讯云", "https://mirrors.cloud.tencent.com/pypi/simple"),
    ("不指定镜像", None),
]

REQUIRED_PKGS = [
    ("flask", "flask",
     "Web 服务框架（启动 encode/decode 接口所需）",
     "Web framework (required for /encode and /decode)"),
    ("Crypto", "pycryptodome",
     "AES / DES / RSA / SM4 填充 等主流算法",
     "AES / DES / RSA and various paddings"),
    ("gmssl", "gmssl",
     "SM2 / SM3 / SM4 国密算法",
     "SM2 / SM3 / SM4 Chinese national algorithms"),
]


def package_status():
    return [(mod, pkg, desc_zh, desc_en, dep_available(mod))
            for mod, pkg, desc_zh, desc_en in REQUIRED_PKGS]


def do_install(index_url):
    todo = [pkg for mod, pkg, _, _, _ in package_status() if not dep_available(mod)]
    if not todo:
        clear_dep_cache()
        ok(t("所有依赖均已安装", "All dependencies installed"))
        return
    print()
    info(t(f"将安装：{', '.join(todo)}", f"Will install: {', '.join(todo)}"))
    if index_url:
        info(t(f"使用镜像：{index_url}", f"Using mirror: {index_url}"))
    if not confirm(t("确认开始安装？", "Start installation?"), True):
        return
    failed = []
    for i, pkg in enumerate(todo, 1):
        print()
        hr()
        info(t(f"[{i}/{len(todo)}] 正在安装 {C.B}{pkg}{C.R}",
               f"[{i}/{len(todo)}] Installing {C.B}{pkg}{C.R}"))
        cmd = [sys.executable, "-m", "pip", "install", "--upgrade", pkg]
        if index_url:
            cmd += ["-i", index_url, "--trusted-host",
                    index_url.split("//")[-1].split("/")[0]]
        try:
            rc = subprocess.call(cmd)
        except Exception as e:
            err(t(f"调用 pip 失败：{e}", f"Failed to run pip: {e}"))
            rc = 1
        if rc != 0:
            failed.append(pkg)
        else:
            ok(t(f"{pkg} 安装完成", f"{pkg} installed"))
    clear_dep_cache()
    print()
    hr("═")
    if failed:
        err(t(f"以下包安装失败：{', '.join(failed)}",
               f"Failed to install: {', '.join(failed)}"))
        warn(t("可尝试手动执行： pip install " + " ".join(failed),
               "Try manually: pip install " + " ".join(failed)))
    else:
        ok(t("环境就绪！可以开始配置加解密了",
             "Environment ready! Start configuring now"))
    pause()


def menu_install():
    while True:
        clear()
        title(t("运行环境检查 / 一键安装", "Environment Check / One-Click Install"))
        print(f"  Python: {C.GRN}{sys.version.split()[0]}{C.R}   "
              f"{t('解释器', 'Interpreter')}: {C.GRY}{sys.executable}{C.R}")
        print()
        print(f"  {t('依赖状态', 'Dependencies')}：")
        for mod, pkg, desc_zh, desc_en, installed in package_status():
            mark = f"{C.GRN}✔ {t('已安装', 'installed')}{C.R}" if installed \
                else f"{C.RED}✘ {t('未安装', 'missing')}{C.R}"
            desc = desc_en if current_lang == "en" else desc_zh
            print(f"    {mark}  {C.B}{pkg:<14}{C.R} {C.GRY}{desc}{C.R}")
        print()
        render_items([
            ("1", t("一键安装 / 补齐所有依赖", "Install / fix all dependencies"), ""),
            ("0", t("返回主菜单", "Back to main menu"), ""),
        ])
        ch = prompt_choice({"1", "0"})
        if ch == "0":
            return
        if ch == "1":
            clear()
            title(t("选择 pip 镜像源", "Select pip mirror"))
            for i, (name, url) in enumerate(MIRRORS, 1):
                suffix = f"  {C.GRY}{url}{C.R}" if url else ""
                print(f"   {C.YEL}{i}{C.R}  {name}{suffix}")
            raw = ask(t("请选择编号", "Select number"), "2")
            try:
                idx = int(raw) - 1
                index_url = MIRRORS[idx][1]
            except Exception:
                index_url = MIRRORS[1][1]
            do_install(index_url)


# =====================================================================
# 菜单 1：算法配置
# =====================================================================
def fmt_bytes_field(v):
    if isinstance(v, dict):
        val = v.get("value", "")
        enc = v.get("encoding", "text")
        if len(val) > 40:
            val = val[:37] + "..."
        return f"{val or t('(空)', '(empty)')}  {C.GRY}[{enc}]{C.R}"
    return str(v) if v else t("(空)", "(empty)")


def show_algo_config(key):
    d = ALGO_DEFS[key]
    cfg = state.algo[key]
    if not d["fields"]:
        print(f"    {C.GRY}{t('该算法无需额外配置', 'No extra config required')}{C.R}")
        return
    for f in d["fields"]:
        v = cfg.get(f["key"])
        shown = fmt_bytes_field(v) if f["kind"] == "bytes" else (str(v) if v else t("(空)", "(empty)"))
        print(f"    {C.GRY}{_flabel(f):<32}{C.R} {shown}")


def edit_algo_field(key, field):
    cfg = state.algo[key]
    fk = field["key"]
    if field["kind"] == "bytes":
        cur = cfg.get(fk) or {"value": "", "encoding": "text"}
        enc = ask_inline(f"{_flabel(field)} " + t("格式", "format"),
                         ["text", "hex", "base64"], cur.get("encoding", "text"))
        if field.get("multiline"):
            val = ask_block(t(f"请输入 {_flabel(field)}：",
                              f"Enter {_flabel(field)}:"), cur.get("value", ""))
        else:
            val = ask(t(f"请输入 {_flabel(field)}", f"Enter {_flabel(field)}"),
                      cur.get("value", ""))
        cfg[fk] = {"value": val, "encoding": enc}
        ok(t(f"{_flabel(field)} 已更新", f"{_flabel(field)} updated"))
    elif field["kind"] == "choice":
        val = ask_inline(_flabel(field), field["choices"], cfg.get(fk, field["default"]))
        cfg[fk] = val
        ok(t(f"{_flabel(field)} 已设置为 {val}", f"{_flabel(field)} set to {val}"))
    elif field["kind"] == "pem":
        val = ask_block(t(f"请输入 {_flabel(field)}：",
                          f"Enter {_flabel(field)}:"), cfg.get(fk, ""))
        cfg[fk] = val
        ok(t(f"{_flabel(field)} 已更新（{len(val or '')} 字符）",
             f"{_flabel(field)} updated ({len(val or '')} chars)"))
    else:
        val = ask(t(f"请输入 {_flabel(field)}", f"Enter {_flabel(field)}"),
                  cfg.get(fk, ""))
        cfg[fk] = val
        ok(t(f"{_flabel(field)} 已更新", f"{_flabel(field)} updated"))


def menu_algo_detail(key):
    d = ALGO_DEFS[key]
    while True:
        clear()
        title(t(f"算法配置 · {d['label']}", f"Algorithm Config · {d['label']}"))
        print(f"  {t('类别', 'Category')}：{cat_label(d['category'])}")
        dep = d.get("dep") or t("无", "none")
        dep_state = f"{C.GRN}{t('满足', 'OK')}{C.R}" if algo_deps_ok(key) \
            else f"{C.RED}{t('缺少依赖', 'missing')}{C.R}"
        print(f"  {t('依赖', 'Dependency')}：{dep}  ({dep_state})")
        print()
        print(f"  {C.B}{t('当前配置', 'Current config')}{C.R}")
        show_algo_config(key)
        print()
        items = []
        if d["fields"]:
            for i, f in enumerate(d["fields"], 1):
                items.append((str(i), t(f"修改 {_flabel(f)}", f"Edit {_flabel(f)}"), ""))
        items.append(("r", t("恢复默认值", "Restore defaults"),
                      t("将所有字段填回初始默认（示例值）",
                        "Fill all fields with initial sample values")))
        items.append(("c", t("清空该算法配置", "Clear this algorithm"),
                      t("所有字段置空 → 回到\"未配置\"状态",
                        "Clear all fields → back to 'not configured'")))
        items.append(("0", t("返回", "Back"), ""))
        render_items(items)
        valid = {str(i) for i in range(1, len(d["fields"]) + 1)} | {"r", "c", "0"}
        ch = prompt_choice(valid)
        if ch == "0":
            return
        if ch == "c":
            if confirm(t(f"确认清空 {d['label']} 的所有配置？（回到未配置状态）",
                         f"Clear all config for {d['label']}? (back to unconfigured)")):
                state.algo[key] = empty_algo_config(key)
                save_config()
                ok(t("已清空", "Cleared"))
                pause()
        elif ch == "r":
            if confirm(t(f"恢复 {d['label']} 为初始默认值？",
                         f"Restore {d['label']} to initial defaults?")):
                state.algo[key] = default_algo_config(key)
                save_config()
                ok(t("已恢复默认", "Defaults restored"))
                pause()
        elif ch.isdigit():
            edit_algo_field(key, d["fields"][int(ch) - 1])
            save_config()
            pause()


def bulk_reset_all_algos():
    for k in ALGO_ORDER:
        state.algo[k] = empty_algo_config(k)


def menu_algorithms():
    while True:
        clear()
        title(t("配置加解密算法", "Configure Algorithms"))
        idx = 1
        mapping = {}
        for cat in (CAT_SYM, CAT_ASYM, CAT_HASH):
            keys = [k for k in ALGO_ORDER if ALGO_DEFS[k]["category"] == cat]
            if not keys:
                continue
            print(f"\n  {C.B}{C.MAG}【{cat_label(cat)}】{C.R}")
            for k in keys:
                deps_ok = algo_deps_ok(k)
                conf = algo_configured(k)
                if not deps_ok:
                    status = f"{C.RED}✘ {t('缺少依赖', 'missing dep')}{C.R}"
                elif conf:
                    status = f"{C.GRN}✔ {t('已配置', 'configured')}{C.R}"
                else:
                    status = f"{C.YEL}○ {t('未配置', 'unconfigured')}{C.R}"
                print(f"   {C.YEL}{str(idx).rjust(2)}{C.R}) {ALGO_DEFS[k]['label']:<34} {status}")
                mapping[str(idx)] = k
                idx += 1
        print()
        render_items([
            ("a", t("一键清空所有算法配置", "Clear all algorithm config"),
                  t("所有算法恢复为\"未配置\"状态",
                    "Reset all algorithms to 'unconfigured'")),
            ("0", t("返回主菜单", "Back to main menu"), ""),
        ])
        ch = prompt_choice(set(mapping) | {"a", "0"})
        if ch == "0":
            return
        if ch == "a":
            if confirm(t("确认清空所有算法配置？所有算法将回到\"未配置\"状态",
                         "Clear all algorithm config? All will become unconfigured"),
                       False):
                bulk_reset_all_algos()
                save_config()
                ok(t("所有算法已恢复为未配置状态",
                     "All algorithms reset to unconfigured"))
                pause()
            continue
        menu_algo_detail(mapping[ch])


# =====================================================================
# 菜单 2：数据格式
# =====================================================================
def menu_data_format():
    while True:
        clear()
        title(t("数据格式设置", "Data Format Settings"))
        cur = state.settings["data_mode"]
        opts = [
            ("auto", t("自动识别", "Auto Detect"),
             t("先尝试 JSON，失败则按表单处理", "Try JSON, fallback to form")),
            ("json", t("强制 JSON", "Force JSON"),
             t("只处理 JSON 数据体", "Handle JSON body only")),
            ("form", t("强制 x-www-form-urlencoded", "Force Form"),
             t("只处理表单数据体", "Handle form body only")),
        ]
        print()
        for i, (val, label, desc) in enumerate(opts, 1):
            mark = f"{C.GRN}●{C.R}" if val == cur else " "
            print(f"   {mark} {C.YEL}{i}{C.R}) {label:<32} {C.GRY}{desc}{C.R}")
        print()
        render_items([("0", t("返回主菜单", "Back to main menu"), "")])
        ch = prompt_choice({"1", "2", "3", "0"})
        if ch == "0":
            return
        state.settings["data_mode"] = opts[int(ch) - 1][0]
        save_config()
        ok(t(f"数据格式已设置为：{opts[int(ch) - 1][1]}",
             f"Data mode set to: {opts[int(ch) - 1][1]}"))
        pause()


# =====================================================================
# 菜单 3：参数配置
# =====================================================================
def fmt_chain(chain):
    chain = [c for c in (chain or []) if c and c != "none"]
    if not chain:
        return f"{C.GRY}{t('无', 'none')}{C.R}"
    return f"{C.CYA}" + " → ".join(enc_label(c) for c in chain) + C.R


def layer_summary(layer):
    alg = layer.get("algorithm", "none")
    return ALGO_DEFS.get(alg, {}).get("label", t("不加密", "None"))


def parse_chain(raw):
    if not raw:
        return []
    raw = raw.strip()
    if raw.lower() in ("none", "无", "-"):
        return []
    parts = [p.strip().lower() for p in raw.replace("，", ",").replace(" ", ",").split(",")]
    out = []
    for p in parts:
        if not p:
            continue
        if p not in ENC_CHOICES:
            raise ValueError(t(f"不支持的编码方式：{p}（可用：{', '.join(ENC_CHOICES)}）",
                               f"Unsupported encoding: {p} (valid: {', '.join(ENC_CHOICES)})"))
        if p != "none":
            out.append(p)
    return out


def choose_algorithm(current=None):
    keys = ["none"] + [k for k in ALGO_ORDER if algo_deps_ok(k)]
    while True:
        clear()
        title(t("选择加密算法", "Choose Algorithm"))
        print()
        for i, k in enumerate(keys, 1):
            if k == "none":
                label, status = t("不加密（仅做编码）", "None (encode only)"), ""
            else:
                label = ALGO_DEFS[k]["label"]
                status = f"{C.GRN}✔{C.R}" if algo_configured(k) \
                    else f"{C.YEL}○ {t('未配置', 'unconfigured')}{C.R}"
            mark = f"{C.GRN}●{C.R}" if k == current else " "
            print(f"   {mark} {C.YEL}{str(i).rjust(2)}{C.R}) {label:<24} {status}")
        print()
        render_items([("0", t("取消", "Cancel"), "")])
        ch = prompt_choice({str(i) for i in range(1, len(keys) + 1)} | {"0"})
        if ch == "0":
            return None
        picked = keys[int(ch) - 1]
        if picked != "none" and not algo_configured(picked):
            if not confirm(t(f"{ALGO_DEFS[picked]['label']} 尚未配置参数，现在去配置？",
                             f"{ALGO_DEFS[picked]['label']} is not configured, configure now?"),
                           True):
                continue
            menu_algo_detail(picked)
            if not algo_configured(picked):
                warn(t("仍未完成配置", "Still unconfigured"))
                pause()
                continue
        return picked


def edit_layer(layer, label=""):
    while True:
        clear()
        title(t(f"层配置 {label}", f"Layer Config {label}"))
        print(f"  {t('算法', 'Algorithm')}       : {C.GRN}{layer_summary(layer)}{C.R}")
        print(f"  {t('加密前编码', 'Before-Enc')}   : {fmt_chain(layer.get('encode_before', []))}")
        print(f"  {t('加密后编码', 'After-Enc')}    : {fmt_chain(layer.get('encode_after', []))}")
        print(f"  {C.GRY}{t('(解密时会自动按相反顺序解码)', '(decryption reverses order automatically)')}{C.R}")
        print()
        render_items([
            ("1", t("修改算法", "Change algorithm"), ""),
            ("2", t("设置【加密前】编码链", "Set [before-enc] chain"),
                  t("加密前 / 解密后", "before-enc / after-dec")),
            ("3", t("设置【加密后】编码链", "Set [after-enc] chain"),
                  t("加密后 / 解密前", "after-enc / before-dec")),
            ("0", t("完成", "Done"), ""),
        ])
        ch = prompt_choice({"1", "2", "3", "0"})
        if ch == "0":
            save_config()
            return layer
        if ch == "1":
            picked = choose_algorithm(layer.get("algorithm"))
            if picked is not None:
                layer["algorithm"] = picked
                save_config()
                ok(t(f"算法已设置为 {algo_label(picked)}",
                     f"Algorithm set to {algo_label(picked)}"))
                pause()
        elif ch in ("2", "3"):
            fld = "encode_before" if ch == "2" else "encode_after"
            cur = ",".join(layer.get(fld, []))
            print(f"  {C.GRY}{t('可用编码', 'Available')}：{', '.join(ENC_CHOICES)}{C.R}")
            raw = ask(t("请输入编码链（逗号分隔，如 url,base64；留空=无）",
                        "Enter chain (comma-separated, e.g. url,base64; empty=none)"),
                      cur if cur else t("无", "none"))
            try:
                layer[fld] = parse_chain(raw)
                save_config()
                ok(t(f"已设置：{fmt_chain(layer[fld])}",
                     f"Set to: {fmt_chain(layer[fld])}"))
            except ValueError as e:
                err(str(e))
            pause()


def menu_layer_editor(layers, owner_name):
    while True:
        clear()
        title(t(f"参数层管理 · {owner_name}", f"Layer Manager · {owner_name}"))
        if not layers:
            print(f"  {C.YEL}{t('当前没有任何层', 'No layers yet')}{C.R}")
        else:
            print(f"  {C.GRY}"
                  + t("（加密时自上而下执行，解密时自下而上执行）",
                      "(encryption runs top-down, decryption bottom-up)")
                  + C.R + "\n")
            for i, l in enumerate(layers, 1):
                print(f"   {C.YEL}{i}{C.R}) {C.B}{layer_summary(l):<22}{C.R} "
                      f"{t('前', 'pre')}:{fmt_chain(l.get('encode_before', []))}  "
                      f"{t('后', 'post')}:{fmt_chain(l.get('encode_after', []))}")
        print()
        render_items([
            ("1", t("新增一层", "Add layer"), ""),
            ("2", t("编辑某一层", "Edit layer"), ""),
            ("3", t("删除某一层", "Delete layer"), ""),
            ("4", t("调整层顺序", "Reorder layers"), ""),
            ("c", t("清空所有层", "Clear all layers"), ""),
            ("0", t("返回", "Back"), ""),
        ])
        ch = prompt_choice({"1", "2", "3", "4", "c", "0"})
        if ch == "0":
            save_config()
            return layers
        if ch == "1":
            picked = choose_algorithm()
            if picked is None:
                continue
            layers.append({"algorithm": picked, "encode_before": [], "encode_after": []})
            edit_layer(layers[-1], f"#{len(layers)}")
        elif ch == "2":
            if not layers:
                warn(t("暂无层可编辑", "No layers to edit"))
                pause()
                continue
            raw = ask(t(f"请输入要编辑的层号 (1-{len(layers)})",
                        f"Layer number to edit (1-{len(layers)})"), "1")
            try:
                i = int(raw) - 1
                assert 0 <= i < len(layers)
            except Exception:
                err(t("无效层号", "Invalid layer"))
                pause()
                continue
            edit_layer(layers[i], f"#{i + 1}")
        elif ch == "3":
            if not layers:
                warn(t("暂无层可删除", "No layers to delete"))
                pause()
                continue
            raw = ask(t(f"请输入要删除的层号 (1-{len(layers)})",
                        f"Layer number to delete (1-{len(layers)})"), str(len(layers)))
            try:
                i = int(raw) - 1
                assert 0 <= i < len(layers)
            except Exception:
                err(t("无效层号", "Invalid layer"))
                pause()
                continue
            if confirm(t(f"确认删除第 {i + 1} 层？", f"Delete layer {i + 1}?")):
                layers.pop(i)
                save_config()
                ok(t("已删除", "Deleted"))
                pause()
        elif ch == "4":
            if len(layers) < 2:
                warn(t("至少需要 2 层才能调整顺序", "Need at least 2 layers"))
                pause()
                continue
            raw = ask(t("请输入新的顺序（空格/逗号分隔，如 2 1 3）",
                        "New order (space/comma separated, e.g. 2 1 3)"),
                      " ".join(str(i) for i in range(1, len(layers) + 1)))
            try:
                order = [int(x) - 1 for x in raw.replace(",", " ").split()]
                assert sorted(order) == list(range(len(layers)))
            except Exception:
                err(t("顺序不合法", "Invalid order"))
                pause()
                continue
            layers[:] = [layers[i] for i in order]
            save_config()
            ok(t("顺序已调整", "Order updated"))
            pause()
        elif ch == "c":
            if confirm(t("确认清空该参数的所有层？", "Clear all layers for this param?")):
                layers.clear()
                save_config()
                ok(t("已清空", "Cleared"))
                pause()


def bulk_apply_algo_to_params():
    if not state.params:
        warn(t("尚未配置任何参数", "No parameters configured"))
        pause()
        return
    picked = choose_algorithm()
    if picked is None:
        return
    print()
    print(f"  {C.GRY}{t('可用编码', 'Available')}：{', '.join(ENC_CHOICES)}{C.R}")
    before = parse_chain(ask(t("加密前编码链（逗号分隔，留空=无）",
                               "Before-enc chain (comma-separated, empty=none)"),
                             t("无", "none")))
    after = parse_chain(ask(t("加密后编码链（逗号分隔，留空=无）",
                              "After-enc chain (comma-separated, empty=none)"),
                            t("无", "none")))
    layer = {"algorithm": picked, "encode_before": before, "encode_after": after}
    if not confirm(t(f"将把所有 {len(state.params)} 个参数都重置为单层 [{algo_label(picked)}]，确认？",
                     f"Reset all {len(state.params)} params to single layer [{algo_label(picked)}]?"),
                   True):
        return
    for name in state.params:
        state.params[name]["layers"] = [dict(layer)]
    save_config()
    ok(t(f"已套用到 {len(state.params)} 个参数",
         f"Applied to {len(state.params)} params"))
    pause()


def menu_params():
    while True:
        clear()
        title(t("配置加解密参数", "Configure Parameters"))
        if not state.params:
            print(f"  {C.YEL}{t('尚未配置任何参数', 'No parameters configured')}{C.R}")
        else:
            print(f"  {C.GRY}"
                  + t(f"当前已配置 {len(state.params)} 个参数：",
                      f"{len(state.params)} parameter(s):")
                  + C.R + "\n")
            for name, pcfg in state.params.items():
                chain = " → ".join(layer_summary(l) for l in pcfg["layers"]) or t("无", "none")
                print(f"   {C.GRN}•{C.R} {C.B}{name}{C.R}   "
                      f"{C.GRY}({len(pcfg['layers'])} {t('层', 'layers')}){C.R}  "
                      f"{C.CYA}{chain}{C.R}")
        print()
        render_items([
            ("1", t("新增参数", "Add parameter"), ""),
            ("2", t("编辑参数", "Edit parameter"), ""),
            ("3", t("删除参数", "Delete parameter"), ""),
            ("4", t("重命名参数", "Rename parameter"), ""),
            ("5", t("一键套用同一算法到所有参数", "Apply one algorithm to all params"), ""),
            ("c", t("清空所有参数配置", "Clear all parameters"), ""),
            ("0", t("返回主菜单", "Back to main menu"), ""),
        ])
        ch = prompt_choice({"1", "2", "3", "4", "5", "c", "0"})
        if ch == "0":
            return
        if ch == "1":
            name = ask(t("请输入参数名（如 password / token / encryptedData）",
                         "Enter param name (e.g. password / token / encryptedData)"))
            if not name:
                warn(t("参数名不能为空", "Param name cannot be empty"))
                pause()
                continue
            if name in state.params:
                warn(t("该参数已存在，将进入编辑", "Param already exists, editing"))
            else:
                state.params[name] = {"layers": []}
                save_config()
            menu_layer_editor(state.params[name]["layers"], name)
        elif ch == "2":
            if not state.params:
                warn(t("暂无参数", "No parameters"))
                pause()
                continue
            name = ask(t("请输入要编辑的参数名", "Param name to edit"))
            if name not in state.params:
                err(t("参数不存在", "Param does not exist"))
                pause()
                continue
            menu_layer_editor(state.params[name]["layers"], name)
        elif ch == "3":
            if not state.params:
                warn(t("暂无参数", "No parameters"))
                pause()
                continue
            name = ask(t("请输入要删除的参数名", "Param name to delete"))
            if name not in state.params:
                err(t("参数不存在", "Param does not exist"))
                pause()
                continue
            if confirm(t(f"确认删除参数 {name}？", f"Delete param {name}?")):
                del state.params[name]
                save_config()
                ok(t("已删除", "Deleted"))
                pause()
        elif ch == "4":
            if not state.params:
                warn(t("暂无参数", "No parameters"))
                pause()
                continue
            name = ask(t("请输入要重命名的参数名", "Param name to rename"))
            if name not in state.params:
                err(t("参数不存在", "Param does not exist"))
                pause()
                continue
            new = ask(t("请输入新名称", "New name"), name)
            if new and new != name:
                if new in state.params:
                    err(t("新名称已存在", "New name already exists"))
                else:
                    state.params[new] = state.params.pop(name)
                    save_config()
                    ok(t("已重命名", "Renamed"))
            pause()
        elif ch == "5":
            bulk_apply_algo_to_params()
        elif ch == "c":
            if confirm(t("确认清空所有参数配置？", "Clear all parameters?"), False):
                state.params.clear()
                save_config()
                ok(t("已清空", "Cleared"))
                pause()


# =====================================================================
# 菜单 4：进阶配置
# =====================================================================
def menu_config_file():
    while True:
        clear()
        title(t("配置文件管理", "Config File Manager"))
        path = config_path()
        exists = os.path.isfile(path)
        print(f"  {t('路径', 'Path')}：{C.CYA}{path}{C.R}")
        print(f"  {t('状态', 'Status')}：" +
              (f"{C.GRN}{t('已存在', 'exists')}{C.R}" if exists
               else f"{C.YEL}{t('尚未创建', 'not created yet')}{C.R}"))
        if exists:
            try:
                sz = os.path.getsize(path)
                mt = time.strftime("%Y-%m-%d %H:%M:%S",
                                   time.localtime(os.path.getmtime(path)))
                print(f"  {t('大小', 'Size')}：{sz} {t('字节', 'bytes')}    "
                      f"{t('修改时间', 'Modified')}：{mt}")
            except Exception:
                pass
        print(f"  {C.GRY}{t('（修改配置时会自动保存到该文件）', '(auto-saved on every change)')}{C.R}")
        print()
        render_items([
            ("1", t("立即保存当前配置", "Save current config now"), ""),
            ("2", t("重新加载配置文件", "Reload from file"),
                  t("将丢弃当前未保存的修改", "Discards unsaved changes")),
            ("3", t("恢复全部出厂默认", "Factory reset"),
                  t("清空算法与参数配置（保留语言/端口）", "Clear algorithms & params")),
            ("4", t("删除配置文件", "Delete config file"), ""),
            ("0", t("返回", "Back"), ""),
        ])
        ch = prompt_choice({"1", "2", "3", "4", "0"})
        if ch == "0":
            return
        if ch == "1":
            save_config(verbose=True)
            pause()
        elif ch == "2":
            if not exists:
                warn(t("配置文件不存在", "Config file does not exist"))
                pause()
                continue
            if confirm(t("确认从文件重新加载？当前未保存的修改将丢失",
                         "Reload from file? Unsaved changes will be lost"), True):
                load_config(verbose=True)
                pause()
        elif ch == "3":
            if confirm(t("确认恢复出厂默认？将清空所有算法参数与参数层配置",
                         "Factory reset? All algorithms and parameter layers will be cleared"),
                       False):
                bulk_reset_all_algos()
                state.params.clear()
                state.settings["enable_default"] = False
                state.settings["default_layers"] = []
                save_config(verbose=True)
                pause()
        elif ch == "4":
            if not exists:
                warn(t("配置文件不存在", "Config file does not exist"))
                pause()
                continue
            if confirm(t(f"确认删除 {path}？", f"Delete {path}?"), False):
                try:
                    os.remove(path)
                    ok(t("已删除", "Deleted"))
                except Exception as e:
                    err(str(e))
                pause()


def menu_advanced():
    while True:
        clear()
        title(t("进阶配置", "Advanced Settings"))
        s = state.settings
        mode_label = {"auto": t("自动识别", "Auto"),
                      "json": t("强制 JSON", "JSON"),
                      "form": t("强制表单", "Form")}[s["data_mode"]]
        default_desc = (t("未启用", "disabled") if not s["enable_default"]
                        else (" → ".join(layer_summary(l) for l in s["default_layers"])
                              or t("未设置", "not set")))
        cfg_exists = os.path.isfile(config_path())
        cfg_desc = (f"{C.GRN}{t('已保存', 'saved')}{C.R}" if cfg_exists
                    else f"{C.YEL}{t('未创建', 'new')}{C.R}")
        items = [
            ("1", t("表单值自动 URL 编码/解码", "Auto URL encode/decode form values"),
                  t("开启", "on") if s["form_url_coded"] else t("关闭", "off")),
            ("2", t("未配置参数统一处理", "Default handling for unconfigured params"),
                  default_desc),
            ("3", t("调试输出", "Debug output"),
                  t("开启", "on") if s["debug_print"] else t("关闭", "off")),
            ("4", t("菜单清屏", "Clear screen on menu"),
                  t("开启", "on") if s["clear_on_menu"] else t("关闭", "off")),
            ("5", t("服务监听地址", "Server listen address"),
                  f"{s['host']}:{s['port']}"),
            ("6", t("配置文件管理", "Config file manager"), cfg_desc),
            ("0", t("返回主菜单", "Back to main menu"),
                  t(f"当前数据格式：{mode_label}",
                    f"Current data mode: {mode_label}")),
        ]
        render_items(items)
        ch = prompt_choice({"1", "2", "3", "4", "5", "6", "0"})
        if ch == "0":
            return
        if ch == "1":
            s["form_url_coded"] = not s["form_url_coded"]
            save_config()
            ok(t(f"表单 URL 编码处理：{'开启' if s['form_url_coded'] else '关闭'}",
                 f"Form URL encode: {'on' if s['form_url_coded'] else 'off'}"))
            pause()
        elif ch == "2":
            clear()
            title(t("未配置参数统一处理", "Default handling for unconfigured params"))
            print(f"  {t('当前', 'Current')}："
                  f"{t('启用', 'enabled') if s['enable_default'] else t('未启用', 'disabled')}")
            print(f"  {t('默认层', 'Default layers')}："
                  f"{' → '.join(layer_summary(l) for l in s['default_layers']) or t('未设置', 'not set')}")
            print()
            render_items([
                ("1", t("启用 / 关闭", "Enable / Disable"), ""),
                ("2", t("配置默认加解密层", "Configure default layers"), ""),
                ("0", t("返回", "Back"), ""),
            ])
            sub = prompt_choice({"1", "2", "0"})
            if sub == "1":
                s["enable_default"] = not s["enable_default"]
                save_config()
                ok(t("已启用" if s["enable_default"] else "已关闭",
                     "Enabled" if s["enable_default"] else "Disabled"))
                pause()
            elif sub == "2":
                if not s["default_layers"]:
                    picked = choose_algorithm()
                    if picked is not None:
                        s["default_layers"] = [{"algorithm": picked,
                                                "encode_before": [],
                                                "encode_after": []}]
                        save_config()
                menu_layer_editor(s["default_layers"], t("默认参数", "default"))
        elif ch == "3":
            s["debug_print"] = not s["debug_print"]
            save_config()
            ok(t(f"调试输出：{'开启' if s['debug_print'] else '关闭'}",
                 f"Debug: {'on' if s['debug_print'] else 'off'}"))
            pause()
        elif ch == "4":
            s["clear_on_menu"] = not s["clear_on_menu"]
            save_config()
            ok(t(f"菜单清屏：{'开启' if s['clear_on_menu'] else '关闭'}",
                 f"Clear screen: {'on' if s['clear_on_menu'] else 'off'}"))
            pause()
        elif ch == "5":
            host = ask(t("监听地址", "Host"), s["host"])
            port_raw = ask(t("监听端口", "Port"), str(s["port"]))
            try:
                port = int(port_raw)
                assert 1 <= port <= 65535
                s["host"], s["port"] = host, port
                save_config()
                ok(t(f"已设置为 {host}:{port}", f"Set to {host}:{port}"))
            except Exception:
                err(t("端口不合法", "Invalid port"))
            pause()
        elif ch == "6":
            menu_config_file()


# =====================================================================
# 菜单 5：预览
# =====================================================================
def build_route(layers, encrypt=True):
    steps = []
    if encrypt:
        for l in layers:
            for e in l.get("encode_before", []):
                steps.append(("enc", e))
            steps.append(("algo", l.get("algorithm", "none")))
            for e in l.get("encode_after", []):
                steps.append(("enc", e))
    else:
        for l in reversed(layers):
            for e in reversed(l.get("encode_after", [])):
                steps.append(("dec", e))
            steps.append(("algo", l.get("algorithm", "none")))
            for e in reversed(l.get("encode_before", [])):
                steps.append(("dec", e))
    return steps


def render_steps(steps, head, tail, encrypt=True):
    parts = [f"{C.B}{head}{C.R}"]
    for kind, val in steps:
        if kind == "algo":
            if val in (None, "none"):
                continue
            label = algo_label(val)
            tag = f"{C.MAG}{label} " \
                  + (t("加密", "Enc") if encrypt else t("解密", "Dec")) + C.R
        else:
            label = enc_label(val)
            tag = f"{C.BLU}{label} " \
                  + (t("编码", "Encode") if kind == "enc" else t("解码", "Decode")) + C.R
        parts.append(tag)
    parts.append(f"{C.B}{tail}{C.R}")
    print("       " + f" {C.GRY}→{C.R} ".join(parts))


def preview_param(name, pcfg):
    print(f"\n   {C.B}{C.CYA}▸ {name}{C.R}   "
          f"{C.GRY}({len(pcfg['layers'])} {t('层', 'layers')}){C.R}")
    enc_steps = build_route(pcfg["layers"], encrypt=True)
    dec_steps = build_route(pcfg["layers"], encrypt=False)
    dm = state.settings["data_mode"]
    show_url = state.settings["form_url_coded"] and dm in ("auto", "form")
    url_note = ""
    if show_url:
        enc_steps = enc_steps + [("enc", "url")]
        dec_steps = [("dec", "url")] + dec_steps
        if dm == "auto":
            url_note = f"  {C.GRY}{t('(若为表单类型才生效)', '(only if form type)')}{C.R}"
    render_steps(enc_steps, t("明文", "Plain"), t("密文", "Cipher"),
                 encrypt=True)
    render_steps(dec_steps, t("密文", "Cipher"), t("明文", "Plain"),
                 encrypt=False)
    if url_note:
        print(f"       {url_note}")


def preview_test():
    clear()
    title(t("实时测试", "Live Test"))
    if not state.params:
        warn(t("尚未配置任何参数", "No parameters configured"))
        pause()
        return
    names = list(state.params.keys())
    print()
    for i, n in enumerate(names, 1):
        print(f"   {C.YEL}{i}{C.R}) {n}")
    raw = ask(t("请选择要测试的参数编号", "Param number to test"), "1")
    try:
        name = names[int(raw) - 1]
    except Exception:
        err(t("无效编号", "Invalid number"))
        pause()
        return
    layers = state.params[name]["layers"]
    plain = ask(t("请输入明文", "Enter plaintext"), "hello world")
    print()
    try:
        cipher = multi_encrypt(plain, layers)
        if state.settings["form_url_coded"] and state.settings["data_mode"] in ("auto", "form"):
            cipher = quote(cipher, safe="")
        print(f"   {C.GRN}{t('加密结果', 'Cipher')}：{C.R}{cipher}")
        dec_input = cipher
        if state.settings["form_url_coded"] and state.settings["data_mode"] in ("auto", "form"):
            dec_input = unquote(dec_input)
        back = multi_decrypt(dec_input, layers)
        if back == plain:
            print(f"   {C.GRN}{t('解密结果', 'Plain')}：{C.R}{back}  "
                  f"{C.GRN}✔ {t('往返一致', 'round-trip OK')}{C.R}")
        else:
            print(f"   {C.YEL}{t('解密结果', 'Plain')}：{C.R}{back}  "
                  f"{C.RED}✘ {t('与原文不一致', 'mismatch')}{C.R}")
    except Exception as e:
        err(t(f"测试失败：{e}", f"Test failed: {e}"))
    pause()


def menu_preview():
    while True:
        clear()
        title(t("加解密流程预览", "Preview Pipeline"))
        if not state.params and not state.settings["enable_default"]:
            warn(t("尚未配置任何加解密参数", "No parameters configured"))
        else:
            for name, pcfg in state.params.items():
                preview_param(name, pcfg)
            if state.settings["enable_default"]:
                print(f"\n   {C.B}{C.YEL}▸ "
                      + t("(未配置参数默认处理)", "(default handling for unconfigured)")
                      + C.R)
                for l in state.settings["default_layers"]:
                    print(f"       {layer_summary(l)}  "
                          f"{t('前', 'pre')}:{fmt_chain(l.get('encode_before', []))} "
                          f"{t('后', 'post')}:{fmt_chain(l.get('encode_after', []))}")
        print()
        render_items([
            ("1", t("实时测试加解密", "Live encrypt/decrypt test"), ""),
            ("0", t("返回主菜单", "Back to main menu"), ""),
        ])
        ch = prompt_choice({"1", "0"})
        if ch == "0":
            return
        preview_test()


# =====================================================================
# 菜单 6：启动服务
# =====================================================================
def build_app():
    from flask import Flask, request
    app = Flask("interactive-crypto-tool")
    # 关键修复：关闭 debug，异常不再显示 werkzeug 调试页面
    app.debug = False

    @app.route("/encode", methods=["POST"])
    def _encode():
        body = (request.form.get("dataBody") or "").strip("\n")
        headers = request.form.get("dataHeaders") or ""
        rr = request.form.get("requestorresponse") or ""
        try:
            out = process_payload(body, "encrypt")
        except Exception as e:
            out = body
            if state.settings["debug_print"]:
                print(f"[encode] {t('处理异常', 'exception')}：{e}")
                traceback.print_exc()
        if state.settings["debug_print"]:
            print(f"[encode] {body!r} -> {out!r}")
        if rr == "request":
            return headers + "\r\n\r\n\r\n\r\n" + out
        return out

    @app.route("/decode", methods=["POST"])
    def _decode():
        body = (request.form.get("dataBody") or "").strip("\n")
        headers = request.form.get("dataHeaders") or ""
        rr = request.form.get("requestorresponse") or ""
        try:
            out = process_payload(body, "decrypt")
        except Exception as e:
            out = body
            if state.settings["debug_print"]:
                print(f"[decode] {t('处理异常', 'exception')}：{e}")
                traceback.print_exc()
        if state.settings["debug_print"]:
            print(f"[decode] {body!r} -> {out!r}")
        if rr == "request":
            return headers + "\r\n\r\n\r\n\r\n" + out
        return out

    return app


def _list_access_urls(host, port):
    """返回 (地址, 说明) 列表，适配 0.0.0.0 场景"""
    urls = []
    if host in ("0.0.0.0", "::", ""):
        urls.append(("127.0.0.1", t("本机回环（AutoDecoder 推荐）",
                                     "Loopback (recommended for AutoDecoder)")))
        urls.append((host or "0.0.0.0",
                     t("所有网卡（局域网设备可访问本机 IP）",
                       "All NICs (LAN devices can access via your IP)")))
    elif host == "127.0.0.1":
        urls.append(("127.0.0.1", t("本机回环（AutoDecoder 推荐）",
                                     "Loopback (recommended for AutoDecoder)")))
    else:
        urls.append((host, t("指定网卡地址", "Specified NIC address")))
        urls.append(("127.0.0.1", t("本机回环（若未监听回环则不可用）",
                                     "Loopback (unavailable if not listening)")))
    return urls


def menu_serve():
    clear()
    title(t("启动服务", "Start Server"))
    if not dep_available("flask"):
        err(t("未安装 Flask，请先执行菜单 0 一键安装",
              "Flask not installed. Run menu 0 first"))
        pause()
        return
    s = state.settings
    host = ask(t("监听地址", "Host"), s["host"])
    port_raw = ask(t("监听端口", "Port"), str(s["port"]))
    try:
        port = int(port_raw)
    except Exception:
        err(t("端口不合法", "Invalid port"))
        pause()
        return
    s["host"], s["port"] = host, port
    save_config()
    print()
    print(f"  {C.GRY}{t('数据格式', 'Data mode')}    :{C.R} {s['data_mode']}")
    print(f"  {C.GRY}{t('已配置参数', 'Params')}  :{C.R} "
          f"{', '.join(state.params.keys()) or t('(无)', '(none)')}")
    print(f"  {C.GRY}{t('默认处理', 'Default')}    :{C.R} "
          f"{t('启用', 'enabled') if s['enable_default'] else t('关闭', 'disabled')}")
    print()
    try:
        from werkzeug.serving import make_server
        app = build_app()
        server = make_server(host, port, app, threaded=True)
    except Exception as e:
        err(t(f"启动失败：{e}", f"Failed to start: {e}"))
        pause()
        return
    t_thread = threading.Thread(target=server.serve_forever, daemon=True)
    t_thread.start()

    print()
    ok(t(f"服务已启动（监听 {host}:{port}）",
         f"Server started (listening {host}:{port})"))
    print(f"  {C.B}{t('可访问地址', 'Accessible URLs')}：{C.R}")
    for a, desc in _list_access_urls(host, port):
        print(f"    {C.GRN}http://{a}:{port}/encode{C.R}    {C.GRY}{desc}{C.R}")
        print(f"    {C.GRN}http://{a}:{port}/decode{C.R}    {C.GRY}{desc}{C.R}")
    print()
    info(t("AutoDecoder 里填 127.0.0.1 就行，即使监听的是 0.0.0.0 也能连通",
           "Use 127.0.0.1 in AutoDecoder even if listening on 0.0.0.0"))
    print(f"  {C.GRY}{t('表单字段', 'Form fields')}："
          f"dataBody / dataHeaders / requestorresponse{C.R}")
    pause(t("按回车停止服务...", "Press Enter to stop server..."))
    try:
        server.shutdown()
    except Exception:
        pass
    ok(t("服务已停止", "Server stopped"))
    pause()


# =====================================================================
# 主菜单
# =====================================================================
def banner():
    print()
    print(C.CYA + C.B + "  ╔" + "═" * 66 + "╗" + C.R)
    line = t("交互式加解密配置控制台", "Interactive Crypto Config Console")
    width = 0
    for ch in line:
        width += 2 if ord(ch) > 0x2000 else 1
    pad = (66 - width) // 2
    print(C.CYA + C.B + "  ║" + " " * pad + line
          + " " * (66 - pad - width) + "║" + C.R)
    print(C.CYA + C.B + "  ╚" + "═" * 66 + "╝" + C.R)


def menu_language():
    global current_lang
    clear()
    title(t("语言 / Language", "Language / 语言"))
    cur = current_lang
    print()
    items = [
        ("1", "中文", f"{C.GRN}●{C.R}" if cur == "zh" else ""),
        ("2", "English", f"{C.GRN}●{C.R}" if cur == "en" else ""),
        ("0", t("返回", "Back"), ""),
    ]
    render_items(items)
    ch = prompt_choice({"1", "2", "0"})
    if ch == "1" and cur != "zh":
        current_lang = "zh"
        save_config()
        ok("语言已切换为中文")
    elif ch == "2" and cur != "en":
        current_lang = "en"
        save_config()
        ok("Language switched to English")
    if ch in ("1", "2"):
        pause()


def main_menu():
    while True:
        clear()
        banner()
        dep_ok_count = sum(1 for *_, okk in package_status() if okk)
        env_state = (f"{C.GRN}{t('已就绪', 'ready')}{C.R}"
                     if dep_ok_count == len(REQUIRED_PKGS)
                     else f"{C.RED}{t('缺失', 'missing')} {len(REQUIRED_PKGS) - dep_ok_count} "
                          f"{t('项', 'pkg(s)')}{C.R}")
        mode_label = {"auto": t("自动识别", "Auto"),
                      "json": t("强制 JSON", "JSON"),
                      "form": t("强制表单", "Form")}[state.settings["data_mode"]]
        param_names = list(state.params.keys())
        param_desc = f"{len(param_names)} " + t("个", "item(s)") + (
            f" {C.GRY}({', '.join(param_names[:3])}"
            f"{'...' if len(param_names) > 3 else ''}){C.R}" if param_names else "")

        cfg_path = config_path()
        cfg_exists = os.path.isfile(cfg_path)
        cfg_state = (f"{C.GRN}{t('已保存', 'saved')}{C.R}" if cfg_exists
                     else f"{C.YEL}{t('未创建', 'new')}{C.R}")

        print()
        print(f"  {t('环境状态', 'Env')}：{env_state}      "
              f"{t('版本', 'Ver')}：{C.GRY}v{VERSION}{C.R}      "
              f"Python：{C.GRY}{sys.version.split()[0]}{C.R}")
        print(f"  {t('配置文件', 'Config')}：{C.GRY}{cfg_path}{C.R}  {cfg_state}")

        lang_label = "中文" if current_lang == "zh" else "English"
        print()
        render_items([
            ("0", t("一键安装 / 修复运行环境", "Install / Repair environment"), env_state),
            ("1", t("配置加解密算法", "Configure algorithms"),
                  f"{C.GRY}"
                  + t(f"已配置 {sum(1 for k in ALGO_ORDER if algo_configured(k))} 个",
                      f"{sum(1 for k in ALGO_ORDER if algo_configured(k))} configured")
                  + C.R),
            ("2", t("数据格式设置", "Data format"), mode_label),
            ("3", t("配置加解密参数", "Configure parameters"), param_desc),
            ("4", t("进阶配置", "Advanced settings"), ""),
            ("5", t("预览加解密流程", "Preview pipeline"), ""),
            ("6", t("启动服务", "Start server"),
                  f"{C.GRY}{state.settings['host']}:{state.settings['port']}{C.R}"),
            ("a", t("切换语言", "Switch Language"),
                  f"{C.GRY}{t('当前', 'Current')}: {lang_label}{C.R}"),
            ("q", t("退出", "Quit"),
                  f"{C.GRY}{t('配置自动保存', 'auto-save on exit')}{C.R}"),
        ])
        print()
        ch = prompt_choice({"0", "1", "2", "3", "4", "5", "6", "a", "q"})

        # EOF / Ctrl+C 视作退出
        if ch in ("", "q"):
            save_config()
            clear()
            print()
            print(f"  {C.CYA}{t('再见 👋', 'Bye 👋')}{C.R}")
            print(f"  {C.GRY}{t('配置已保存到', 'Config saved to')}: {config_path()}{C.R}")
            print()
            return

        try:
            if ch == "0":
                menu_install()
            elif ch == "1":
                menu_algorithms()
            elif ch == "2":
                menu_data_format()
            elif ch == "3":
                menu_params()
            elif ch == "4":
                menu_advanced()
            elif ch == "5":
                menu_preview()
            elif ch == "6":
                menu_serve()
            elif ch == "a":
                menu_language()
        finally:
            # 无论子菜单里发生什么（含 Ctrl+C 中断），都把配置落盘
            save_config()


def entry():
    if os.name == "nt":
        try:
            os.system("chcp 65001 > nul")
        except Exception:
            pass
    # 启动时自动加载上次保存的配置
    load_config()
    try:
        main_menu()
    except KeyboardInterrupt:
        save_config()
        print()
        print(f"\n  {C.YEL}{t('已中断，配置已保存，再见', 'Interrupted, config saved, bye')}{C.R}\n")
        sys.exit(0)


if __name__ == "__main__":
    entry()
