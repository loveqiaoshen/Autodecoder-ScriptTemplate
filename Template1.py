#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Interactive Crypto Tool —— 交互式加解密配置控制台 v1.3.15

v1.3.15 变更（相对 1.3.14，review_round3 t10 JSON 路径 allow 判据补有效性）：
  * 【t10】process_json_text 决定「哪些键参与处理」用的是 allow 判据
    ——「params[name] 是 dict 且 scope 匹配」。它不含 F-06 新加的有效性判断，
    于是 {} / {"layers": []} / {"layers": [{"algorithm": "none"}]} 这类
    「有配置但没有有效层」的字段在 JSON 路径被当成"有字段级配置"，
    走自己的空 layers，default_layers 永远接不到。
  * 后果是同一份配置换个 body 格式就失效：form 路径（F-06 已修）会让
    default_layers 接管，JSON 路径不会 —— 用户无从预期。
  * 改法：allow 判据后补一行 `if allow and not _layers_effective(layers)`，
    把「空层配置」降级成「没有字段级配置」，与 _process_top_pairs 共用
    同一个 _layers_effective（不另写逻辑）。空配置是合法状态：静默跳过，
    不发提示。enable_default=false 或 default_layers 为空时字段原样不动。
  * JSON 保形不受影响：改动只决定 allow/layers，值的替换仍走
    v1.3.7 的字符区间替换，未处理字段的空白、number 字面量、缩进逐字节不变。

v1.3.14 变更（相对 1.3.13，review_round3 F-10 错误文案分支丢头段）：
  * 【F-10】/encode 与 /decode 的「明文非 UTF-8」错误文案分支，两段式拼接
    时把头段写成了空串（_join_two_part("", msg)），响应变成
    "\r\n\r\n\r\n\r\n[文案]"。插件侧 arr[0].split("\r\n") 得到 [""]，
    buildHttpMessage 会把整组 header 清空 —— Cookie、Content-Type、自定义头
    全没了，现象是「解密失败一次，后续请求的认证头也丢了」。
  * 改法：两处改为 _join_two_part(out_headers, msg)，头段回填处理后的 headers。
    _join_two_part 本体一行未动（head 为空则返回 CRLF4+body 的既有行为是 M1
    契约的一部分，空头场景必须保持）。
  * 触发条件说明：只有算法层（aes/des/rc4/sm4/rsa/sm2/AEAD）解出非 UTF-8 明文
    才会进这个分支；none+base64 这类纯编解码层的失败走 _text_or_original
    （soft=True，"utf8" 标记为 False），_utf8_failure() 返回 None，不触发。

v1.3.13 变更（相对 1.3.12，review_round3 R-14 配置覆盖前自动备份）：
  * 【R-14】save_config() 在 os.replace() 覆盖之前，把磁盘上的旧配置
    复制成 <配置文件>.bak（shutil.copy2，含 mtime）。只保留一份：下一次
    保存直接覆盖上一次的备份，不编号、不累积、不放别的目录。
  * 目标文件不存在（首次保存）→ 不产生 .bak，也不报错；内容与磁盘完全
    相同 → 跳过备份（先比文件尺寸，尺寸相同才读文件比对），避免每次
    退出都写一次盘。
  * 备份失败不阻断保存：捕获异常 → _record_error("save.backup", …)
    → 继续 os.replace。保存成功率优先于备份完整性。
  * 用户可见：配置文件旁多一个 crypto_tool_config.json.bak，它就是
    「上一次保存之前的那份配置」，改名回来即可回滚；/health 新增
    config_file / backup_file / backup_exists 三个字段。
  * 事故背景：一次探针隔离打错桩，把测试态（params={}、default_layers=[]、
    空 RSA 公钥）save_config(force=True) 覆盖进真实配置，33 个算法的
    配置瞬间归零。原子替换保证不写一半，但不保证能回滚。

v1.3.12 变更（相对 1.3.11，review_round3 F-06 真因收口）：
  * 【F-06 真因】handled 的判据从「params[name] 是不是 dict」改成
    「有没有真的应用过有效层」：新增 _layer_effective / _layers_effective，
    一个层算有效当且仅当 algorithm != "none"，或 encode_before / encode_after
    至少一个非 "none" 编码名。{}、{"layers": []}、
    {"layers": [{"algorithm": "none"}]}、{"algo": "none"}（键名错）现在
    与「未配置」完全等价：两个方向都逐字节不变。有编码层的
    （{"algorithm": "none", "encode_after": ["base64"]}）照旧处理。
  * 同一判据也用在 default_layers 上：全是 algorithm=none 的默认层
    不再让字段进入 quote/unquote。

v1.3.11 变更（相对 1.3.10，review_round3 第二轮：F-01…F-09 + R-12）：
  * 【F-01】base64/hex/base32 解码出来的二进制（PNG 之类）不再被当成
    「明文非 UTF-8」：该字段原样保留（与 1.3.9 可见行为一致），失败仍进
    /last-errors；多字段 body 里其它字段的正常结果不再被整条顶掉。
  * 【F-02】「非 UTF-8」错误文案改为按 requestorresponse 走两段式，
    rr=request/response 时补 4×CRLF，插件 arr.length 不再是 1。
  * 【F-03】/encode 的同类文案措辞改成「处理失败」，与 /decode 的
    「解密失败」区分。
  * 【F-04】SM2 公钥长度提示改准确（旧文案对 130 位非 04 开头的情形
    自相矛盾）。
  * 【F-05】算法名 "none"（只走编解码）不再被 R-02 误报成
    「algorithm: 'none' → none」。
  * 【F-06】配置畸形的参数（不是对象）在没有有效处理层时不再被
    quote/unquote：字节逐字不变，只剩一条类型提示。
  * 【F-07】default_layers 分支处理同名键时与主路径一样发同名提示。
  * 【F-08】同名键提示上的次数改成「键的实际出现次数」，并注明其中
    带值可处理的个数。
  * 【F-09】启动打印的表单上限改为读取 app.config，与 /health、413 一致。
  * 【R-12】配置文件读取增加父目录只读回退：脚本同目录没有、上一级目录
    有时读上一级那份（保存仍写脚本同目录，旧文件不动）；环境变量优先级
    不变。

v1.3.10 变更（相对 1.3.9，review_round3 的 R-01…R-11）：
  * 【R-01】form_url_coded 只作用于「本次真正被处理」的字段：以前整条 body
    每个字段都 unquote/quote，未配置的 x=%E4%B8%AD 会被二次编码成
    x=%25E4%25B8%25AD、x=中 会被编码成 x=%E4%B8%AD。现在按
    _process_top_pairs 的命中结果逐字段决定。
  * 【R-02】配置规范化不再静默：未知算法名→none、非法编码值丢弃、
    非法 scope→auto、param 非对象→空配置，四类改写都会收集成提示，
    启动打印一次、主菜单打印一次（不阻断启动），并可从 /health、
    /last-errors 查询。
  * 【R-03】SM2 解密自行重算 C3 并比对：gmssl 只算不校验，篡改 C3
    以前照样返回明文，现在直接报错。
  * 【R-04】SM2 公钥先规范化：只有「130 位 hex 且以 04 开头」才切掉
    前 2 个字符；gmssl 内部用 lstrip("04") 按字符集剥离，0400… 会被
    剥成 126 位，现在不会再被二次截断。
  * 【R-05】GCM/CCM/EAX 的 nonce 长度按模式校验（CCM 7-13 字节、
    GCM/EAX 8-128 字节），越界报错写明要求与当前长度。
  * 【R-06】JSON 嵌套深度 > 8 时记一条错误，不再静默跳过。
  * 【R-07】param 配置不是对象时先判类型，记录「参数名 + 实际类型」，
    不再抛 'str' object has no attribute 'get'。
  * 【R-08】同名 form 键全处理并记一条提示，不再只处理第一个。
  * 【R-09】启动打印 500 KB 表单上限，413 错误文案给出处置建议。
  * 【R-10】/decode 遇到非法 UTF-8 返回明确错误（含「非 UTF-8」字样与
    偏移/字节数/成因），不再返回乱码或抛 UnicodeDecodeError 栈。
  * 【R-11】data_mode=auto 改为「先试 JSON 扫描成功→json；失败再看 =」，
    判定结果写入 trace，[{"q":"a=b"}] 不再被当成 form 拆坏。
  * 新增 GET /health（版本、配置提示、表单上限、参数数量）。

v1.3.8 变更（相对 1.3.7）：
  * 【扩容】对称分组增加 CFB8（segment_size=8），AES 增加 CCM / EAX，
    并新增 AEAD tag 位置（tail/head）与 tag 长度配置。
  * 【扩容】SM4 增加 CFB / CFB8 / OFB / CTR（用 ECB 块运算自行构造），
    并对 mode 做白名单校验，不再静默降级成 ECB。
  * 【扩容】新增流密码 ChaCha20 / Salsa20。
  * 【扩容】摘要增加 SHA-224 / SHA-384 / SHA3-256 / SHA3-512 /
    RIPEMD-160 / BLAKE2b；HMAC 增加 sha224 / sha384 / sha3-256 / sm3。
  * 【扩容】新增签名算法 RSA（PKCS1v15 / PSS）与 SM2（SM3 摘要），均为单向。

v1.3.7 变更（相对 1.3.6）：
  * 【修复】JSON body 改为保形处理：只替换被处理字段的值区间，
    不再用 json.dumps 重建整个 body —— 缩进/空格、数字字面量
    （2.50 -> 2.5）、键顺序都不再被改写，整包签名不再被打乱。
  * 【新增】错误可见性：失败不再只打印一行，改为
      · 结构化记录（内存环形缓冲，最多 50 条）
      · GET /last-errors 查看最近失败（不影响流量）
      · 可选 fail_mode=http_500，失败时直接以 500 返回给调用方
  * 【新增】进阶配置 → 8 失败处理方式（passthrough / http_500）

终版功能清单：
  * 配置持久化：算法 / 参数 / 设置 / 语言 自动保存与恢复
  * 多层加解密（编码 → 算法 → 编码 / 反向）
  * 每步 debug trace（逐层、逐编码打印输入输出）
  * 参数级作用域 scope：auto / form / json / req_header / resp_header
  * 参数处理顺序 = 数据包处理顺序（可调整）
  * JSON 字符串内部字段处理（如 data 里的 password）
  * 整包：__req_body__（/encode 触发）、__resp_body__（/decode 触发）
  * 请求头 / 响应头字段处理
  * 参数列表选择（删除/编辑/重命名不再手输）
  * 删除参数包含整包（修复版）
  * 整包空壳自动清理
"""

import os
import re
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
import collections
import shutil

from urllib.parse import quote, unquote

# [H4] Windows 控制台默认 GBK：`debug_print` 里的裸 print 遇到 emoji / 生僻字会抛
# UnicodeEncodeError，而那段 print 位于 try 之外 → Flask 直接吐 500 HTML，插件只看到
# Format error，/last-errors 里还查不到。这里一次性把两个流的错误策略改成替换，
# 任何不可编码字符退化成 \uXXXX 转义，不再中断请求。
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(errors="backslashreplace")
    except Exception:
        pass

VERSION = "1.3.15"

RESERVED_REQ_BODY = "__req_body__"
RESERVED_RESP_BODY = "__resp_body__"
RESERVED_BODY_NAMES = (RESERVED_REQ_BODY, RESERVED_RESP_BODY)
OLD_BODY_PARAM_NAME = "__body__"

SCOPE_AUTO = "auto"
SCOPE_FORM = "form"
SCOPE_JSON = "json"
SCOPE_REQ_HEADER = "req_header"
SCOPE_RESP_HEADER = "resp_header"
VALID_SCOPES = (SCOPE_AUTO, SCOPE_FORM, SCOPE_JSON, SCOPE_REQ_HEADER, SCOPE_RESP_HEADER)

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


def _pem_summary(text):
    if not text:
        return t("(空)", "(empty)")
    text = text.strip()
    if "-----BEGIN" in text:
        lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
        head = lines[0] if lines else ""
        tail = ""
        for ln in reversed(lines):
            if "-----END" in ln:
                tail = ln
                break
        body_len = sum(len(ln) for ln in lines if "-----" not in ln)
        return f"{head}  …  ({body_len} chars base64)  …  {tail}"
    compact = "".join(text.split())
    if len(compact) > 40:
        return f"{compact[:16]}…{compact[-16:]}  ({len(compact)} chars)"
    return compact or t("(空)", "(empty)")


def _clean_pem(text):
    if not text:
        return ""
    lines = [ln.rstrip() for ln in text.splitlines()]
    non_empty = [ln for ln in lines if ln.strip()]
    if not non_empty:
        return ""
    begin_idx = None
    for i, ln in enumerate(non_empty):
        s = ln.strip()
        if s.startswith("-----BEGIN ") and s.endswith("-----"):
            begin_idx = i
            break
    if begin_idx is not None:
        end_idx = None
        for j in range(begin_idx + 1, len(non_empty)):
            s = non_empty[j].strip()
            if s.startswith("-----END ") and s.endswith("-----"):
                end_idx = j
                break
        if end_idx is not None:
            pem_lines = [non_empty[begin_idx].strip()]
            for ln in non_empty[begin_idx + 1:end_idx]:
                body = "".join(ln.split())
                if body:
                    pem_lines.append(body)
            pem_lines.append(non_empty[end_idx].strip())
            return "\n".join(pem_lines)
    return "".join("".join(non_empty).split())


def ask_pem(prompt, default=None):
    print(f"  {C.CYA}❯{C.R} {prompt}")
    hint_text = t(
        "支持直接粘贴 PEM 或纯 Base64（可含换行、空行），粘贴完成后：\n"
        "      · Windows：按 Ctrl+Z 再回车结束\n"
        "      · Linux / macOS：按 Ctrl+D 再回车结束\n"
        "      · 直接按上述组合键（不粘贴任何内容）= 保持当前值",
        "Paste PEM or plain Base64 (line breaks and blank lines allowed). To finish:\n"
        "      · Windows: press Ctrl+Z then Enter\n"
        "      · Linux/macOS: press Ctrl+D then Enter\n"
        "      · Press the combo immediately (paste nothing) = keep current value"
    )
    print(f"    {C.GRY}{hint_text}{C.R}")
    if default:
        print(f"    {C.GRY}{t('当前值', 'Current')}: {_pem_summary(default)}{C.R}")
    lines = []
    while True:
        try:
            line = input("      ")
        except EOFError:
            break
        except KeyboardInterrupt:
            print()
            return default if default is not None else ""
        lines.append(line)
    if not lines:
        return default if default is not None else ""
    raw = "\n".join(lines)
    cleaned = _clean_pem(raw)
    if not cleaned:
        return default if default is not None else ""
    return cleaned


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


BLOCK_MODES = ["CBC", "ECB", "CFB", "CFB8", "OFB", "CTR"]
BLOCK_MODES_AES = ["CBC", "ECB", "CFB", "CFB8", "OFB", "CTR", "GCM", "CCM", "EAX"]
BLOCK_MODES_SM4 = ["CBC", "ECB", "CFB", "CFB8", "OFB", "CTR"]
PADDINGS = ["pkcs7", "pkcs5", "zero", "iso7816", "ansiX923", "none"]
PADDINGS_SM4 = ["pkcs7", "pkcs5", "zero", "none"]
RSA_PADS = ["pkcs1_v1_5", "oaep"]
RSA_SIGN_PADS = ["pkcs1_v1_5", "pss"]
RSA_OAEP_HASH = ["sha1", "sha256", "sha384", "sha512"]
SM2_MODES = ["C1C3C2", "C1C2C3"]
AEAD_MODES = ("GCM", "CCM", "EAX")
STREAM_MODES = {"CFB", "CFB8", "OFB", "CTR", "GCM", "CCM", "EAX"}


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
            _ch("tag_position", "AEAD tag 位置", "AEAD tag position",
                ["tail", "head"], "tail"),
            _txt("tag_length", "AEAD tag 长度（字节）", "AEAD tag length (bytes)", "16"),
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
        "fields": [_bf("key", "密钥 Key", "Key")],
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
    "chacha20": {
        "label": "ChaCha20", "category": CAT_SYM, "block_size": 1,
        "cipher": None, "dep": "pycryptodome",
        "fields": [
            _bf("key", "密钥 Key（32 字节）", "Key (32 bytes)"),
            _bf("iv", "Nonce（8/12/24 字节）", "Nonce (8/12/24 bytes)"),
        ],
    },
    "salsa20": {
        "label": "Salsa20", "category": CAT_SYM, "block_size": 1,
        "cipher": None, "dep": "pycryptodome",
        "fields": [
            _bf("key", "密钥 Key（16/32 字节）", "Key (16/32 bytes)"),
            _bf("iv", "Nonce（8 字节）", "Nonce (8 bytes)"),
        ],
    },
    "rsa": {
        "label": "RSA", "category": CAT_ASYM, "dep": "pycryptodome",
        "fields": [
            _pem("public_key", "公钥（PEM 或纯 Base64）",
                 "Public Key (PEM or pure Base64)"),
            _pem("private_key", "私钥（PEM 或纯 Base64）",
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

    # ---- v1.3.8 扩容：更多摘要 ----
    "sha224": {"label": "SHA-224", "category": CAT_HASH, "oneway": True,
               "dep": None, "fields": []},
    "sha384": {"label": "SHA-384", "category": CAT_HASH, "oneway": True,
               "dep": None, "fields": []},
    "sha3-256": {"label": "SHA3-256", "category": CAT_HASH, "oneway": True,
                 "dep": None, "fields": []},
    "sha3-512": {"label": "SHA3-512", "category": CAT_HASH, "oneway": True,
                 "dep": None, "fields": []},
    "ripemd160": {"label": "RIPEMD-160", "category": CAT_HASH, "oneway": True,
                  "dep": None, "fields": []},
    "blake2b": {"label": "BLAKE2b", "category": CAT_HASH, "oneway": True,
                "dep": None, "fields": []},

    # ---- v1.3.8 扩容：更多 HMAC ----
    "hmac-sha224": {
        "label": "HMAC-SHA224", "category": CAT_HASH, "oneway": True,
        "dep": None, "hmac_hash": "sha224",
        "fields": [_bf("key", "HMAC 密钥", "HMAC Key")],
    },
    "hmac-sha384": {
        "label": "HMAC-SHA384", "category": CAT_HASH, "oneway": True,
        "dep": None, "hmac_hash": "sha384",
        "fields": [_bf("key", "HMAC 密钥", "HMAC Key")],
    },
    "hmac-sha3-256": {
        "label": "HMAC-SHA3-256", "category": CAT_HASH, "oneway": True,
        "dep": None, "hmac_hash": "sha3_256",
        "fields": [_bf("key", "HMAC 密钥", "HMAC Key")],
    },
    "hmac-sm3": {
        "label": "HMAC-SM3", "category": CAT_HASH, "oneway": True,
        "dep": None, "hmac_hash": "sm3",
        "fields": [_bf("key", "HMAC 密钥", "HMAC Key")],
    },

    # ---- v1.3.8 扩容：签名（单向） ----
    "rsa-sign": {
        "label": "RSA 签名", "category": CAT_ASYM, "oneway": True,
        "dep": "pycryptodome",
        "fields": [
            _pem("private_key", "私钥（PEM 或纯 Base64）",
                 "Private Key (PEM or pure Base64)"),
            _ch("padding", "签名填充", "Signature padding",
                RSA_SIGN_PADS, "pkcs1_v1_5"),
            _ch("sign_hash", "摘要算法", "Digest", RSA_OAEP_HASH, "sha256"),
        ],
    },
    "sm2-sign": {
        "label": "SM2 签名", "category": CAT_ASYM, "oneway": True,
        "dep": "gmssl",
        "fields": [
            _txt("private_key", "私钥（hex，64 字符）",
                 "Private Key (hex, 64 chars)", ""),
            _txt("public_key", "公钥（hex，128 字符，用于 Z 值）",
                 "Public Key (hex, 128 chars, used for Z)", ""),
        ],
    },
}

ALGO_ORDER = [
    "aes", "des", "3des", "blowfish", "cast", "rc2", "rc4", "sm4",
    "chacha20", "salsa20",
    "rsa", "sm2", "rsa-sign", "sm2-sign",
    "md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sm3",
    "sha3-256", "sha3-512", "ripemd160", "blake2b",
    "hmac-md5", "hmac-sha1", "hmac-sha224", "hmac-sha256", "hmac-sha384",
    "hmac-sha512", "hmac-sha3-256", "hmac-sm3",
]

ENC_LABEL = {
    "none": "无", "url": "URL", "base64": "Base64", "base64url": "Base64URL",
    "hex": "Hex", "base32": "Base32", "html": "HTML", "unicode": "Unicode",
}
ENC_LABEL_EN = {
    "none": "none", "url": "URL", "base64": "Base64", "base64url": "Base64URL",
    "hex": "Hex", "base32": "Base32", "html": "HTML", "unicode": "Unicode",
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


def _display_param_name(name):
    if name == RESERVED_REQ_BODY:
        return t("📦 请求体", "📦 Request Body")
    if name == RESERVED_RESP_BODY:
        return t("📦 响应体", "📦 Response Body")
    if name == OLD_BODY_PARAM_NAME:
        return t("📦 请求体(旧)", "📦 Request Body (legacy)")
    return name


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
        "chacha20": {"key": "12345678901234567890123456789012",
                     "iv": "12345678"},
        "salsa20": {"key": "12345678901234567890123456789012",
                    "iv": "12345678"},
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


def empty_param_config():
    return {"layers": [], "scope": SCOPE_AUTO}


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
            # [Low] 原来默认 0.0.0.0 = 把加解密中继直接开到同网段所有人可访问
            "host": "127.0.0.1",
            "port": 8888,
            # [Low] 非空时 /encode /decode /last-errors 都要求令牌
            "api_token": "",
            "clear_on_menu": True,
            # passthrough：失败时返回原值（老行为）
            # http_500   ：失败时返回 500 + 错误文本，让调用方直接看见
            "fail_mode": "passthrough",
            "error_log": "",
        }


state = Config()


# =====================================================================
# 配置持久化
# =====================================================================
CONFIG_ENV_VAR = "CRYPTO_TOOL_CONFIG"
CONFIG_FILENAME = "crypto_tool_config.json"

_save_error_shown = False


# [M2] 配置自毁防护：load_config() 失败时记下路径，
# save_config() 遇到同一路径就拒绝写回，避免用默认值把用户配置覆盖掉。
_CONFIG_LOAD_FAILED = None
_config_err_shown = False


def _config_base_dir():
    return os.path.dirname(os.path.abspath(__file__))


def config_path():
    """配置**读取**路径（[R-12] 带父目录只读 fallback）。

    优先级：环境变量 CRYPTO_TOOL_CONFIG > 脚本同目录 > 上一级目录。
    以前只有前两级：把 Template.py 放进 Template\\ 子目录以后，仍留在
    autoDecoder\\ 的那份真配置（用户辛苦配的 33 个算法）永远读不到，
    每次启动都是「未找到配置文件」+ 一套空默认值，而保存又会把一份新配置
    写进 Template\\ —— 两份文件长期并存，用户看到的行为和自己手里的文件对不上。
    这里只做**读取**回退：文件不会被搬动、更不会被删除。
    """
    override = os.environ.get(CONFIG_ENV_VAR)
    if override:
        return os.path.abspath(os.path.expanduser(override))
    base = _config_base_dir()
    local = os.path.join(base, CONFIG_FILENAME)
    if os.path.isfile(local):
        return local
    parent = os.path.dirname(base)
    if parent and parent != base:
        legacy = os.path.join(parent, CONFIG_FILENAME)
        if os.path.isfile(legacy):
            return legacy
    return local


def config_write_path():
    """配置**写入**路径：永远写脚本同目录，不写回上层目录。"""
    override = os.environ.get(CONFIG_ENV_VAR)
    if override:
        return os.path.abspath(os.path.expanduser(override))
    return os.path.join(_config_base_dir(), CONFIG_FILENAME)


def config_backup_path():
    """[R-14] 配置备份路径：固定为写入路径 + `.bak`，不换目录、不编号。

    只保留一份：下一次保存直接覆盖上一次的备份。用户看到 `.bak` 时，
    它就是"上一次保存之前的那份配置"，改名回来即可回滚。
    """
    return config_write_path() + ".bak"


_CONFIG_FALLBACK_SHOWN = [False]


# ---------------------------------------------------------------------
# [R-02] 配置规范化提示
#
# 以前 _coerce_* 系列是"静默修复"：未知算法名→none、非法编码值丢弃、
# 非法 scope→auto、param 非对象→空配置。用户在菜单里看到的是默认值，
# 却完全不知道自己写的配置被吃掉了，而且第一次改写往往就是加密对不上。
# 现在统一收集成清单：启动打印一次、主菜单打印一次（不阻断启动），
# 并可从 GET /health 与 GET /last-errors 复查。
# ---------------------------------------------------------------------
_CONFIG_NOTES = []
_CONFIG_NOTE_SEEN = set()
_CONFIG_REPORT_DONE = set()


def _note_config(msg):
    key = str(msg)
    if key in _CONFIG_NOTE_SEEN:
        return
    _CONFIG_NOTE_SEEN.add(key)
    _CONFIG_NOTES.append(key)


def _reset_config_notes():
    del _CONFIG_NOTES[:]
    _CONFIG_NOTE_SEEN.clear()
    _CONFIG_REPORT_DONE.clear()


def config_notes():
    return list(_CONFIG_NOTES)


def _report_config_notes(sink="startup", verbose=True, force=False):
    """打印配置规范化提示（按调用点各报一次，主菜单循环不会刷屏）。"""
    notes = config_notes()
    if not notes:
        return 0
    if sink in _CONFIG_REPORT_DONE and not force:
        return len(notes)
    _CONFIG_REPORT_DONE.add(sink)
    if verbose:
        warn(t(f"配置有 {len(notes)} 处被规范化（已继续启动）：",
               f"{len(notes)} config value(s) were normalized (startup continues):"))
        for n in notes:
            print(f"      {C.GRY}·{C.R} {n}")
        info(t("→ 若上述字段本应生效，请手动改回；菜单「进阶配置」与 /health 可复查",
               "→ Fix those fields by hand if they mattered; "
               "see 进阶配置 or /health"))
    return len(notes)


def _coerce_bytes_field(saved, current, label=""):
    if isinstance(saved, dict):
        enc = saved.get("encoding", "text")
        if enc not in ("text", "hex", "base64"):
            # [R-02] 非法编码值以前静默改成 text（等于把 hex 当明文用），现在记一条
            # 空值 = 该字段没配 → 保持默认，不算「被规范化」，不打扰用户
            if label and enc not in ("", None):
                _note_config(f"{label}.encoding: {enc!r} → text")
            enc = "text"
        val = saved.get("value", "")
        return {"value": str(val) if val is not None else "", "encoding": enc}
    if isinstance(saved, str):
        return {"value": saved, "encoding": "text"}
    if isinstance(current, dict):
        return dict(current)
    return {"value": "", "encoding": "text"}


def _coerce_layers(raw, label=""):
    out = []
    base = label or "layers"
    if not isinstance(raw, list):
        # [R-02] 非数组以前静默变空，配置里的层全部蒸发且毫无痕迹
        if raw not in (None, []):
            _note_config(f"{base}: 不是数组（{type(raw).__name__}）→ 已丢弃")
        return out
    for idx, l in enumerate(raw):
        where = f"{base}[{idx}]"
        if not isinstance(l, dict):
            _note_config(f"{where}: 不是对象（{type(l).__name__}）→ 已丢弃")
            continue
        alg = l.get("algorithm", "none")
        # [F-05] "none" 不在 ALGO_DEFS（33 项全是真算法），但它是菜单
        # choose_algorithm() 的第 1 项，代表「只走编解码、不做加解密」。
        # 以前没放行它 → 用户保存一份"仅编码层"配置，下次启动就被提示
        # "algorithm: 'none' → none"，把 R-02 的提示变成噪音。
        if alg != "none" and alg not in ALGO_DEFS:
            # [R-02] 关键：未知算法名以前变 none，等于该字段明文透传
            _note_config(f"{where}.algorithm: {alg!r} → none")
            alg = "none"

        def _chain(key):
            vals = l.get(key) or []
            if not isinstance(vals, list):
                _note_config(f"{where}.{key}: 不是数组（{type(vals).__name__}）→ 已丢弃")
                return []
            kept = []
            for v in vals:
                if isinstance(v, str) and v in ENC_CHOICES and v != "none":
                    kept.append(v)
                else:
                    # [R-02] 非法编码值以前静默丢弃（少一层编解码=密文对不上）
                    _note_config(f"{where}.{key}: 丢弃非法编码值 {v!r}")
            return kept

        out.append({
            "algorithm": alg,
            "encode_before": _chain("encode_before"),
            "encode_after": _chain("encode_after"),
        })
    return out


def _coerce_param_config(raw, name=""):
    label = name or "params.<unnamed>"
    if not isinstance(raw, dict):
        # [R-02] param 非对象以前静默变空配置，等于该参数完全不处理
        _note_config(f"{label}: 不是对象（{type(raw).__name__}）→ 空配置")
        return empty_param_config()
    layers = _coerce_layers(raw.get("layers"), label=f"{label}.layers")
    scope = raw.get("scope", SCOPE_AUTO)
    if scope not in VALID_SCOPES:
        # [R-02] 非法 scope 以前静默变 auto（作用域全开，可能误伤别的字段）
        # 空值/缺省 = 没配作用域，等同于 auto，不打扰用户
        if scope not in ("", None):
            _note_config(f"{label}.scope: {scope!r} → auto")
        scope = SCOPE_AUTO
    return {"layers": layers, "scope": scope}


def load_config(verbose=False):
    global current_lang, _CONFIG_LOAD_FAILED, _config_err_shown
    path = config_path()
    # [R-12] 用的是上层目录那份（本目录还没有）→ 一次提示，说明保存会落到哪儿
    _write_back = config_write_path()
    if (not _CONFIG_FALLBACK_SHOWN[0]
            and os.path.isfile(path)
            and os.path.abspath(path) != os.path.abspath(_write_back)):
        _CONFIG_FALLBACK_SHOWN[0] = True
        info(t(f"配置文件读自上层目录：{path}",
               f"Loaded config from the parent directory: {path}"))
        info(t(f"→ 本次保存会写到 {_write_back}（旧文件保持原样，不会删除或改写）",
               f"→ Saves will go to {_write_back} (the old file is left untouched)"))
    if not os.path.isfile(path):
        if verbose:
            info(t(f"未找到配置文件：{path}（将使用默认配置）",
                   f"No config file found: {path} (using defaults)"))
        # 文件不存在 = 首次使用，允许后续保存
        _CONFIG_LOAD_FAILED = None
        return False
    try:
        # [M2] utf-8-sig：带 BOM 的配置（记事本另存、某些编辑器）以前会直接解析失败，
        # 然后被"静默失败 + 后面一保存就覆盖"的组合毁掉。
        with open(path, "r", encoding="utf-8-sig") as fh:
            data = json.load(fh)
    except Exception as e:
        _CONFIG_LOAD_FAILED = path
        if verbose or not _config_err_shown:
            _config_err_shown = True
            err(t(f"配置文件读取失败：{path}（{e}）",
                  f"Failed to read config: {path} ({e})"))
            err(t("→ 本次运行已禁用自动保存，避免用默认值覆盖你的配置；"
                  "修好该文件（或删除它）后重启即可恢复。",
                  "→ Auto-save is disabled for this run to protect your config; "
                  "fix or delete the file and restart."))
        return False
    if not isinstance(data, dict):
        _CONFIG_LOAD_FAILED = path
        if verbose or not _config_err_shown:
            _config_err_shown = True
            err(t(f"配置文件格式不正确（顶层不是对象）：{path}",
                  f"Config file has invalid format (top level is not an object): {path}"))
            err(t("→ 本次运行已禁用自动保存，避免覆盖该文件。",
                  "→ Auto-save is disabled for this run to protect the file."))
        return False
    _CONFIG_LOAD_FAILED = None
    _config_err_shown = False
    _reset_config_notes()

    lang = data.get("lang")
    if lang in ("zh", "en"):
        current_lang = lang

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
                    state.settings[k] = _coerce_layers(
                        v, label="settings.default_layers")
        if not (1 <= state.settings.get("port", 8888) <= 65535):
            # [R-02] 端口非法以前静默回落 8888
            _note_config(f"settings.port: {saved_settings.get('port')!r} → 8888")
            state.settings["port"] = 8888
        if state.settings.get("data_mode") not in ("auto", "json", "form"):
            # [R-02] data_mode 非法以前静默回落 auto
            _note_config(
                f"settings.data_mode: {state.settings.get('data_mode')!r} → auto")
            state.settings["data_mode"] = "auto"
        if not isinstance(state.settings.get("host"), str) or not state.settings["host"]:
            _note_config(f"settings.host: {state.settings.get('host')!r} → 127.0.0.1")
            state.settings["host"] = "127.0.0.1"
        if state.settings.get("fail_mode") not in ("passthrough", "http_500"):
            _note_config(
                f"settings.fail_mode: {state.settings.get('fail_mode')!r} → passthrough")
            state.settings["fail_mode"] = "passthrough"
        if not isinstance(state.settings.get("error_log"), str):
            _note_config("settings.error_log: 不是字符串 → 空")
            state.settings["error_log"] = ""

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
                    cfg[fk] = _coerce_bytes_field(v, cfg[fk], label=f"algo.{key}.{fk}")
                elif f["kind"] == "choice":
                    if isinstance(v, str) and v in f["choices"]:
                        cfg[fk] = v
                    elif v == "" or v is None:
                        # 空值 = 该字段没配，保持默认即可，不算「被规范化」，不打扰用户
                        pass
                    else:
                        _note_config(
                            f"algo.{key}.{fk}: {v!r} → 保持默认 {cfg[fk]!r}")
                else:
                    cfg[fk] = v if isinstance(v, str) else str(v)
            state.algo[key] = cfg

    saved_params = data.get("params")
    if isinstance(saved_params, dict):
        clean = {}
        for name, pcfg in saved_params.items():
            if not isinstance(name, str):
                continue
            if name == OLD_BODY_PARAM_NAME:
                if RESERVED_REQ_BODY not in saved_params:
                    clean[RESERVED_REQ_BODY] = _coerce_param_config(
                        pcfg, name=RESERVED_REQ_BODY)
                continue
            clean[name] = _coerce_param_config(pcfg, name=f"params.{name}")
        state.params = clean

    if verbose:
        ok(t(f"已加载配置：{path}", f"Config loaded: {path}"))
    return True


_SAVED_AT_RE = re.compile(r'"saved_at"\s*:\s*"[^"]*"')


def _config_core(text):
    """[R-14] 把 `_meta.saved_at` 抹平后再比较：只存了一次的退出不该产生备份。

    每份配置都带 `"saved_at": "YYYY-MM-DD HH:MM:SS"`（定长 19 字符），所以
    两次保存的字节长度几乎总是相等——尺寸比较挡不住"只是时间戳变了"。
    真正要判断的是"用户配置有没有变"，时间戳是元数据，不是配置内容。
    """
    if not isinstance(text, str):
        return None
    return _SAVED_AT_RE.sub('"saved_at": ""', text)


def _save_config_backup(path, payload, new_size=None):
    """[R-14] 覆盖前把磁盘上的旧配置留在 `<path>.bak`，返回处置结果字符串。

    背景（真实事故，不是理论风险）：一次探针隔离打错桩，把测试态的
    `params={}` / `default_layers=[]` / 空 RSA 公钥通过 save_config() 覆盖进了
    真实配置，33 个算法的配置瞬间归零。`os.replace()` 保证的是原子性
    ——要么旧文件、要么新文件，不会写一半——但它**不提供回滚**：替换成功
    的那一刻旧内容就没了。所以覆盖前必须自己留一份。

    返回：
        "absent"  目标文件不存在 → 跳过（首次保存，没有"旧配置"可备）
        "same"    内容与将要写入的完全相同 → 跳过（避免每次退出都写盘）
        "copied"  已备份到 `<path>.bak`
        "failed"  备份本身出错 → 记一条错误后照常保存（保存成功率优先）
    """
    if not os.path.exists(path):
        return "absent"
    try:
        # new_size 传的是已经落到 .tmp 的真实字节数：Windows 文本模式会把 \n 写成
        # \r\n，用 len(payload.encode()) 比尺寸会永远差上行数，等于从不判断。
        if new_size is None:
            new_size = len(payload.encode("utf-8"))
        try:
            old_size = os.path.getsize(path)
        except OSError:
            old_size = -1
        if old_size == new_size:
            # [R-14] 先比尺寸再比内容：尺寸不同直接备份，别为一次退出多读一整份配置
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    old_text = fh.read()
            except OSError:
                old_text = None
            if _config_core(old_text) == _config_core(payload):
                return "same"
        shutil.copy2(path, path + ".bak")
        return "copied"
    except Exception as e:
        # 备份是"额外保障"，不能反过来把保存本身拖垮
        _record_error("save.backup", t(
            f"配置备份失败（保存继续，未产生 .bak）：{path}.bak ← {e}",
            f"Config backup failed (save continues, no .bak): {path}.bak <- {e}"))
        return "failed"


def save_config(verbose=False, force=False):
    global _save_error_shown
    # [R-12] 写入一律走 config_write_path()：读可能来自上层目录，写不回上层目录
    path = config_write_path()
    # [M2] 读失败过就绝不写回：以前 load 失败 → 静默用默认值 →
    # 用户随手点一个菜单项 → finally 里 save_config() → 原配置被默认值覆盖。
    # [R-12] 判据改成"任何一次读取失败"（不再比字符串路径）：读取路径可能是
    # 上层目录那份，写入路径却是脚本同目录，比路径会漏掉这道防护。
    if not force and _CONFIG_LOAD_FAILED is not None:
        if verbose or not _save_error_shown:
            _save_error_shown = True
            err(t(f"跳过保存：配置读取失败（{_CONFIG_LOAD_FAILED}），写入会覆盖 {path}",
                  f"Save skipped: config load failed ({_CONFIG_LOAD_FAILED}); "
                  f"writing would overwrite {path}"))
        return False
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
    tmp = path + ".tmp"          # [Low] 提到 try 外，异常时才能清理残留
    try:
        folder = os.path.dirname(path)
        if folder and not os.path.isdir(folder):
            os.makedirs(folder, exist_ok=True)
        # [R-14] 先序列化到内存：备份前要拿"将要写入的内容"跟磁盘上的比，
        # 比对用的是 payload 的长度（先比尺寸，相同才读旧文件），不额外多读一遍。
        payload = json.dumps(data, ensure_ascii=False, indent=2)
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(payload)
        # [R-14] 覆盖前留一份 .bak：只有"有新内容要写进同一个位置"时才备份，
        # 备份失败不阻断下面的 os.replace。
        backup = _save_config_backup(path, payload, os.path.getsize(tmp))
        os.replace(tmp, path)
        _save_error_shown = False
        if verbose:
            ok(t(f"配置已保存：{path}", f"Config saved: {path}"))
            if backup == "copied":
                info(t(f"上一次的配置已备份到 {path}.bak（改名回来即可回滚）",
                       f"Previous config backed up to {path}.bak "
                       f"(rename it back to roll back)"))
        return True
    except Exception as e:
        # [Low] 失败时清掉半截 .tmp，别在用户目录里留垃圾
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass
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
    if key == "rsa-sign":
        return bool((cfg.get("private_key") or "").strip())
    if key == "sm2":
        return bool((cfg.get("public_key") or "").strip()
                    and (cfg.get("private_key") or "").strip())
    if key == "sm2-sign":
        return bool((cfg.get("public_key") or "").strip()
                    and (cfg.get("private_key") or "").strip())
    if d.get("hmac_hash"):
        return bool(cfg.get("key", {}).get("value", "").strip())
    if d.get("category") == CAT_SYM:
        return bool(cfg.get("key", {}).get("value", "").strip())
    return True


# =====================================================================
# Base64 兼容编解码
# =====================================================================
def _b64d(s):
    if isinstance(s, bytes):
        try:
            s = s.decode('utf-8')
        except UnicodeDecodeError:
            s = s.decode('latin-1')
    s = str(s)
    s = s.replace(' ', '+')
    s = s.replace('-', '+').replace('_', '/')
    s = ''.join(s.split())
    s = s + '=' * (-len(s) % 4)
    return base64.b64decode(s)


def _b64e(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return base64.b64encode(data).decode('utf-8')


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


class NonUtf8Error(ValueError):
    """解密得到的字节不是合法 UTF-8（例如服务端明文其实用 GBK）。

    [F-01] soft=True 表示「这些字节本来就不该被当成文本」：它来自 base64/hex/
    base32 这类**编解码层**解出来的二进制（典型例子：一个字段是 PNG 的 base64）。
    这种失败只算该字段没解出来（原样透传），不能算「明文不是 UTF-8」，
    更不能把整条 /decode 响应顶掉。
    """

    def __init__(self, *args, **kwargs):
        self.soft = bool(kwargs.pop("soft", False))
        ValueError.__init__(self, *args, **kwargs)


def _to_text(data, where="", soft=False):
    """字节 → str；非法 UTF-8 抛 NonUtf8Error（可读、可上报到 /last-errors）。

    [R-10] 以前解密链路里到处是裸 data.decode("utf-8")：明文是 GBK 时
    要么抛 UnicodeDecodeError（被 catch 成 passthrough，插件只看到原密文），
    要么在 /decode 里直接吐 Python 栈。这里统一换成带成因说明的错误。

    [F-01] soft=True 用于编解码层（decode_step）：解出来是二进制属于正常情况，
    该失败不参与端点级别的「整条响应替换」判定。
    """
    if isinstance(data, str):
        return data
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as e:
        head = data[max(0, e.start - 2):e.start + 6]
        raise NonUtf8Error(t(
            f"非 UTF-8 明文（{where or '解密'}）：解密得到的 {len(data)} 字节无法按 "
            f"UTF-8 解码（{e.reason}，首个非法字节在偏移 {e.start}，"
            f"该处片段 0x{head.hex()}）。"
            f"常见原因：①服务端明文其实是 GBK/GB18030 ②Key/IV/Mode/MAC 配错 "
            f"③密文被截断或多套了一层编码",
            f"not valid UTF-8 ({where or 'decrypt'}): {len(data)}B cannot be decoded "
            f"({e.reason} at offset {e.start}, bytes 0x{head.hex()}). "
            f"Causes: GBK plaintext, wrong Key/IV/Mode/MAC, or truncated ciphertext"),
            soft=soft)
    except AttributeError:
        raise ValueError(t(
            f"{where or '解密'} 的返回值不是字节串（{type(data).__name__}）",
            f"{where or 'decrypt'} did not return bytes ({type(data).__name__})"))


# =====================================================================
# 加密引擎
# =====================================================================
def _cipher_module(key):
    name = ALGO_DEFS[key]["cipher"]
    return importlib.import_module(f"Crypto.Cipher.{name}")


def _tag_len(cfg):
    """AEAD tag 字节数（4..16，默认 16）。"""
    try:
        n = int(str(cfg.get("tag_length") or "16").strip() or 16)
    except Exception:
        n = 16
    return n if 4 <= n <= 16 else 16


def _tag_head(cfg):
    """AEAD tag 是否放在密文头部（默认尾部）。"""
    return str(cfg.get("tag_position") or "tail").strip().lower() == "head"


# [R-05] AEAD 各模式的 nonce 长度区间。以前 GCM/CCM/EAX 三者共用 iv 字段、
# 完全不做校验：CCM 直接抛 "Nonce of length 16 is not supported by CCM"
# （被 catch 成 passthrough，插件只看到原密文），GCM 用 8 字节 nonce 也不会
# 有人知道安全性已经打折。这里按模式给出区间，越界报错写明要求与当前长度。
AEAD_NONCE_RANGE = {"GCM": (8, 128), "CCM": (7, 13), "EAX": (8, 128)}


def _check_aead_nonce(mode, iv):
    lo, hi = AEAD_NONCE_RANGE.get(mode, (1, 128))
    n = len(iv or b"")
    if lo <= n <= hi:
        return n
    if n < lo:
        hint = t(f"请加长 iv（{mode} 至少 {lo} 字节）",
                 f"lengthen iv (at least {lo}B for {mode})")
    else:
        hint = t(f"请缩短 iv（{mode} 最多 {hi} 字节）",
                 f"shorten iv (at most {hi}B for {mode})")
    raise ValueError(t(
        f"{mode} 要求 nonce {lo}-{hi} 字节，当前 {n} 字节（iv 字段，"
        f"hex 编码时每字节 2 个字符）。{hint}",
        f"{mode} requires a {lo}-{hi} byte nonce, got {n}B in the iv field. {hint}"))


def _make_cipher(mod, key_b, mode, iv, algo, mac_len=16):
    mode = mode.upper()
    bs = ALGO_DEFS[algo]["block_size"]
    # [H1] RC2 的 effective_keylen：pycryptodome 默认 1024，
    # 而 openssl rc2-128 / 绝大多数服务端实现取「密钥位数本身」，
    # 两者用同一把 key 算出的密文完全不同（RFC 2268 官方向量对不上就是这么来的）。
    ek = {}
    if algo == "rc2":
        ek["effective_keylen"] = min(max(len(key_b) * 8, 1), 1024)
    # [H2] CFB 的 segment_size 和 CTR 的 counter 位宽必须跟着分组大小走。
    # 以前写死 128，导致 DES/3DES/Blowfish/CAST/RC2（64 位分组）在 CFB 抛
    # "segment_size 128 > block size"、在 CTR 抛 "counter block must match block size"。
    if mode == "CBC":
        return mod.new(key_b, mod.MODE_CBC, iv, **ek)
    if mode == "ECB":
        return mod.new(key_b, mod.MODE_ECB, **ek)
    if mode == "CFB":
        return mod.new(key_b, mod.MODE_CFB, iv, segment_size=min(128, bs * 8), **ek)
    if mode == "CFB8":
        return mod.new(key_b, mod.MODE_CFB, iv, segment_size=8, **ek)
    if mode == "OFB":
        return mod.new(key_b, mod.MODE_OFB, iv, **ek)
    if mode == "CTR":
        from Crypto.Util import Counter
        nbits = bs * 8
        ivb = (iv + b"\x00" * bs)[:bs]
        ctr = Counter.new(nbits, initial_value=int.from_bytes(ivb, "big"))
        return mod.new(key_b, mod.MODE_CTR, counter=ctr, **ek)
    if mode == "GCM":
        _check_aead_nonce(mode, iv)
        return mod.new(key_b, mod.MODE_GCM, nonce=iv, mac_len=mac_len, **ek)
    if mode == "CCM":
        _check_aead_nonce(mode, iv)
        return mod.new(key_b, mod.MODE_CCM, nonce=iv, mac_len=mac_len, **ek)
    if mode == "EAX":
        _check_aead_nonce(mode, iv)
        return mod.new(key_b, mod.MODE_EAX, nonce=iv, mac_len=mac_len, **ek)
    raise ValueError(t(f"不支持的加密模式：{mode}", f"Unsupported mode: {mode}"))


def _sym_encrypt(algo, text):
    cfg = state.algo[algo]
    mod = _cipher_module(algo)
    key_b = _b(cfg.get("key"))
    data = text.encode("utf-8")
    if algo == "rc4":
        return _b64e(mod.new(key_b).encrypt(data))
    bs = ALGO_DEFS[algo]["block_size"]
    mode = str(cfg.get("mode") or "CBC").upper()
    iv = _b(cfg.get("iv"))
    tag_len = _tag_len(cfg)
    cipher = _make_cipher(mod, key_b, mode, iv, algo, mac_len=tag_len)
    if mode in AEAD_MODES:
        ct, tag = cipher.encrypt_and_digest(data)
        tag = tag[:tag_len]
        raw = (tag + ct) if _tag_head(cfg) else (ct + tag)
        return _b64e(raw)
    if mode not in STREAM_MODES and cfg.get("padding") != "none":
        data = _pad(data, bs, cfg.get("padding", "pkcs7"))
    return _b64e(cipher.encrypt(data))


def _sym_decrypt(algo, text):
    cfg = state.algo[algo]
    mod = _cipher_module(algo)
    key_b = _b(cfg.get("key"))
    raw = _b64d(text)
    if algo == "rc4":
        return _to_text(mod.new(key_b).decrypt(raw), f"rc4·{algo}")
    bs = ALGO_DEFS[algo]["block_size"]
    mode = str(cfg.get("mode") or "CBC").upper()
    iv = _b(cfg.get("iv"))
    tag_len = _tag_len(cfg)
    cipher = _make_cipher(mod, key_b, mode, iv, algo, mac_len=tag_len)
    if mode in AEAD_MODES:
        if len(raw) < tag_len:
            raise ValueError(
                t(f"{mode} 密文过短（应包含 {tag_len} 字节 tag，实际 {len(raw)} 字节）",
                  f"{mode} ciphertext too short (expected {tag_len}-byte tag, got {len(raw)}B)"))
        if _tag_head(cfg):
            tag, ct = raw[:tag_len], raw[tag_len:]
        else:
            ct, tag = raw[:-tag_len], raw[-tag_len:]
        return _to_text(cipher.decrypt_and_verify(ct, tag), f"{algo}·{mode}")
    data = cipher.decrypt(raw)
    if mode not in STREAM_MODES and cfg.get("padding") != "none":
        try:
            data = _unpad(data, bs, cfg.get("padding", "pkcs7"))
        except ValueError as e:
            tail = ("0x%02x" % data[-1]) if data else "N/A"
            raise ValueError(
                t(f"{e}；当前密文 {len(raw)} 字节，解密后 {len(data)} 字节，"
                  f"末字节 {tail}。请检查 Key/IV/Mode/Padding 是否与服务器一致",
                  f"{e}; ciphertext={len(raw)}B, decrypted={len(data)}B, "
                  f"last byte={tail}. Check Key/IV/Mode/Padding")
            )
    return _to_text(data, f"{algo}·{mode}")


SM4_VALID_MODES = ("CBC", "ECB", "CFB", "CFB8", "OFB", "CTR")


def _sm4_block(key, block, decrypt=False):
    """单块 SM4 运算（无补块），用于自行构造 CBC/ECB/CFB/OFB/CTR。

    必须用 one_round，不能用 crypt_ecb：
    gmssl 的 crypt_ecb/crypt_cbc 内部无条件 PKCS#7 补块，
    16 字节输入会补成 32 字节；更糟的是解密方向会再 unpad 一次，
    标准 16 字节密文会被整块吃成空串且不报错。
    """
    from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT
    c = CryptSM4()
    c.set_key(key, SM4_DECRYPT if decrypt else SM4_ENCRYPT)
    return bytes(c.one_round(c.sk, block[:16]))


def _sm4_ecb(key, data, decrypt=False):
    """[M3] 纯 ECB，不留补块权给 gmssl。

    gmssl 的 crypt_ecb/crypt_cbc 内部无条件做 PKCS#7 补块，
    所以调用它们之前自己补一次 = 双重补块（16B 明文出 32B/48B 密文），
    与任何标准实现都不互通。这里只用无补块的块运算自己拼。
    """
    out = bytearray()
    for i in range(0, len(data), 16):
        out += _sm4_block(key, data[i:i + 16], decrypt)
    return bytes(out)


def _sm4_cbc(key, iv, data, decrypt=False):
    """[M3] 纯 CBC 链式，补块由调用方负责（与 _sm4_ecb 同理）。"""
    bs = 16
    iv = (iv + b"\x00" * bs)[:bs]
    out = bytearray()
    if decrypt:
        prev = iv
        for i in range(0, len(data), bs):
            blk = data[i:i + bs]
            plain = _sm4_block(key, blk, True)
            out += bytes(a ^ b for a, b in zip(plain, prev))
            prev = blk
    else:
        prev = iv
        for i in range(0, len(data), bs):
            blk = bytes(a ^ b for a, b in zip(data[i:i + bs], prev))
            enc = _sm4_block(key, blk)
            out += enc
            prev = enc
    return bytes(out)


def _sm4_stream(mode, data, key, iv, decrypt):
    """gmssl 只提供 ECB/CBC，这里用块运算自行实现 CFB/CFB8/OFB/CTR。"""
    bs = 16
    iv = (iv + b"\x00" * bs)[:bs]
    out = bytearray()
    if mode == "CFB":                                   # CFB128
        prev = iv
        for i in range(0, len(data), bs):
            chunk = data[i:i + bs]
            ks = _sm4_block(key, prev)
            x = bytes(a ^ b for a, b in zip(chunk, ks))
            out += x
            prev = chunk if decrypt else x
        return bytes(out)
    if mode == "CFB8":
        prev = iv
        for i in range(len(data)):
            ks = _sm4_block(key, prev)
            b = data[i] ^ ks[0]
            out.append(b)
            prev = prev[1:] + bytes([data[i] if decrypt else b])
        return bytes(out)
    if mode == "OFB":
        prev = iv
        for i in range(0, len(data), bs):
            prev = _sm4_block(key, prev)
            chunk = data[i:i + bs]
            out += bytes(a ^ b for a, b in zip(chunk, prev))
        return bytes(out)
    if mode == "CTR":
        ctr = int.from_bytes(iv, "big")
        for i in range(0, len(data), bs):
            ks = _sm4_block(key, ctr.to_bytes(bs, "big"))
            chunk = data[i:i + bs]
            out += bytes(a ^ b for a, b in zip(chunk, ks))
            ctr = (ctr + 1) & ((1 << 128) - 1)
        return bytes(out)
    raise ValueError(t(f"SM4 不支持的模式：{mode}", f"SM4 unsupported mode: {mode}"))


def _sm4_config_mode(cfg):
    mode = str(cfg.get("mode") or "CBC").upper()
    if mode not in SM4_VALID_MODES:
        raise ValueError(t(
            f"SM4 只支持 {'/'.join(SM4_VALID_MODES)}，当前为 {mode}",
            f"SM4 supports only {'/'.join(SM4_VALID_MODES)}, got {mode}"))
    return mode


def _sm4_encrypt(text):
    from gmssl.sm4 import CryptSM4, SM4_ENCRYPT
    cfg = state.algo["sm4"]
    mode = _sm4_config_mode(cfg)
    key = _b(cfg.get("key"))
    iv = _b(cfg.get("iv"))
    data = text.encode("utf-8")
    if mode in ("CBC", "ECB"):
        if cfg.get("padding") != "none":
            data = _pad(data, 16, cfg.get("padding", "pkcs7"))
        elif len(data) % 16:
            raise ValueError(t(
                f"SM4 {mode} padding=none 时明文长度必须是 16 的倍数，实际 {len(data)} 字节",
                f"SM4 {mode} with padding=none needs a multiple of 16B, got {len(data)}B"))
        ct = _sm4_cbc(key, iv, data) if mode == "CBC" else _sm4_ecb(key, data)
    else:
        ct = _sm4_stream(mode, data, key, iv, decrypt=False)
    return _b64e(ct)


def _sm4_decrypt(text):
    from gmssl.sm4 import CryptSM4, SM4_DECRYPT
    cfg = state.algo["sm4"]
    mode = _sm4_config_mode(cfg)
    key = _b(cfg.get("key"))
    iv = _b(cfg.get("iv"))
    ct = _b64d(text)
    if mode in ("CBC", "ECB"):
        if len(ct) % 16:
            raise ValueError(t(
                f"SM4 {mode} 密文长度必须是 16 的倍数，实际 {len(ct)} 字节",
                f"SM4 {mode} ciphertext must be a multiple of 16B, got {len(ct)}B"))
        data = (_sm4_cbc(key, iv, ct, decrypt=True) if mode == "CBC"
                else _sm4_ecb(key, ct, decrypt=True))
        if cfg.get("padding") != "none":
            data = _unpad(data, 16, cfg.get("padding", "pkcs7"))
    else:
        data = _sm4_stream(mode, ct, key, iv, decrypt=True)
    return _to_text(data, f"sm4·{mode}")


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
    return _to_text(b"".join(out), "rsa")


def _sm2_key_hex(raw, label="sm2.public_key"):
    """[R-04] SM2 公钥规范化：只认「130 位 hex 且以 04 开头」这一种形态。

    gmssl 内部写的是 public_key.lstrip("04") —— 这是按字符集剥离，不是按前缀：
      "0400…" → 前 4 个字符全在集合 {'0','4'} 里，被剥成 126 位；
      "0412…" → 只剥掉 "04"，剩 128 位（这一种恰好是对的）。
    长度一旦不对，报错信息与真实原因（公钥写错）毫无关系。
    这里自己规范化，再由 _sm2_obj 把结果写回对象，绕开 gmssl 的那一步。
    """
    pub = (raw or "").strip()
    if not pub:
        return ""
    compact = "".join(pub.split())
    if (len(compact) == 130 and compact[:2].lower() == "04"
            and all(ch in "0123456789abcdefABCDEF" for ch in compact)):
        return compact[2:]
    if len(compact) != 128:
        # [F-04] 旧文案「长度 130 位，既不是 130 位（04+XY）也不是 128 位」自相矛盾：
        # 走到这里必然 len != 128，而 len == 130 且以 04 开头的情形上面已经 return。
        _record_note("sm2", t(
            f"{label}: 长度 {len(compact)} 位 —— 合法形态只有两种："
            f"128 位裸 XY，或 04+128 位（共 130 位）；"
            f"已按原样交给 gmssl；解密/验签失败请先修正公钥",
            f"{label}: length {len(compact)}; valid forms are 128 hex (raw XY) or "
            f"04+128 hex (130 total); passed through unchanged"))
    return compact


def _sm2_obj(cfg, pub_label="sm2.public_key"):
    from gmssl import sm2 as gsm2
    pub = _sm2_key_hex(cfg.get("public_key", ""), pub_label)
    pri = (cfg.get("private_key") or "").strip()
    c = gsm2.CryptSM2(public_key=pub, private_key=pri,
                      mode=1 if cfg.get("mode") == "C1C3C2" else 0)
    # 规范化后的 128 位裸 XY 若恰好以 "04" 开头，会被 gmssl 的 lstrip("04")
    # 二次截断成 126 位 —— 直接覆盖属性，确保交给它的一定是 128 位。
    c.public_key = pub
    return c


def _sm2_encrypt(text):
    c = _sm2_obj(state.algo["sm2"])
    return _b64e(c.encrypt(text.encode("utf-8")))


def _sm2_decrypt(text):
    """[R-03] SM2 解密 + 自行校验 C3。

    gmssl 的 decrypt() 会把 C3 = SM3(x2 || M || y2) 算出来就地丢掉、从不比对，
    所以 C3 被篡改（或私钥/模式配错）时照样返回"解密成功"的明文，
    整条链路看起来一切正常，直到业务侧报签名不对。
    """
    from gmssl import sm3
    cfg = state.algo["sm2"]
    c = _sm2_obj(cfg)
    raw = _b64d(text)
    if len(raw) < 96:
        raise ValueError(t(
            f"SM2 密文过短：{len(raw)} 字节，至少需要 96 字节"
            f"（C1 64 字节 + C3 32 字节，C2 可为空）",
            f"SM2 ciphertext too short: {len(raw)}B, need ≥96B (C1 64 + C3 32)"))
    hx = raw.hex()
    c1 = hx[0:128]
    c3 = hx[128:192] if c.mode else hx[-64:]
    plain = c.decrypt(raw)
    xy = c._kg(int(c.private_key, 16), c1)
    if not xy or len(xy) < 128:
        raise ValueError(t(
            "SM2 解密失败：C1 不是曲线上的点（公钥/私钥/密文不匹配）",
            "SM2 decrypt failed: C1 is not a point on the curve"))
    calc = sm3.sm3_hash(list(bytes.fromhex(xy[0:64] + plain.hex() + xy[64:128])))
    if calc.lower() != c3.lower():
        raise ValueError(t(
            f"SM2 解密校验失败：C3 不一致（密文内 {c3[:16]}… / 重算 {calc[:16]}…），"
            f"密文被篡改或私钥、C1C3C2 顺序不匹配",
            f"SM2 C3 mismatch ({c3[:16]}… vs {calc[:16]}…): tampered ciphertext "
            f"or wrong private key / mode"))
    return _to_text(plain, "sm2")


def _stream_cipher(algo, text, decrypt=False):
    """ChaCha20 / Salsa20（流密码，无 padding，输出 base64）。"""
    from Crypto.Cipher import ChaCha20, Salsa20
    cfg = state.algo[algo]
    key = _b(cfg.get("key"))
    nonce = _b(cfg.get("iv"))
    if not nonce:
        raise ValueError(t(f"{algo} 需要 nonce（填在 iv 字段）",
                           f"{algo} requires a nonce (iv field)"))
    mod = ChaCha20 if algo == "chacha20" else Salsa20
    c = mod.new(key=key, nonce=nonce)
    if decrypt:
        return _to_text(c.decrypt(_b64d(text)), algo)
    return _b64e(c.encrypt(text.encode("utf-8")))


def _rsa_sign(text):
    from Crypto.Signature import pkcs1_15, pss
    from Crypto.Hash import SHA1, SHA256, SHA384, SHA512
    cfg = state.algo["rsa-sign"]
    key = _load_rsa_key(cfg.get("private_key", ""), private=True)
    hashes = {"sha1": SHA1, "sha256": SHA256, "sha384": SHA384, "sha512": SHA512}
    h = hashes.get((cfg.get("sign_hash") or "sha256").lower(),
                   SHA256).new(text.encode("utf-8"))
    pad = (cfg.get("padding") or "pkcs1_v1_5").lower()
    signer = pss.new(key) if pad == "pss" else pkcs1_15.new(key)
    return _b64e(signer.sign(h))


def _sm2_sign(text):
    from gmssl import sm2 as gsm2
    cfg = state.algo["sm2-sign"]
    pri = (cfg.get("private_key") or "").strip()
    pub = (cfg.get("public_key") or "").strip()
    if not pri:
        raise ValueError(t("SM2 签名需要私钥", "SM2 sign requires a private key"))
    pub_norm = _sm2_key_hex(pub, "sm2-sign.public_key")
    c = gsm2.CryptSM2(public_key=pub_norm, private_key=pri, mode=1)
    # [R-04] 同上：防止 gmssl 构造函数把已规范化的 128 位裸 XY 再 lstrip 一次
    c.public_key = pub_norm
    return c.sign_with_sm3(text.encode("utf-8"))


_HASHLIB_NAME = {
    "sha3-256": "sha3_256",
    "sha3-512": "sha3_512",
    "ripemd160": "ripemd160",
    "blake2b": "blake2b",
}


def _hash_encrypt(algo, text):
    if algo == "sm3":
        from gmssl import sm3 as gsm3
        return gsm3.sm3_hash(list(text.encode("utf-8")))
    h = hashlib.new(_HASHLIB_NAME.get(algo, algo))
    h.update(text.encode("utf-8"))
    return h.hexdigest()


def _hmac_encrypt(algo, text):
    cfg = state.algo[algo]
    name = ALGO_DEFS[algo]["hmac_hash"]
    # hmac.new 接受字符串 digestmod，内部走 hashlib.new，因此 sm3 / sha3_256 都可用
    h = _hmac.new(_b(cfg.get("key")), text.encode("utf-8"), name)
    return h.hexdigest()


def encrypt_by_algo(algo, text):
    if algo in (None, "none"):
        return text
    d = ALGO_DEFS.get(algo)
    if not d:
        raise ValueError(t(f"未知算法：{algo}", f"Unknown algorithm: {algo}"))
    if d.get("hmac_hash"):
        return _hmac_encrypt(algo, text)
    if d.get("oneway"):
        if algo == "rsa-sign":
            return _rsa_sign(text)
        if algo == "sm2-sign":
            return _sm2_sign(text)
        return _hash_encrypt(algo, text)
    if algo in ("chacha20", "salsa20"):
        return _stream_cipher(algo, text, decrypt=False)
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
    if algo in ("chacha20", "salsa20"):
        return _stream_cipher(algo, text, decrypt=True)
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


def _text_or_original(raw, original, where):
    """[F-01] 编解码层解出来的二进制不是文本 → 保留原字符串，记一条软失败。

    base64/hex/base32 后面跟的可能是 PNG、protobuf、压缩包，本来就不是 UTF-8。
    以前这里直接 decode("utf-8")：1.3.9 抛 UnicodeDecodeError（字段 passthrough，
    用户只看到"没反应"），1.3.10 又因为它被标成 utf8 失败而把整条 /decode 顶成
    错误文案。现在既不抛也不顶替：字段保持原样（与 1.3.9 一致），失败照样进
    /last-errors，用户能看到「这个字段没解出来」。
    """
    try:
        return _to_text(raw, where, soft=True)
    except NonUtf8Error as e:
        _record_error(where, e)
        return original


def decode_step(data, method):
    """解码一层；[F-01] 编解码层解出来的可能是二进制（PNG 之类），
    所以这四处的转换一律走 _text_or_original：解不出文本就原样保留，
    不再被当成「明文非 UTF-8」去顶掉整条 /decode 响应。
    """
    if method in (None, "none"):
        return data
    if method == "url":
        return unquote(data)
    if method == "base64":
        return _text_or_original(_b64d(data), data, "解码·base64")
    if method == "base64url":
        s = data.replace("-", "+").replace("_", "/")
        s += "=" * (-len(s) % 4)
        return _text_or_original(base64.urlsafe_b64decode(s), data, "解码·base64url")
    if method == "hex":
        return _text_or_original(
            binascii.unhexlify("".join(data.split())), data, "解码·hex")
    if method == "base32":
        s = data + "=" * (-len(data) % 8)
        return _text_or_original(base64.b32decode(s), data, "解码·base32")
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
# debug 输出
# =====================================================================
def _short(s, n=140):
    if s is None:
        return ""
    s = str(s)
    if len(s) <= n:
        return s
    head = n // 2 - 1
    return s[:head] + " ... " + s[-head:]


def _trace_enabled():
    return bool(state.settings.get("debug_print", True))


def _log_trace(stage, before, after):
    if not _trace_enabled():
        return
    print(f"      {C.GRY}[trace]{C.R} {C.CYA}{stage}{C.R}")
    print(f"        {C.GRY}in :{C.R} {_short(before)}")
    print(f"        {C.GRY}out:{C.R} {_short(after)}")


# =====================================================================
# 【核心】多层加解密
# =====================================================================
def multi_encrypt(plaintext, layers, trace=None):
    if trace is None:
        trace = _trace_enabled()
    result = plaintext
    total = len(layers or [])
    for idx, layer in enumerate(layers or [], 1):
        algo = layer.get("algorithm", "none")
        for e in layer.get("encode_before", []):
            prev = result
            result = encode_step(result, e)
            if trace:
                _log_trace(f"[{idx}/{total}] encode_before · {enc_label(e)}", prev, result)
        if algo not in (None, "none"):
            prev = result
            result = encrypt_by_algo(algo, result)
            if trace:
                _log_trace(f"[{idx}/{total}] encrypt · {algo_label(algo)}", prev, result)
        for e in layer.get("encode_after", []):
            prev = result
            result = encode_step(result, e)
            if trace:
                _log_trace(f"[{idx}/{total}] encode_after  · {enc_label(e)}", prev, result)
    return result


def multi_decrypt(ciphertext, layers, trace=None):
    if trace is None:
        trace = _trace_enabled()
    result = ciphertext
    total = len(layers or [])
    for idx, layer in enumerate(reversed(layers or []), 1):
        algo = layer.get("algorithm", "none")
        for e in reversed(layer.get("encode_after", [])):
            prev = result
            result = decode_step(result, e)
            if trace:
                _log_trace(f"[{idx}/{total}] decode_after  · {enc_label(e)}", prev, result)
        if algo not in (None, "none"):
            prev = result
            result = decrypt_by_algo(algo, result)
            if trace:
                _log_trace(f"[{idx}/{total}] decrypt · {algo_label(algo)}", prev, result)
        for e in reversed(layer.get("encode_before", [])):
            prev = result
            result = decode_step(result, e)
            if trace:
                _log_trace(f"[{idx}/{total}] decode_before · {enc_label(e)}", prev, result)
    return result


# =====================================================================
# 数据体处理
# =====================================================================
_PARAM_TYPE_REPORTED = set()


def _param_scope(p, name=""):
    """[R-07] 取参数作用域；p 不是对象时记录「参数名 + 实际类型」并按 auto 处理。

    以前这里直接 p.get(...)：state.params 里只要混进一个字符串（手改配置、
    旧版本遗留、脚本写坏），整个请求就在 AttributeError 上炸掉，插件只看到
    "'str' object has no attribute 'get'"，完全看不出是哪个参数。
    """
    if not isinstance(p, dict):
        label = name or "<unnamed>"
        if label not in _PARAM_TYPE_REPORTED:
            _PARAM_TYPE_REPORTED.add(label)
            _record_error("params", t(
                f"参数 {label} 的配置不是对象（实际类型 {type(p).__name__}），"
                f"已按 scope=auto、无处理层跳过；请修正配置文件里的该字段",
                f"param {label} config is not an object ({type(p).__name__}); "
                f"skipped as scope=auto with no layers"))
        return SCOPE_AUTO
    s = p.get("scope", SCOPE_AUTO)
    return s if s in VALID_SCOPES else SCOPE_AUTO


def _param_layers(p, name=""):
    """[R-07] 安全取 layers：非对象先记提示，返回空列表。"""
    if not isinstance(p, dict):
        _param_scope(p, name)
        return []
    layers = p.get("layers")
    return layers if isinstance(layers, list) else []


def _reset_param_type_reports():
    _PARAM_TYPE_REPORTED.clear()


# ---------------------------------------------------------------------
# 【v1.3.7 新增】错误记录：让"静默失败"变成"可查"
#
# 原始实现把所有异常都 catch 成「返回原值 + 一行 print」，调用方（插件）
# 拿到的永远是 200 + 未修改的 body，无法区分「成功但没变」和「处理失败」。
# 这里做三件事：
#   1. 结构化记录失败（内存环形缓冲 + 可选写文件）
#   2. 暴露 GET /last-errors，用浏览器/curl 就能看最近失败
#   3. 可选 fail_mode=http_500，让失败直接以 500 回给插件
# ---------------------------------------------------------------------
_ERRORS = collections.deque(maxlen=50)
_ERR_SEQ = [0]

# [R-02/R-06/R-08/R-09/R-11] 非致命提示：与 _record_error 分开，
# 因为"配置被规范化""走了 json 分支""同名键有 2 个"都不是失败，
# 但用户必须能看到。走 trace + GET /last-errors 的 notes 字段。
_NOTES = collections.deque(maxlen=50)
_NOTE_SEQ = [0]


def _record_note(where, detail):
    _NOTE_SEQ[0] += 1
    item = {
        "seq": _NOTE_SEQ[0],
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "where": str(where),
        "detail": str(detail),
    }
    _NOTES.append(item)
    if state.settings.get("debug_print", True):
        print(f"      {C.YEL}[note]{C.R} [{item['where']}] {item['detail']}")
    return item


def notes():
    return list(_NOTES)


def _errors_since(seq0):
    """取本次请求内新增的错误（deque 会自动丢旧项，不能用切片）。"""
    return [it for it in list(_ERRORS) if it.get("seq", 0) > seq0]


def _record_error(where, detail):
    _ERR_SEQ[0] += 1
    item = {
        "seq": _ERR_SEQ[0],
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "where": str(where),
        "detail": str(detail),
        # [R-10] 标记"解密出来的字节不是 UTF-8"，端点据此返回明确文案。
        # [F-01] soft 的（编解码层解出二进制，如 PNG 的 base64）不算：
        #        那种失败只该让本字段原样透传，不该整条替换 /decode 响应。
        "utf8": isinstance(detail, NonUtf8Error) and not getattr(detail, "soft", False),
    }
    _ERRORS.append(item)
    if state.settings.get("debug_print", True):
        print(f"      {C.RED}[!]{C.R} [{item['where']}] {item['detail']}")
    log_path = state.settings.get("error_log") or ""
    if log_path:
        try:
            with open(log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(item, ensure_ascii=False) + "\n")
        except Exception:
            pass
    return item


def _apply_layers(v, layers, mode, label=""):
    if not layers:
        return v
    try:
        if mode == "encrypt":
            return multi_encrypt(v, layers)
        else:
            return multi_decrypt(v, layers)
    except Exception as e:
        _record_error(label or "-", e)
        return v


def _layer_effective(layer):
    """[F-06 真因] 这一层是否会真的改动字节。

    「有配置」不等于「有处理」：{"layers": []}、{"layers": [{"algorithm": "none"}]}、
    空对象、键名写错（"algo"）——它们都能通过 _param_layers 拿到一个 list，
    但里面一个有效动作都没有。以前只要 params[name] 是 dict 就把字段标成
    handled，于是 process_form 仍对它 quote/unquote：配置空着却改写了字节。

    判据（契约给的）：algorithm 不是 "none"，或 encode_before / encode_after
    至少有一个非 "none" 的编码名。
    """
    if not isinstance(layer, dict):
        return False
    if layer.get("algorithm") not in (None, "", "none"):
        return True
    for key in ("encode_before", "encode_after"):
        vals = layer.get(key) or []
        if isinstance(vals, str):
            vals = [vals]
        try:
            seq = list(vals)
        except TypeError:
            seq = []
        for enc in seq:
            if isinstance(enc, str) and enc not in ("", "none"):
                return True
    return False


def _layers_effective(layers):
    """层列表里是否至少有一个有效层（见 _layer_effective）。"""
    if not isinstance(layers, (list, tuple)):
        return False
    return any(_layer_effective(l) for l in layers)


def _try_json(text):
    if not isinstance(text, str):
        return None
    s = text.strip()
    if not s or s[0] not in "[{":
        return None
    try:
        return json.loads(s)
    except Exception:
        return None


def _json_scan_ok(text):
    """整段文本能否被完整扫描成 JSON 对象/数组（[R-11] data_mode=auto 判定用）。

    与 _try_json 的区别：这里用的是保形扫描器（_jscan_value），
    只要有一个字符解析不了就返回 False，不做 json.loads 的宽松兜底。
    """
    if not isinstance(text, str):
        return False
    i = _jskip(text, 0)
    if i >= len(text) or text[i] not in "[{":
        return False
    try:
        kind, vend, _children = _jscan_value(text, i)
    except Exception:
        return False
    if kind not in ("object", "array"):
        return False
    return _jskip(text, vend) >= len(text)
# ---------------------------------------------------------------------
# 【v1.3.7 新增】保形 JSON 处理
#
# 背景：旧实现用 json.loads -> json.dumps 重建整个 body，会带来三个副作用：
#   1. 缩进/空白被压平（"a": 1  ->  "a": 1，多余空格消失）
#   2. 数字字面量被改写（2.50 -> 2.5、1e3 -> 1000.0）
#   3. 键顺序可能被重排（先按配置参数顺序输出，再补剩余键）
# 只要服务端对「整个 body」做签名/哈希，以上任意一条都会让签名对不上。
#
# 现在改为「扫描原始文本 -> 只替换被处理字段的值区间」，其余字节原样保留。
# ---------------------------------------------------------------------
_JSON_WS = " \t\r\n"


def _jskip(text, i):
    n = len(text)
    while i < n and text[i] in _JSON_WS:
        i += 1
    return i


def _jscan_string(text, i):
    """text[i] == '"'，返回结束引号之后的位置（不处理转义语义，只跳过）。"""
    n = len(text)
    j = i + 1
    while j < n:
        c = text[j]
        if c == "\\":
            j += 2
            continue
        if c == '"':
            return j + 1
        j += 1
    raise ValueError("unterminated string")


def _jscan_value(text, i):
    """扫描一个 JSON 值。

    返回 (kind, vend, children)
      kind     : 'object' | 'array' | 'string' | 'scalar'
      vend     : 值文本的结束位置（不含尾随空白）
      children : [{'key': str|None, 'vstart': int, 'vend': int, 'kind': str}]
    """
    i = _jskip(text, i)
    if i >= len(text):
        raise ValueError("unexpected end")
    c = text[i]

    if c == "{":
        children = []
        j = i + 1
        while True:
            j = _jskip(text, j)
            if j >= len(text):
                raise ValueError("unexpected end in object")
            if text[j] == "}":
                return "object", j + 1, children
            key_end = _jscan_string(text, j)
            key = json.loads(text[j:key_end])
            j = _jskip(text, key_end)
            if j >= len(text) or text[j] != ":":
                raise ValueError("expected ':'")
            j = _jskip(text, j + 1)
            kind, vend, _ = _jscan_value(text, j)
            children.append({"key": key, "vstart": j, "vend": vend, "kind": kind})
            j = _jskip(text, vend)
            if j >= len(text):
                raise ValueError("unexpected end in object")
            if text[j] == ",":
                j += 1
                continue
            if text[j] == "}":
                return "object", j + 1, children
            raise ValueError("expected ',' or '}'")

    if c == "[":
        children = []
        j = i + 1
        while True:
            j = _jskip(text, j)
            if j >= len(text):
                raise ValueError("unexpected end in array")
            if text[j] == "]":
                return "array", j + 1, children
            kind, vend, _ = _jscan_value(text, j)
            children.append({"key": None, "vstart": j, "vend": vend, "kind": kind})
            j = _jskip(text, vend)
            if j >= len(text):
                raise ValueError("unexpected end in array")
            if text[j] == ",":
                j += 1
                continue
            if text[j] == "]":
                return "array", j + 1, children
            raise ValueError("expected ',' or ']'")

    if c == '"':
        return "string", _jscan_string(text, i), []

    j = i
    n = len(text)
    while j < n and text[j] not in ",}]":
        j += 1
    k = j
    while k > i and text[k - 1] in _JSON_WS:
        k -= 1
    return "scalar", k, []


def process_json_text(text, mode, depth=0, inner_start=False):
    """对 JSON 文本做加解密，只替换被处理字段的值文本，其余原样保留。

    text        : 原始 JSON 文本（顶层对象或数组）
    inner_start : True 表示这段文本本身就是某个字段的值（内层），
                  此时按 auto/json 语义匹配参数；否则按 auto/form。
    """
    if depth > 8:
        # [R-06] 以前静默 return text：嵌套太深的那一块完全没被处理，
        # 用户只看到"这个字段没变"，/last-errors 里也查不到任何线索。
        _record_error("json-depth", t(
            f"JSON 嵌套深度超过 8 层（当前 depth={depth}），该块原样透传未处理",
            f"JSON nesting deeper than 8 (depth={depth}); block passed through"))
        return text
    if not isinstance(text, str):
        return text
    i = _jskip(text, 0)
    if i >= len(text):
        return text
    try:
        kind, _vend, children = _jscan_value(text, i)
    except Exception:
        return text
    if kind not in ("object", "array") or not children:
        return text

    if kind == "object":
        ordered = []
        used = set()
        for name in state.params.keys():
            if name in RESERVED_BODY_NAMES or name == OLD_BODY_PARAM_NAME:
                continue
            for idx, ch in enumerate(children):
                if ch["key"] == name and idx not in used:
                    ordered.append(ch)
                    used.add(idx)
                    break
        for idx, ch in enumerate(children):
            if idx not in used:
                ordered.append(ch)
                used.add(idx)
    else:
        ordered = list(children)

    allow_scopes = ((SCOPE_AUTO, SCOPE_JSON) if inner_start
                    else (SCOPE_AUTO, SCOPE_FORM))

    edits = []
    # [Low] 未配置字段也要吃 default_layers（与 _process_top_pairs 同语义）
    default_layers_cfg = None
    if state.settings.get("enable_default") and state.settings.get("default_layers"):
        default_layers_cfg = state.settings["default_layers"]
    for ch in ordered:
        raw = text[ch["vstart"]:ch["vend"]]
        if ch["kind"] == "string":
            try:
                inner_val = json.loads(raw)
            except Exception:
                continue
            if not isinstance(inner_val, str):
                continue
            name = ch["key"]
            p = state.params.get(name) if name else None
            # [R-07] 非对象配置在这里也会被 _param_scope 记一条「参数名 + 类型」
            allow = (p is not None
                     and _param_scope(p, name or "") in allow_scopes)
            layers = _param_layers(p, name or "") if allow else []
            # [t10] 「有配置」不等于「有处理」：{}、{"layers": []}、
            # [{"algorithm": "none"}] 都能通过上面两步拿到一个合法（但空）的层列表。
            # 以前 JSON 路径到此就算 allow=True，于是走字段自己的空 layers，
            # default_layers 永远接不到 —— 同一份配置在 form 路径（F-06 判据）
            # 却会交给 default_layers，换个 body 格式就失效，用户无从预期。
            # 判据与 _process_top_pairs 共用 _layers_effective，不另写一份逻辑；
            # 空配置是合法状态，静默跳过、不发提示。
            if allow and not _layers_effective(layers):
                allow = False
                layers = []
            new = inner_val
            if mode == "encrypt":
                if _try_json(new) is not None:
                    new = process_json_text(new, mode, depth + 1, inner_start=True)
                if allow:
                    new = _apply_layers(new, layers, mode, label=name or "")
                elif default_layers_cfg:
                    new = _apply_layers(new, default_layers_cfg, mode, label=name or "")
            else:
                if allow:
                    new = _apply_layers(new, layers, mode, label=name or "")
                elif default_layers_cfg:
                    new = _apply_layers(new, default_layers_cfg, mode, label=name or "")
                if _try_json(new) is not None:
                    new = process_json_text(new, mode, depth + 1, inner_start=True)
            if new != inner_val:
                edits.append((ch["vstart"], ch["vend"],
                              json.dumps(new, ensure_ascii=False)))
        else:
            sub = process_json_text(raw, mode, depth + 1, inner_start=True)
            if sub != raw:
                edits.append((ch["vstart"], ch["vend"], sub))

    if not edits:
        return text
    edits.sort(key=lambda e: e[0], reverse=True)
    out = text
    for s, e, r in edits:
        out = out[:s] + r + out[e:]
    return out


def _process_top_pairs(pairs, mode, coded=False):
    """处理 form 顶层键值对，返回 (new_pairs, handled)。

    handled[i] 表示第 i 个字段「本次真的被处理过」（命中参数配置，或落到
    default_layers）。[R-01] 调用方据此决定要不要给该字段做 URL 编解码；
    coded=True（且 decrypt）时在这里就地 unquote —— 顺序必须和解密一致，
    以前是 process_form 里对整条 body 无差别 unquote/quote。

    [R-08] 同名键（a=1&a=2）：以前 break 只处理第一个，第二个原样透传，
    同一个 body 里出现"改了一半"的状态；现在同名键全部处理并记一条提示。
    """
    n = len(pairs)
    out = [None] * n
    handled = [False] * n

    for k in state.params.keys():
        if k in RESERVED_BODY_NAMES or k == OLD_BODY_PARAM_NAME:
            continue
        p = state.params.get(k)
        scope = _param_scope(p, k)      # 非对象时顺带记下 R-07 的类型提示
        if not isinstance(p, dict):
            # [F-06] 配置畸形的参数没有任何有效层，绝不能把它标成 handled：
            # 一旦标了，process_form 仍会给该字段 quote/unquote —— 明明没有有效配置
            # 却改写了字节，这正是 R-01 要消灭的行为，只是入口从"未配置"换成了
            # "配置畸形"。（R-07 的类型提示由上面的 _param_scope 负责，不丢。）
            continue
        if scope not in (SCOPE_AUTO, SCOPE_FORM):
            continue
        layers = _param_layers(p, k)
        if not _layers_effective(layers):
            # [F-06 真因] 有配置但没有一个有效层 —— 等价于「没配置」。
            # 之前只判了 isinstance(p, dict)，于是 {}、{"layers": []}、
            # 全是 algorithm=none 的层都会把字段标成 handled，process_form
            # 随即对它 quote/unquote：空配置却改写了字节。这里直接跳过，
            # 交给下面的 default_layers / 嵌套 JSON 分支（那边同样不标 handled）。
            continue
        # [F-08] 提示里的次数必须是键的实际出现次数：旧代码用的是 hits（只统计
        # "带值且被处理"的），于是 a=1&a&a=2 会说"2 次"，与实际 3 次脱节。
        appeared = sum(1 for kk, _v in pairs if kk == k)
        hits = 0
        for i, (kk, vv) in enumerate(pairs):
            if kk != k or handled[i] or vv is None:
                continue
            v = vv
            if coded and mode == "decrypt" and isinstance(v, str):
                v = unquote(v)
            if mode == "encrypt":
                if isinstance(v, str) and _try_json(v) is not None:
                    v = process_json_text(v, mode, inner_start=True)
                v = _apply_layers(v, layers, mode, label=k)
            else:
                v = _apply_layers(v, layers, mode, label=k)
                if isinstance(v, str) and _try_json(v) is not None:
                    v = process_json_text(v, mode, inner_start=True)
            out[i] = v
            handled[i] = True
            hits += 1
        if appeared > 1:
            _record_note("form", t(
                f"同名 form 键 {k} 出现 {appeared} 次（带值可处理的 {hits} 个），已全部处理"
                f"（form_url_coded 对这种键按同名一起生效）",
                f"form key {k} appeared {appeared} times ({hits} with a value); "
                f"all processed"))

    # [Low] 落实「未配置参数默认处理」：以前 default_layers 只用来显示，
    #       运行链路一次都没用过 —— 菜单里配得漂漂亮亮，实际请求直接透传。
    default_layers_cfg = None
    if state.settings.get("enable_default") and state.settings.get("default_layers"):
        # [F-06 真因] 默认层同样要先判有效性：全是 algorithm=none 的默认层
        # 等于「没有默认处理」，不能因为它存在就给字段做 quote/unquote。
        if _layers_effective(state.settings["default_layers"]):
            default_layers_cfg = state.settings["default_layers"]

    def_hits = {}
    for i, (k, v) in enumerate(pairs):
        if handled[i]:
            continue
        if v is None or not isinstance(v, str):
            out[i] = v
            continue
        if default_layers_cfg:
            vv = v
            if coded and mode == "decrypt":
                vv = unquote(vv)
            if mode == "encrypt":
                if _try_json(vv) is not None:
                    vv = process_json_text(vv, mode, inner_start=True)
                vv = _apply_layers(vv, default_layers_cfg, mode, label=k)
            else:
                vv = _apply_layers(vv, default_layers_cfg, mode, label=k)
                if isinstance(vv, str) and _try_json(vv) is not None:
                    vv = process_json_text(vv, mode, inner_start=True)
            out[i] = vv
            handled[i] = True
            def_hits[k] = def_hits.get(k, 0) + 1
            continue
        inner = _try_json(v)
        if inner is not None:
            out[i] = process_json_text(v, mode, inner_start=True)
        else:
            out[i] = v

    for i, (k, v) in enumerate(pairs):
        if out[i] is None:
            out[i] = v
    # [F-07] 与主路径对齐：default_layers 分支同样会把同名键全部处理，
    #        以前却一条提示都不发（主路径发、这里不发，行为不对称）。
    for k, c in def_hits.items():
        if c > 1:
            _record_note("form", t(
                f"同名 form 键 {k} 出现 {c} 次，已全部按默认处理层处理"
                f"（form_url_coded 对这种键按同名一起生效）",
                f"form key {k} appeared {c} times; all handled by default layers"))
    return [(k, out[i]) for i, (k, v) in enumerate(pairs)], handled


def process_form(data, mode):
    parts = data.split("&")
    pairs = []
    for part in parts:
        if "=" in part:
            k, _, v = part.partition("=")
            pairs.append((k, v))
        else:
            pairs.append((part, None))

    # [R-01] form_url_coded 默认 True，但只对「本次真的被处理」的字段生效：
    # 未配置的 x=%E4%B8%AD 以前会被二次编码成 x=%25E4%25B8%25AD。
    coded = bool(state.settings.get("form_url_coded", True))
    pairs, handled = _process_top_pairs(
        pairs, mode, coded=(coded and mode == "decrypt"))

    out = []
    for i, (k, v) in enumerate(pairs):
        if v is None:
            out.append(k)
        else:
            if mode == "encrypt" and coded and handled[i]:
                v = quote(v, safe="")
            out.append(f"{k}={v}")
    return "&".join(out)


def process_header_text(header_text, mode, target_scope):
    if not header_text:
        return header_text
    raw_has_crlf = "\r\n" in header_text
    text = header_text.replace("\r\n", "\n").replace("\r", "\n")
    lines = text.split("\n")
    out_lines = []
    for line in lines:
        if ":" not in line:
            out_lines.append(line)
            continue
        k, _, v = line.partition(":")
        k_name = k.strip()
        v_val = v.strip()
        p = state.params.get(k_name)
        if p is not None:
            # [R-07] 非对象配置先记「参数名 + 类型」，不再 AttributeError
            if _param_scope(p, k_name) == target_scope:
                prev = v_val
                v_val = _apply_layers(
                    v_val, _param_layers(p, k_name), mode, label=k_name)
                if _trace_enabled() and prev != v_val:
                    _log_trace(f"header · {k_name}", prev, v_val)
        out_lines.append(f"{k_name}: {v_val}")
    result = "\n".join(out_lines)
    if raw_has_crlf:
        result = result.replace("\n", "\r\n")
    return result


def _process_body(data, mode, target_body_param_name):
    if not data:
        return data

    body_p = state.params.get(target_body_param_name)
    body_layers = _param_layers(body_p, target_body_param_name) if body_p is not None else []
    if body_layers:
        if state.settings.get("debug_print", True):
            print(f"      {C.GRY}[whole-body]{C.R} "
                  f"{_display_param_name(target_body_param_name)} "
                  f"({len(body_layers)} {t('层', 'layers')})")
        try:
            if mode == "encrypt":
                return multi_encrypt(data, body_layers)
            else:
                return multi_decrypt(data, body_layers)
        except Exception as e:
            _record_error(_display_param_name(target_body_param_name), e)
            return data

    if target_body_param_name == RESERVED_REQ_BODY:
        legacy = state.params.get(OLD_BODY_PARAM_NAME)
        legacy_layers = _param_layers(legacy, OLD_BODY_PARAM_NAME) if legacy is not None else []
        if legacy_layers:
            if state.settings.get("debug_print", True):
                print(f"      {C.GRY}[whole-body]{C.R} legacy __body__ "
                      f"({len(legacy_layers)} {t('层', 'layers')})")
            try:
                if mode == "encrypt":
                    return multi_encrypt(data, legacy_layers)
                else:
                    return multi_decrypt(data, legacy_layers)
            except Exception as e:
                _record_error("legacy __body__", e)
                return data

    dm = state.settings.get("data_mode", "auto")
    if dm in ("auto", "json"):
        # [R-11] 判定顺序改成「先试 JSON 扫描成功 → json；失败再看有没有 =」。
        # 以前是 json.loads 成功但顶层不是 dict 就落到 process_form，
        # 于是 [{"q":"a=b"}] 被判成 form，再叠上 form_url_coded 直接被拆坏。
        if _json_scan_ok(data):
            if dm == "auto":
                _record_note("data_mode", t(
                    f"auto → json（JSON 扫描成功，{len(data)} 字节）",
                    f"auto → json (JSON scan ok, {len(data)}B)"))
            return process_json_text(data, mode)
        if dm == "json":
            _record_note("data_mode", t(
                f"json → 原样透传（JSON 扫描失败，{len(data)} 字节）",
                f"json → passthrough (scan failed, {len(data)}B)"))
            return data
        has_eq = "=" in data
        _record_note("data_mode", t(
            f"auto → {'form（JSON 扫描失败，body 含 =）' if has_eq else '原样透传（JSON 扫描失败且不含 =）'}",
            f"auto → {'form (scan failed, body has =)' if has_eq else 'passthrough (no = found)'}"))
        if not has_eq:
            return data
    return process_form(data, mode)


def process_payload(data, headers, mode):
    # [R-07] 每个请求重置「非对象 param」去重表，保证每次都能看到提示
    _reset_param_type_reports()
    if mode == "encrypt":
        target_body = RESERVED_REQ_BODY
        target_header_scope = SCOPE_REQ_HEADER
    else:
        target_body = RESERVED_RESP_BODY
        target_header_scope = SCOPE_RESP_HEADER

    new_body = _process_body(data, mode, target_body)
    new_headers = process_header_text(headers, mode, target_header_scope)
    return new_body, new_headers


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
        if f["kind"] == "bytes":
            shown = fmt_bytes_field(v)
        elif f["kind"] == "pem":
            shown = _pem_summary(v or "")
        else:
            shown = str(v) if v else t("(空)", "(empty)")
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
        val = ask_pem(t(f"请输入 {_flabel(field)}", f"Enter {_flabel(field)}"),
                      cfg.get(fk, ""))
        cfg[fk] = val
        chars = len("".join(val.split())) if val else 0
        ok(t(f"{_flabel(field)} 已更新（{chars} 字符有效内容）",
             f"{_flabel(field)} updated ({chars} effective chars)"))
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
# 数据格式
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
        render_items([("0", t("返回", "Back"), "")])
        ch = prompt_choice({"1", "2", "3", "0"})
        if ch == "0":
            return
        state.settings["data_mode"] = opts[int(ch) - 1][0]
        save_config()
        ok(t(f"数据格式已设置为：{opts[int(ch) - 1][1]}",
             f"Data mode set to: {opts[int(ch) - 1][1]}"))
        pause()


# =====================================================================
# 菜单 2：参数配置
# =====================================================================
def fmt_chain(chain):
    chain = [c for c in (chain or []) if c and c != "none"]
    if not chain:
        return f"{C.GRY}{t('无', 'none')}{C.R}"
    return f"{C.CYA}" + " → ".join(enc_label(c) for c in chain) + C.R


def layer_summary(layer):
    alg = layer.get("algorithm", "none")
    return ALGO_DEFS.get(alg, {}).get("label", t("不加密", "None"))


def scope_label(scope):
    if scope == SCOPE_FORM:
        return f"{C.BLU}[form]{C.R}"
    if scope == SCOPE_JSON:
        return f"{C.MAG}[json]{C.R}"
    if scope == SCOPE_REQ_HEADER:
        return f"{C.CYA}[reqH]{C.R}"
    if scope == SCOPE_RESP_HEADER:
        return f"{C.YEL}[respH]{C.R}"
    return f"{C.GRY}[auto]{C.R}"


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


def _is_body_name(name):
    return name in RESERVED_BODY_NAMES or name == OLD_BODY_PARAM_NAME


def _param_line(i, name, pcfg, marker=""):
    # [R-07] 菜单里遍历全部参数：非对象配置以前在这里直接 AttributeError，
    # 整个参数菜单打不开；现在按 auto/无层显示，并在运行时链路里报一次。
    scope = _param_scope(pcfg, name)
    layers = _param_layers(pcfg, name)
    if _is_body_name(name):
        tag = f"{C.YEL}[body]{C.R}"
    else:
        tag = scope_label(scope)
    chain = " → ".join(layer_summary(l) for l in layers) or t("无", "none")
    idx_str = f"{C.YEL}{str(i).rjust(2)}{C.R}"
    return (f"   {marker} {idx_str}) {C.B}{_display_param_name(name)}{C.R} {tag}  "
            f"{C.GRY}({len(layers)} {t('层', 'layers')}){C.R}  "
            f"{C.CYA}{chain}{C.R}")


def pick_param(prompt=None, exclude_body=True):
    names = [n for n in state.params.keys()
             if not (exclude_body and _is_body_name(n))]
    if not names:
        warn(t("尚未配置任何参数", "No parameters configured"))
        pause()
        return None
    while True:
        clear()
        title(prompt or t("选择参数", "Select Parameter"))
        print()
        for i, n in enumerate(names, 1):
            print(_param_line(i, n, state.params[n]))
        print()
        render_items([("0", t("取消", "Cancel"), "")])
        ch = prompt_choice({str(i) for i in range(1, len(names) + 1)} | {"0"})
        if ch == "0":
            return None
        return names[int(ch) - 1]


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


def _edit_param_scope(owner_name, params_dict):
    p = params_dict.get(owner_name)
    if p is None:
        return
    cur = p.get("scope", SCOPE_AUTO)
    clear()
    title(t(f"参数作用域 · {owner_name}", f"Parameter Scope · {owner_name}"))
    print(f"  {t('当前', 'Current')}：{scope_label(cur)}")
    print()
    print(f"  {C.GRY}"
          + t("作用域决定这个参数名在哪些位置被匹配：",
              "Scope decides where this parameter name is matched:")
          + C.R)
    print(f"   {C.YEL}1{C.R}) {C.GRY}[auto]{C.R} "
          + t("form 顶层和 JSON 字符串内部都匹配（默认）",
              "match both form top-level and JSON string inner"))
    print(f"   {C.YEL}2{C.R}) {C.BLU}[form]{C.R} "
          + t("只在 form / JSON 顶层匹配", "match top-level only"))
    print(f"   {C.YEL}3{C.R}) {C.MAG}[json]{C.R} "
          + t("只在 JSON 字符串内部匹配（如 data 值内部的 password）",
              "match inside JSON string only"))
    print(f"   {C.YEL}4{C.R}) {C.CYA}[reqH]{C.R} "
          + t("只在【请求头】匹配（/encode 时处理）",
              "match request headers only (processed on /encode)"))
    print(f"   {C.YEL}5{C.R}) {C.YEL}[respH]{C.R} "
          + t("只在【响应头】匹配（/decode 时处理）",
              "match response headers only (processed on /decode)"))
    print()
    render_items([("0", t("取消", "Cancel"), "")])
    ch = prompt_choice({"1", "2", "3", "4", "5", "0"})
    if ch == "0":
        return
    new_scope = {"1": SCOPE_AUTO, "2": SCOPE_FORM, "3": SCOPE_JSON,
                 "4": SCOPE_REQ_HEADER, "5": SCOPE_RESP_HEADER}[ch]
    p["scope"] = new_scope
    save_config()
    ok(t(f"作用域已设置为 {new_scope}", f"Scope set to {new_scope}"))
    pause()


def menu_layer_editor(layers, owner_name, params_dict=None):
    is_body = _is_body_name(owner_name)
    while True:
        clear()
        title(t(f"参数层管理 · {_display_param_name(owner_name)}",
                f"Layer Manager · {_display_param_name(owner_name)}"))
        if params_dict is not None and owner_name in params_dict:
            p = params_dict[owner_name]
            scope = p.get("scope", SCOPE_AUTO)
            if is_body:
                print(f"  {t('作用域', 'Scope')}   : {C.YEL}[body]{C.R}  "
                      + t("(整包 —— 不做字段匹配)", "(whole body — no field matching)"))
            else:
                print(f"  {t('作用域', 'Scope')}   : {scope_label(scope)}")
                print(f"  {C.GRY}"
                      + t("(作用域定义这个参数名在哪里被匹配)",
                          "(scope defines where this name is matched)")
                      + C.R)
            print()
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
        items = [
            ("1", t("新增一层", "Add layer"), ""),
            ("2", t("编辑某一层", "Edit layer"), ""),
            ("3", t("删除某一层", "Delete layer"), ""),
            ("4", t("调整层顺序", "Reorder layers"), ""),
            ("c", t("清空所有层", "Clear all layers"), ""),
        ]
        allow_rename_scope = params_dict is not None and not is_body
        if allow_rename_scope:
            items.append(("r", t("修改参数名", "Rename parameter"),
                          t(f"当前：{owner_name}", f"current: {owner_name}")))
            items.append(("s", t("修改作用域", "Change scope"),
                          t("auto / form / json / reqH / respH",
                            "auto / form / json / reqH / respH")))
        items.append(("0", t("返回", "Back"), ""))
        render_items(items)
        valid = {"1", "2", "3", "4", "c", "0"}
        if allow_rename_scope:
            valid.add("r")
            valid.add("s")
        ch = prompt_choice(valid)
        if ch == "0":
            save_config()
            return layers
        if ch == "r" and allow_rename_scope:
            new = ask(t("请输入新的参数名", "New parameter name"), owner_name)
            new = (new or "").strip()
            if not new or new == owner_name:
                pause()
                continue
            if _is_body_name(new):
                err(t("不能使用保留名", "Cannot use reserved name"))
                pause()
                continue
            if new in params_dict:
                err(t("该名称已存在", "Name already exists"))
                pause()
                continue
            params_dict[new] = params_dict.pop(owner_name)
            owner_name = new
            save_config()
            ok(t(f"参数名已修改为 {new}", f"Renamed to {new}"))
            pause()
            continue
        if ch == "s" and allow_rename_scope:
            _edit_param_scope(owner_name, params_dict)
            continue
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


def menu_whole_body(target):
    if target not in state.params:
        state.params[target] = empty_param_config()
        save_config()
    if not state.params[target]["layers"]:
        info(t(f"{_display_param_name(target)} 尚未配置层，现在开始配置",
               f"{_display_param_name(target)} has no layers yet, configuring now"))
        picked = choose_algorithm()
        if picked is None:
            if not state.params[target]["layers"]:
                del state.params[target]
                save_config()
            return
        state.params[target]["layers"].append({
            "algorithm": picked, "encode_before": [], "encode_after": []})
        save_config()
    menu_layer_editor(state.params[target]["layers"],
                      target,
                      params_dict=state.params)
    if target in state.params and not state.params[target]["layers"]:
        del state.params[target]
        save_config()


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


def reorder_params():
    names = [n for n in state.params.keys() if not _is_body_name(n)]
    if len(names) < 2:
        warn(t("至少需要 2 个非整包参数才能调整顺序",
               "Need at least 2 non-body parameters to reorder"))
        pause()
        return
    clear()
    title(t("调整参数处理顺序", "Reorder Parameters"))
    print(f"  {C.GRY}"
          + t("提示：UI 中参数的上下顺序 = 处理数据包时的顺序（自上而下依次处理）",
              "Note: top-to-bottom order = processing order (processed top-down)")
          + C.R)
    print()
    for i, n in enumerate(names, 1):
        print(_param_line(i, n, state.params[n]))
    print()
    raw = ask(t("请输入新的顺序（空格/逗号分隔，如 2 1 3）",
                "New order (space/comma separated, e.g. 2 1 3)"),
              " ".join(str(i) for i in range(1, len(names) + 1)))
    try:
        order = [int(x) - 1 for x in raw.replace(",", " ").split()]
        assert sorted(order) == list(range(len(names)))
    except Exception:
        err(t("顺序不合法", "Invalid order"))
        pause()
        return
    new_dict = {}
    if RESERVED_REQ_BODY in state.params:
        new_dict[RESERVED_REQ_BODY] = state.params[RESERVED_REQ_BODY]
    if RESERVED_RESP_BODY in state.params:
        new_dict[RESERVED_RESP_BODY] = state.params[RESERVED_RESP_BODY]
    for i in order:
        new_dict[names[i]] = state.params[names[i]]
    state.params.clear()
    state.params.update(new_dict)
    save_config()
    ok(t("参数处理顺序已调整", "Parameter order updated"))
    pause()


def menu_params():
    while True:
        clear()
        title(t("配置加解密参数", "Configure Parameters"))
        if not state.params:
            print(f"  {C.YEL}{t('尚未配置任何参数', 'No parameters configured')}{C.R}")
        else:
            print(f"  {C.GRY}"
                  + t(f"当前已配置 {len(state.params)} 个参数（自上而下 = 数据包处理顺序）：",
                      f"{len(state.params)} parameter(s) (top-down = processing order):")
                  + C.R + "\n")
            for i, (name, pcfg) in enumerate(state.params.items(), 1):
                print(_param_line(i, name, pcfg))
        print()
        render_items([
            ("1", t("新增参数", "Add parameter"), ""),
            ("2", t("编辑参数（含改参数名/作用域）",
                    "Edit parameter (rename/scope)"), ""),
            ("3", t("删除参数", "Delete parameter"), ""),
            ("4", t("修改参数名", "Rename parameter"), ""),
            ("5", t("一键套用同一算法到所有参数", "Apply one algorithm to all params"), ""),
            ("6", t("调整参数处理顺序", "Reorder parameters"), ""),
            ("7", t("配置【请求体】整包加解密（📦 请求体）",
                    "Configure [request body] whole-body"),
                  t("/encode 触发（请求侧加密）", "/encode triggers (encrypt on request)")),
            ("8", t("配置【响应体】整包加解密（📦 响应体）",
                    "Configure [response body] whole-body"),
                  t("/decode 触发（响应侧解密）", "/decode triggers (decrypt on response)")),
            ("c", t("清空所有参数配置", "Clear all parameters"), ""),
            ("0", t("返回主菜单", "Back to main menu"), ""),
        ])
        ch = prompt_choice({"1", "2", "3", "4", "5", "6", "7", "8", "c", "0"})
        if ch == "0":
            return
        if ch == "1":
            name = ask(t("请输入参数名（如 password / token / X-Token）",
                         "Enter param name (e.g. password / token / X-Token)"))
            name = (name or "").strip()
            if not name:
                warn(t("参数名不能为空", "Param name cannot be empty"))
                pause()
                continue
            if _is_body_name(name):
                err(t("该名称是保留名，请用菜单 7/8 配置整包",
                      "Reserved name, use menu 7/8 to configure whole body"))
                pause()
                continue
            if name in state.params:
                warn(t("该参数已存在，将进入编辑", "Param already exists, editing"))
            else:
                state.params[name] = empty_param_config()
                save_config()
            menu_layer_editor(state.params[name]["layers"], name,
                              params_dict=state.params)
        elif ch == "2":
            name = pick_param(t("选择要编辑的参数", "Select parameter to edit"))
            if name is None:
                continue
            menu_layer_editor(state.params[name]["layers"], name,
                              params_dict=state.params)
        elif ch == "3":
            # 【修复】允许删除整包
            name = pick_param(t("选择要删除的参数", "Select parameter to delete"),
                              exclude_body=False)
            if name is None:
                continue
            pcfg = state.params[name]
            print()
            print(f"  {t('目标参数', 'Target')}：{C.B}{_display_param_name(name)}{C.R}   "
                  f"{C.GRY}({len(pcfg['layers'])} {t('层', 'layers')}){C.R}")
            if _is_body_name(name):
                warn(t("这是整包参数，删除后整包模式将停用",
                       "Whole-body parameter, deleting will disable whole-body mode"))
            if confirm(t(f"确认删除 {_display_param_name(name)}？",
                         f"Delete {_display_param_name(name)}?")):
                del state.params[name]
                save_config()
                ok(t("已删除", "Deleted"))
            pause()
        elif ch == "4":
            name = pick_param(t("选择要修改名称的参数", "Select parameter to rename"))
            if name is None:
                continue
            new = ask(t("请输入新名称", "New name"), name).strip()
            if new and new != name:
                if _is_body_name(new):
                    err(t("不能使用保留名", "Cannot use reserved name"))
                elif new in state.params:
                    err(t("新名称已存在", "New name already exists"))
                else:
                    state.params[new] = state.params.pop(name)
                    save_config()
                    ok(t(f"已重命名：{name} → {new}", f"Renamed: {name} → {new}"))
            pause()
        elif ch == "5":
            bulk_apply_algo_to_params()
        elif ch == "6":
            reorder_params()
        elif ch == "7":
            menu_whole_body(RESERVED_REQ_BODY)
        elif ch == "8":
            menu_whole_body(RESERVED_RESP_BODY)
        elif ch == "c":
            if confirm(t("确认清空所有参数配置？", "Clear all parameters?"), False):
                state.params.clear()
                save_config()
                ok(t("已清空", "Cleared"))
                pause()


# =====================================================================
# 菜单 3：进阶配置
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
            ("2", t("重新加载配置文件", "Reload from file"), ""),
            ("3", t("恢复全部出厂默认", "Factory reset"), ""),
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
            if confirm(t("确认恢复出厂默认？", "Factory reset?"), False):
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
            ("1", t("数据格式设置", "Data format"), mode_label),
            ("2", t("表单值自动 URL 编码/解码", "Auto URL encode/decode form values"),
                  t("开启", "on") if s["form_url_coded"] else t("关闭", "off")),
            ("3", t("未配置参数统一处理", "Default handling for unconfigured params"),
                  default_desc),
            ("4", t("调试输出（含每步中间结果）",
                    "Debug output (incl. per-step trace)"),
                  t("开启", "on") if s["debug_print"] else t("关闭", "off")),
            ("5", t("菜单清屏", "Clear screen on menu"),
                  t("开启", "on") if s["clear_on_menu"] else t("关闭", "off")),
            ("6", t("服务监听地址", "Server listen address"),
                  f"{s['host']}:{s['port']}"),
            ("7", t("配置文件管理", "Config file manager"), cfg_desc),
            ("8", t("失败处理方式", "Failure handling"),
                  f"{C.GRY}{s.get('fail_mode', 'passthrough')}{C.R}"),
            ("0", t("返回主菜单", "Back to main menu"), ""),
        ]
        render_items(items)
        ch = prompt_choice({"1", "2", "3", "4", "5", "6", "7", "8", "0"})
        if ch == "0":
            return
        if ch == "1":
            menu_data_format()
        elif ch == "2":
            s["form_url_coded"] = not s["form_url_coded"]
            save_config()
            ok(t(f"表单 URL 编码处理：{'开启' if s['form_url_coded'] else '关闭'}",
                 f"Form URL encode: {'on' if s['form_url_coded'] else 'off'}"))
            pause()
        elif ch == "3":
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
        elif ch == "4":
            s["debug_print"] = not s["debug_print"]
            save_config()
            ok(t(f"调试输出：{'开启' if s['debug_print'] else '关闭'}（开启时打印每一步中间结果）",
                 f"Debug: {'on' if s['debug_print'] else 'off'} (prints per-step trace)"))
            pause()
        elif ch == "5":
            s["clear_on_menu"] = not s["clear_on_menu"]
            save_config()
            ok(t(f"菜单清屏：{'开启' if s['clear_on_menu'] else '关闭'}",
                 f"Clear screen: {'on' if s['clear_on_menu'] else 'off'}"))
            pause()
        elif ch == "6":
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
        elif ch == "7":
            menu_config_file()
        elif ch == "8":
            clear()
            title(t("失败处理方式", "Failure handling"))
            print(f"  {t('当前', 'Current')}：{C.GRY}{s.get('fail_mode', 'passthrough')}{C.R}")
            print()
            print(f"   {C.YEL}1{C.R}) passthrough  "
                  + t("失败时返回原值（老行为，Burp 里看不出异常）",
                      "return original value on failure (legacy)"))
            print(f"   {C.YEL}2{C.R}) http_500     "
                  + t("失败时返回 500 + 错误文本（调用方直接可见）",
                      "return 500 + error text (visible to caller)"))
            print()
            render_items([("0", t("取消", "Cancel"), "")])
            sub = prompt_choice({"1", "2", "0"})
            if sub == "1":
                s["fail_mode"] = "passthrough"
            elif sub == "2":
                s["fail_mode"] = "http_500"
            else:
                continue
            save_config()
            ok(t(f"失败处理方式已设为 {s['fail_mode']}",
                 f"fail_mode set to {s['fail_mode']}"))
            pause()


# =====================================================================
# 菜单 4：预览
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
    scope = pcfg.get("scope", SCOPE_AUTO)
    if _is_body_name(name):
        _scope_tag = f"{C.YEL}[body]{C.R}"
    else:
        _scope_tag = scope_label(scope)
    print(f"\n   {C.B}{C.CYA}▸ {_display_param_name(name)}{C.R} {_scope_tag}   "
          f"{C.GRY}({len(pcfg['layers'])} {t('层', 'layers')}){C.R}")
    if name == RESERVED_REQ_BODY:
        print(f"       {C.GRY}"
              + t("(整包处理：/encode 时对请求体直接加解密)",
                  "(whole body: /encode processes request body directly)")
              + C.R)
    elif name == RESERVED_RESP_BODY:
        print(f"       {C.GRY}"
              + t("(整包处理：/decode 时对响应体直接加解密)",
                  "(whole body: /decode processes response body directly)")
              + C.R)
    elif scope == SCOPE_REQ_HEADER:
        print(f"       {C.GRY}"
              + t("(请求头字段：/encode 时处理 dataHeaders)",
                  "(request header: processed by /encode on dataHeaders)")
              + C.R)
    elif scope == SCOPE_RESP_HEADER:
        print(f"       {C.GRY}"
              + t("(响应头字段：/decode 时处理 dataHeaders)",
                  "(response header: processed by /decode on dataHeaders)")
              + C.R)
    enc_steps = build_route(pcfg["layers"], encrypt=True)
    dec_steps = build_route(pcfg["layers"], encrypt=False)
    dm = state.settings["data_mode"]
    show_url = (state.settings["form_url_coded"] and dm in ("auto", "form")
                and not _is_body_name(name)
                and scope not in (SCOPE_REQ_HEADER, SCOPE_RESP_HEADER))
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
        scope = state.params[n].get("scope", SCOPE_AUTO)
        tag = scope_label(scope) if not _is_body_name(n) else f"{C.YEL}[body]{C.R}"
        print(f"   {C.YEL}{i}{C.R}) {_display_param_name(n)}  {tag}")
    raw = ask(t("请选择要测试的参数编号", "Param number to test"), "1")
    try:
        name = names[int(raw) - 1]
    except Exception:
        err(t("无效编号", "Invalid number"))
        pause()
        return
    layers = state.params[name]["layers"]
    if _is_body_name(name):
        info(t("整包测试：输入被当作整个 body",
               "Whole body test: input is treated as the entire body"))
    plain = ask(t("请输入明文", "Enter plaintext"), "hello world")
    print()
    try:
        cipher = multi_encrypt(plain, layers, trace=False)
        is_hdr = state.params[name].get("scope") in (SCOPE_REQ_HEADER, SCOPE_RESP_HEADER)
        if (not _is_body_name(name) and not is_hdr
                and state.settings["form_url_coded"]
                and state.settings["data_mode"] in ("auto", "form")):
            cipher = quote(cipher, safe="")
        print(f"   {C.GRN}{t('加密结果', 'Cipher')}：{C.R}{cipher}")
        dec_input = cipher
        if (not _is_body_name(name) and not is_hdr
                and state.settings["form_url_coded"]
                and state.settings["data_mode"] in ("auto", "form")):
            dec_input = unquote(dec_input)
        back = multi_decrypt(dec_input, layers, trace=False)
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
            print(f"  {C.GRY}"
                  + t("（参数自上而下即数据包处理顺序）",
                      "(top-down = data processing order)")
                  + C.R)
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
# 菜单 5：启动服务
# =====================================================================
_CRLF4 = "\r\n\r\n\r\n\r\n"


def _join_two_part(headers, body):
    """[M1][H3] 组装插件要的两段式应答：<headers> + 4×CRLF + <body>

    插件侧逻辑是 `resp.split("\\r\\n\\r\\n\\r\\n\\r\\n")`，
    取 arr[0] 当 HTTP 头、arr[1] 当 body；arr.length == 1 时会把整段当"只有头没有 body"。
    所以分隔符必须恰好是 4 组 CRLF，且头尾部不能自带 CRLF，
    否则连写后被 split 吃掉 4 组，剩下的残留在 body 前面，污染 form 首字段名。
    """
    head = (headers or "").strip("\r\n")
    body = body or ""
    if not head:
        # scope 不含 header 时仍返回两段：插件对空头是接受的（arr[0] 为空串）
        return _CRLF4 + body
    return head + _CRLF4 + body


def _form_memory_limit(app=None):
    """[R-09] 表单体上限（字节）：Werkzeug 默认 500 KB，可被 app.config 覆盖。"""
    if app is not None:
        try:
            v = app.config.get("MAX_FORM_MEMORY_SIZE")
        except Exception:
            v = None
        if isinstance(v, int) and v > 0:
            return v
    return 500000


def build_app():
    from flask import Flask, request
    app = Flask("interactive-crypto-tool")
    app.debug = False

    def _utf8_failure(seq0):
        """[R-10] 本次请求里是否出现「解密结果不是 UTF-8」。"""
        for e in _errors_since(seq0):
            if e.get("utf8"):
                return e
        return None

    @app.before_request
    def _check_token():
        """[Low] 可选令牌校验：api_token 为空则不启用（保持向后兼容）。

        以前服务无任何鉴权，任何能连上端口的人都能把你的加解密中继当免鉴权
        加密机用。填了令牌后可用三种方式之一携带：
            X-Auth-Token: <token>
            ?token=<token>
            form 字段 token=<token>
        """
        want = (state.settings.get("api_token") or "").strip()
        if not want:
            return None
        got = (request.headers.get("X-Auth-Token")
               or request.args.get("token")
               or request.form.get("token") or "")
        if got.strip() != want:
            return ("[JEADChain] unauthorized\n", 401)
        return None

    @app.route("/last-errors", methods=["GET"])
    def _last_errors():
        # [R-02][R-11] notes：配置规范化提示 + data_mode 判定/同名键等非致命信息
        payload = {
            "total": _ERR_SEQ[0],
            "recent": list(_ERRORS),
            "notes": list(_NOTES),
            "config_notes": config_notes(),
        }
        return (json.dumps(payload, ensure_ascii=False, indent=2), 200,
                {"Content-Type": "application/json; charset=utf-8"})

    @app.route("/health", methods=["GET"])
    def _health():
        # [R-02][R-09] 版本 / 配置规范化提示 / 表单上限，便于排查"配了却不生效"
        _bak = config_backup_path()
        payload = {
            "version": VERSION,
            "data_mode": state.settings.get("data_mode"),
            "form_url_coded": bool(state.settings.get("form_url_coded", True)),
            "form_limit_bytes": _form_memory_limit(app),
            "params": list(state.params.keys()),
            "config_notes": config_notes(),
            "notes": list(_NOTES),
            # [R-14] 配置备份：backup_exists=True 时，.bak 就是上一次保存前的配置
            "config_file": config_write_path(),
            "backup_file": _bak,
            "backup_exists": os.path.exists(_bak),
        }
        return (json.dumps(payload, ensure_ascii=False, indent=2), 200,
                {"Content-Type": "application/json; charset=utf-8"})

    @app.errorhandler(413)
    def _too_large(e):
        """[R-09] 表单超过上限时给出可执行的处置建议，而不是 werkzeug 的裸 413。"""
        lim = _form_memory_limit(app)
        kb = lim / 1024.0
        msg = t(
            f"[JEADChain] 请求体过大：超过服务端 {lim} 字节（约 {kb:.0f} KB）的表单上限，"
            f"本次未被处理。\n"
            f"建议：① 缩短该字段或分片发送大 body；"
            f"② 关闭 payload 的 base64/hex 膨胀（膨胀后体积约为原始的 4/3～2 倍）；"
            f"③ 大文件改用整包 __req_body__ 之外的通道，或调大 MAX_FORM_MEMORY_SIZE。",
            f"[JEADChain] request too large: exceeds the {lim}-byte (~{kb:.0f} KB) form "
            f"limit.\nSuggestions: shorten or split the field, disable base64/hex "
            f"inflation, or raise MAX_FORM_MEMORY_SIZE.")
        return msg, 413

    @app.route("/encode", methods=["POST"])
    def _encode():
        seq0 = _ERR_SEQ[0]
        body = (request.form.get("dataBody") or "").strip("\r\n")
        headers = request.form.get("dataHeaders") or ""
        rr = request.form.get("requestorresponse") or ""
        if state.settings["debug_print"]:
            print(f"{C.CYA}{'='*70}{C.R}")
            print(f"{C.B}[encode]{C.R} {C.GRY}原始数据体：{C.R}{_short(body, 200)}")
            if headers.strip():
                print(f"{C.B}[encode]{C.R} {C.GRY}原始头：{C.R}{_short(headers, 200)}")
        try:
            out_body, out_headers = process_payload(body, headers, "encrypt")
        except Exception as e:
            _record_error("encode", e)
            out_body, out_headers = body, headers
            if state.settings["debug_print"]:
                traceback.print_exc()
        if state.settings["debug_print"]:
            print(f"{C.B}[encode]{C.R} {C.GRY}最终结果：{C.R}{_short(out_body, 200)}")
            if out_headers != headers:
                print(f"{C.B}[encode]{C.R} {C.GRY}最终头：{C.R}{_short(out_headers, 200)}")
        if _ERR_SEQ[0] > seq0 and state.settings.get("fail_mode") == "http_500":
            last = _ERRORS[-1] if _ERRORS else {"where": "-", "detail": "unknown"}
            msg = t(f"[JEADChain] 处理失败 [{last['where']}]：{last['detail']}",
                    f"[JEADChain] failed [{last['where']}]: {last['detail']}")
            return msg, 500
        # [R-10] 输出不是 UTF-8 时返回明确文案，而不是把乱码/原密文当结果吐出去。
        # [F-03] 这是 /encode，措辞用「处理失败」；该分支在加密方向基本不可达
        #        （multi_encrypt 只走 encode_step，不产生 NonUtf8Error）。
        # [F-02] 文案必须按 rr 走两段式：否则插件 arr.length==1，把整段当 HTTP 头、
        #        body 为空（直接推翻 M1）。
        # [F-01] 且只有整条 body 都解不出来（单字段）时才用文案顶替整条响应；
        #        多字段时保留其余字段的结果，失败字段已由 _apply_layers 原样透传。
        bad = _utf8_failure(seq0)
        if bad is not None and "&" not in body:
            msg = t(f"[JEADChain] 处理失败 [{bad['where']}]：{bad['detail']}",
                    f"[JEADChain] encode failed [{bad['where']}]: {bad['detail']}")
            # [F-10] 头段必须是处理后的 headers，不能给空串：_join_two_part("", msg)
            #        会返回 CRLF4+msg，段 0 变成空串，插件 arr[0].split("\r\n") 得到 [""]，
            #        buildHttpMessage 就会把整组 header 清空（Cookie/Content-Type 全丢），
            #        用户看到的是「解密失败一次，后续请求的认证头也没了」。
            if rr.strip().lower() in ("request", "response"):
                return _join_two_part(out_headers, msg)
            return msg
        # [M1] 插件在请求方向传 requestorresponse="request"，响应方向传 "response"；
        # 旧代码只认 "request"，导致 /decode 永远返回单段，插件把明文当 HTTP 头、body 为空。
        # [H3] 分隔符拼接前必须剥掉头尾部已有的 CRLF，否则连写的 CRLF 会被插件 split 后
        # 残留到 body 前面，污染 form 首字段名。
        if rr.strip().lower() in ("request", "response"):
            return _join_two_part(out_headers, out_body)
        return out_body

    @app.route("/decode", methods=["POST"])
    def _decode():
        seq0 = _ERR_SEQ[0]
        body = (request.form.get("dataBody") or "").strip("\r\n")
        headers = request.form.get("dataHeaders") or ""
        rr = request.form.get("requestorresponse") or ""
        if state.settings["debug_print"]:
            print(f"{C.CYA}{'='*70}{C.R}")
            print(f"{C.B}[decode]{C.R} {C.GRY}原始数据体：{C.R}{_short(body, 200)}")
            if headers.strip():
                print(f"{C.B}[decode]{C.R} {C.GRY}原始头：{C.R}{_short(headers, 200)}")
        try:
            out_body, out_headers = process_payload(body, headers, "decrypt")
        except Exception as e:
            _record_error("decode", e)
            out_body, out_headers = body, headers
            if state.settings["debug_print"]:
                traceback.print_exc()
        if state.settings["debug_print"]:
            print(f"{C.B}[decode]{C.R} {C.GRY}最终结果：{C.R}{_short(out_body, 200)}")
            if out_headers != headers:
                print(f"{C.B}[decode]{C.R} {C.GRY}最终头：{C.R}{_short(out_headers, 200)}")
        if _ERR_SEQ[0] > seq0 and state.settings.get("fail_mode") == "http_500":
            last = _ERRORS[-1] if _ERRORS else {"where": "-", "detail": "unknown"}
            msg = t(f"[JEADChain] 处理失败 [{last['where']}]：{last['detail']}",
                    f"[JEADChain] failed [{last['where']}]: {last['detail']}")
            return msg, 500
        # [R-10] 明文不是 UTF-8 时返回明确文案，而不是把乱码/原密文当结果吐出去。
        # [F-02] 文案必须按 rr 走两段式：否则插件 arr.length==1，把整段当 HTTP 头、
        #        body 为空（直接推翻 M1）。
        # [F-01] 且只有整条 body 都解不出来（单字段）时才用文案顶替整条响应；
        #        多字段时保留其余字段的结果，失败字段已由 _apply_layers 原样透传。
        bad = _utf8_failure(seq0)
        if bad is not None and "&" not in body:
            msg = t(f"[JEADChain] 解密失败 [{bad['where']}]：{bad['detail']}",
                    f"[JEADChain] decrypt failed [{bad['where']}]: {bad['detail']}")
            # [F-10] 同 /encode：头段必须是处理后的 headers，空串会让插件清空整组 header。
            if rr.strip().lower() in ("request", "response"):
                return _join_two_part(out_headers, msg)
            return msg
        # [M1] 插件在请求方向传 requestorresponse="request"，响应方向传 "response"；
        # 旧代码只认 "request"，导致 /decode 永远返回单段，插件把明文当 HTTP 头、body 为空。
        # [H3] 分隔符拼接前必须剥掉头尾部已有的 CRLF，否则连写的 CRLF 会被插件 split 后
        # 残留到 body 前面，污染 form 首字段名。
        if rr.strip().lower() in ("request", "response"):
            return _join_two_part(out_headers, out_body)
        return out_body

    return app


def _list_access_urls(host, port):
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

    _param_summary = ", ".join(
        "{}({})".format(_display_param_name(k),
                        "body" if _is_body_name(k)
                        else _param_scope(state.params[k], k))
        for k in state.params
    ) or t("(无)", "(none)")

    # [R-02] 启动时把配置规范化提示报一次（不阻断启动）
    _report_config_notes(sink="serve")

    print()
    print(f"  {C.GRY}{t('数据格式', 'Data mode')}    :{C.R} {s['data_mode']}")
    print(f"  {C.GRY}{t('已配置参数', 'Params')}  :{C.R} {_param_summary}")
    print(f"  {C.GRY}{t('调试输出', 'Debug')}     :{C.R} "
          f"{t('开启（打印每一步）', 'on (print every step)') if s['debug_print'] else t('关闭', 'off')}")
    print(f"  {C.GRY}{t('默认处理', 'Default')}    :{C.R} "
          f"{t('启用', 'enabled') if s['enable_default'] else t('关闭', 'disabled')}")
    req_p = state.params.get(RESERVED_REQ_BODY)
    resp_p = state.params.get(RESERVED_RESP_BODY)
    if _param_layers(req_p, RESERVED_REQ_BODY) if req_p is not None else []:
        print(f"  {C.YEL}{t('请求体整包', 'Req body')}   :{C.R} "
              + t("已启用（/encode 触发）", "enabled (triggered on /encode)"))
    if _param_layers(resp_p, RESERVED_RESP_BODY) if resp_p is not None else []:
        print(f"  {C.YEL}{t('响应体整包', 'Resp body')}  :{C.R} "
              + t("已启用（/decode 触发）", "enabled (triggered on /decode)"))
    # [F-09] 先把 app 建出来：启动行必须读 app.config["MAX_FORM_MEMORY_SIZE"]，
    #        否则 /health 与 413 吃的是覆盖值、启动行却永远显示默认 500000。
    #        build_app() 只装配路由不绑定端口，失败处理与原来一致。
    try:
        app = build_app()
    except Exception as e:
        err(t(f"启动失败：{e}", f"Failed to start: {e}"))
        pause()
        return

    # [R-09] 表单上限以前完全不可见：用户只知道"某次请求开始没反应了"
    _lim = _form_memory_limit(app)
    print(f"  {C.GRY}{t('表单上限', 'Form limit')}   :{C.R} "
          f"{_lim} {t('字节', 'bytes')} (≈{_lim / 1024:.0f} KB)  "
          f"{C.GRY}{t('超出返回 413 并给出精简建议', 'over-limit → 413 + advice')}{C.R}")
    print()
    try:
        from werkzeug.serving import make_server
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
        print(f"    {C.GRN}http://{a}:{port}/last-errors{C.R}    "
              f"{C.GRY}{t('查看最近失败（浏览器直接打开）', 'recent failures (open in browser)')}{C.R}")
    print()
    info(t("AutoDecoder 里填 127.0.0.1 就行，即使监听的是 0.0.0.0 也能连通",
           "Use 127.0.0.1 in AutoDecoder even if listening on 0.0.0.0"))
    print(f"  {C.GRY}{t('表单字段', 'Form fields')}："
          f"dataBody / dataHeaders / requestorresponse{C.R}")
    if s["debug_print"]:
        info(t("已开启每步 debug：请求时会打印参数、每层每步的输入输出",
               "Per-step debug is ON: parameter, each layer's in/out will be logged"))
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
        ("1", "中文（CN）", f"{C.GRN}●{C.R}" if cur == "zh" else ""),
        ("2", "English (EN)", f"{C.GRN}●{C.R}" if cur == "en" else ""),
        ("0", t("返回", "Back"), ""),
    ]
    render_items(items)
    ch = prompt_choice({"1", "2", "0"})
    if ch == "1" and cur != "zh":
        current_lang = "zh"
        save_config()
        ok("语言已切换为中文（CN）")
    elif ch == "2" and cur != "en":
        current_lang = "en"
        save_config()
        ok("Language switched to English (EN)")
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
        param_names = [_display_param_name(n) for n in state.params.keys()]
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
        # [R-02] 菜单侧也报一次（sink 记录后不会随循环重复刷）
        _report_config_notes(sink="menu")

        lang_label = "中文（CN）" if current_lang == "zh" else "English (EN)"
        print()
        render_items([
            ("0", t("一键安装 / 修复运行环境", "Install / Repair environment"), env_state),
            ("1", t("配置加解密算法", "Configure algorithms"),
                  f"{C.GRY}"
                  + t(f"已配置 {sum(1 for k in ALGO_ORDER if algo_configured(k))} 个",
                      f"{sum(1 for k in ALGO_ORDER if algo_configured(k))} configured")
                  + C.R),
            ("2", t("配置加解密参数", "Configure parameters"), param_desc),
            ("3", t("进阶配置", "Advanced settings"),
                  f"{C.GRY}{t('数据格式', 'Data mode')}: {mode_label}{C.R}"),
            ("4", t("预览加解密流程", "Preview pipeline"), ""),
            ("5", t("启动服务", "Start server"),
                  f"{C.GRY}{state.settings['host']}:{state.settings['port']}{C.R}"),
            ("a", t("切换语言 / Switch Language", "Switch Language / 切换语言"),
                  f"{C.GRY}{t('当前', 'Current')}: {lang_label}{C.R}"),
            ("q", t("退出", "Quit"),
                  f"{C.GRY}{t('配置自动保存', 'auto-save on exit')}{C.R}"),
        ])
        print()
        ch = prompt_choice({"0", "1", "2", "3", "4", "5", "a", "q"})

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
                menu_params()
            elif ch == "3":
                menu_advanced()
            elif ch == "4":
                menu_preview()
            elif ch == "5":
                menu_serve()
            elif ch == "a":
                menu_language()
        finally:
            save_config()


def entry():
    if os.name == "nt":
        try:
            os.system("chcp 65001 > nul")
        except Exception:
            pass
    load_config()
    # [R-02] 启动时（主菜单出现前）先把配置规范化提示报一次
    _report_config_notes(sink="startup")
    try:
        main_menu()
    except KeyboardInterrupt:
        save_config()
        print()
        print(f"\n  {C.YEL}{t('已中断，配置已保存，再见', 'Interrupted, config saved, bye')}{C.R}\n")
        sys.exit(0)


if __name__ == "__main__":
    entry()