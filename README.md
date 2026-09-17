# Autodecoder-ScriptTemplate
Autodecoder-ScriptTemplate / autodecoder 插件的通用脚本模板

<a href="README.md"><img src="https://img.shields.io/badge/-简体中文-red.svg" alt="简体中文"></a>
<a href="README_EN.md"><img src="https://img.shields.io/badge/-English-blue.svg" alt="English"></a>

# 脚本介绍

这是一个基于 Flask 的**通用加解密中间件**，用于配合 AutoDecoder、Burp 插件等工具对 HTTP 请求/响应中的指定参数做加解密、编解码处理。支持**对称加密、非对称加密、国密、哈希、HMAC**五大类算法，支持多参数、多层加解密、多重编码链，自动识别 JSON 与表单格式。

---

## 一、整体结构

```text
配置区（算法选择 / 通用开关 / 算法密钥 / 参数配置）
        ↓
算法实现层
    ├─ 对称加密：AES / DES / 3DES / Blowfish / CAST / RC2 / RC4 / SM4
    ├─ 非对称加密：RSA / SM2
    ├─ 哈希：MD5 / SHA1 / SHA256 / SHA512 / SM3
    └─ HMAC：hmac-md5 / hmac-sha1 / hmac-sha256 / hmac-sha512
        ↓
编码工具层（none / url / base64 / hex）
        ↓
层解析与多层加解密（multi_encrypt / multi_decrypt）
        ↓
JSON 处理 / 表单处理
        ↓
统一入口 process_data
        ↓
Flask 路由 /encode 和 /decode
```

---

## 二、支持的算法全览

### 1. 对称加密

| 算法 | 配置键 | 依赖库 | 密钥长度 |
|---|---|---|---|
| AES | `aes` | `pycryptodome` | 16 / 24 / 32 字节 |
| DES | `des` | `pycryptodome` | 8 字节 |
| 3DES（DESede） | `3des` | `pycryptodome` | 16 / 24 字节 |
| Blowfish | `blowfish` | `pycryptodome` | 4 ~ 56 字节 |
| CAST | `cast` | `pycryptodome` | 5 ~ 16 字节 |
| RC2 | `rc2` | `pycryptodome` | 5 ~ 16 字节 |
| RC4（流加密） | `rc4` | `pycryptodome` | 5 ~ 256 字节 |
| SM4 | `sm4` | `gmssl` + `pycryptodome`（填充） | 16 字节 |

支持 `CBC` / `ECB` 模式，`pkcs7` 填充。RC4 是流加密，无需 IV 和填充。

### 2. 非对称加密

| 算法 | 配置键 | 依赖库 | 说明 |
|---|---|---|---|
| RSA | `rsa` | `pycryptodome` | PKCS1 / OAEP，自动分块 |
| SM2 | `sm2` | `gmssl` | C1C2C3 / C1C3C2 |

### 3. 哈希（单向）

| 算法 | 配置键 | 依赖库 |
|---|---|---|
| MD5 | `md5` | 内置 `hashlib` |
| SHA-1 | `sha1` | 内置 `hashlib` |
| SHA-256 | `sha256` | 内置 `hashlib` |
| SHA-512 | `sha512` | 内置 `hashlib` |
| SM3 | `sm3` | `gmssl` |

### 4. HMAC（单向）

| 算法 | 配置键 | 依赖库 |
|---|---|---|
| HMAC-MD5 | `hmac-md5` | 内置 `hmac` + `hashlib` |
| HMAC-SHA1 | `hmac-sha1` | 内置 `hmac` + `hashlib` |
| HMAC-SHA256 | `hmac-sha256` | 内置 `hmac` + `hashlib` |
| HMAC-SHA512 | `hmac-sha512` | 内置 `hmac` + `hashlib` |

HMAC 密钥在 `HMAC_CONFIG["key"]` 里配置。

### 5. 纯编码

`none`：不做加解密，只做编码链。

---

## 三、依赖安装

```bash
# 必需
pip install flask

# 对称加密 + RSA + 哈希填充
pip install pycryptodome

# 国密（SM2 / SM3 / SM4）
pip install gmssl
```

| 算法 | 必须安装的库 |
|---|---|
| AES / DES / 3DES / Blowfish / CAST / RC2 / RC4 | `pycryptodome` |
| RSA | `pycryptodome` |
| SM4（含 pkcs7 填充） | `pycryptodome` + `gmssl` |
| SM2 | `gmssl` |
| SM3 | `gmssl` |
| MD5 / SHA1 / SHA256 / SHA512 | Python 内置，无需安装 |
| HMAC-MD5 / SHA1 / SHA256 / SHA512 | Python 内置，无需安装 |

---

## 四、对外接口

脚本启动后监听 `0.0.0.0:8888`，提供两个接口：

| 接口 | 方法 | 作用 |
|---|---|---|
| `/encode` | POST | 对参数做加密 |
| `/decode` | POST | 对参数做解密 |

两个接口都接收三个表单字段：

| 字段 | 说明 |
|---|---|
| `dataBody` | 原始请求体或响应体 |
| `dataHeaders` | 原始请求头 |
| `requestorresponse` | `"request"` 或 `"response"` |

返回规则：

- `requestorresponse == "request"`：返回 `headers + \r\n\r\n\r\n\r\n + 处理后的 body`
- 其他情况：只返回处理后的 body

---

## 五、配置区详解

### 1. `ALGORITHM`：全局默认算法

```python
ALGORITHM = "none"   # 具体算法名 或 "none"
```

- 指定具体算法：所有未在层内指定算法的层都使用它。
- 设为 `"none"`：自动检测哪个算法配置了 `enabled=True`，按 **AES → DES → 3DES → SM4 → Blowfish → CAST → RC2 → RC4 → RSA → SM2** 顺序取第一个。

优先级：

```text
层内显式 algorithm（含 "none"）  >  全局 ALGORITHM  >  自动检测 enabled
```

### 2. `DEBUG_PRINT`：是否打印明文/密文

```python
DEBUG_PRINT = True
```

安全测试时可开，多人协作或日志被采集时建议关掉。

### 3. `FORM_VALUE_URL_CODED`：表单值的 URL 编码契约

```python
FORM_VALUE_URL_CODED = True
```

- `True`（默认）：客户端对 `dataBody` 的值做 URL 编码，脚本加密端 `quote`、解密端 `unquote`。
- `False`：客户端不做额外编码，脚本两端都不做。

两边必须一致，否则加解密不对称。

### 4. 算法配置

每个算法都有独立的配置字典，例如：

```python
AES_CONFIG = {
    "enabled": True,
    "key": b"1234567890123456",
    "iv": b"1234567890123456",
    "mode": "CBC",              # "CBC" / "ECB"
    "padding": "pkcs7",         # "pkcs7" / "none"
}
```

DES、3DES、Blowfish、CAST、RC2、SM4 结构类似，密钥和 IV 长度不同。

RC4 只需 `key`：

```python
RC4_CONFIG = {
    "enabled": False,
    "key": b"1234567890123456",
}
```

RSA 和 SM2 使用密钥对：

```python
RSA_CONFIG = {
    "enabled": False,
    "public_key": "",       # PEM 字符串
    "private_key": "",
    "padding": "pkcs1",     # "pkcs1" / "oaep"
}

SM2_CONFIG = {
    "enabled": False,
    "public_key": "",       # hex，128 字符（X||Y）
    "private_key": "",      # hex，64 字符
    "mode": 1,              # 0=C1C2C3, 1=C1C3C2
}
```

HMAC 配置：

```python
HMAC_CONFIG = {
    "enabled": False,
    "key": b"shared-secret",
    "hash_algorithm": "sha256",   # "md5" / "sha1" / "sha256" / "sha512"
}
```

### 5. `TARGET_PARAMS`：要处理的参数

支持两种写法。

**单层写法（简单场景）**：

```python
TARGET_PARAMS = {
    "password": {
        "algorithm": "aes",
        "encrypt_encodings": ["base64"],
        "decrypt_decodings": ["base64"],
    },
}
```

**多层写法（多轮加解密）**：

```python
TARGET_PARAMS = {
    "encryptedData": {
        "layers": [
            # 内层：先执行
            {"algorithm": "aes",
             "encrypt_encodings": ["none"],
             "decrypt_decodings": ["none"]},
            # 外层：后执行
            {"algorithm": "rsa",
             "encrypt_encodings": ["base64"],
             "decrypt_decodings": ["base64"]},
        ],
    },
}
```

`layer` 中 `algorithm` 含义：

| 值 | 含义 |
|---|---|
| 未写 / `None` | 走全局 `ALGORITHM` |
| 具体算法名（如 `"aes"`、`"des"`、`"rsa"`） | 强制使用该算法 |
| `"none"` | 跳过加解密，只做编码/解码链 |

编码方式可选：

| 编码 | 加密时 | 解密时 |
|---|---|---|
| `"none"` | 不变 | 不变 |
| `"url"` | `quote(data, safe='')` | `unquote(data)` |
| `"base64"` | Base64 编码 | Base64 解码 |
| `"hex"` | 十六进制编码 | 十六进制解码 |

### 6. `ENABLE_DEFAULT` 和 `DEFAULT_LAYERS`

未在 `TARGET_PARAMS` 中列出的参数，如果也想统一处理：

```python
ENABLE_DEFAULT = True
DEFAULT_LAYERS = [
    {"algorithm": None, "encrypt_encodings": ["none"], "decrypt_decodings": ["none"]},
]
```

`algorithm` 为 `None` 表示走全局 `ALGORITHM`。

---

## 六、多层执行顺序

**加密**：`layers` 列表**从内到外**执行，即索引 0 先执行。

```text
明文
  → 层 0 加密 → 层 0 编码
  → 层 1 加密 → 层 1 编码
  → 最终密文
```

**解密**：`layers` 列表**从外到内**执行，即索引 1 先执行。

```text
最终密文
  → 层 1 解码 → 层 1 解密
  → 层 0 解码 → 层 0 解密
  → 明文
```

记忆法：**`layers` 书写顺序 = 加密执行顺序；解密是它的逆序。**

---

## 七、数据格式识别

`process_data` 会自动判断 `dataBody`：

1. **能解析为 JSON 对象**：走 JSON 处理，只处理顶层字符串值。
2. **能解析为 JSON 数组或标量**：原样返回，不做处理。
3. **其他**：走表单处理，按 `&` 分割，找 `key` 在 `TARGET_PARAMS` 中的项，只处理 `value`。

---

## 八、使用步骤

### 1. 安装依赖

```bash
pip install flask pycryptodome gmssl
```

用不到的算法库可以不装，脚本只在调用对应算法时才检查。

### 2. 修改算法配置

根据目标系统填写密钥、IV、模式、填充、公钥、私钥、HMAC 密钥等。

### 3. 配置目标参数

把需要加解密的参数名和编码链写进 `TARGET_PARAMS`。

### 4. 启动服务

```bash
python run.py
```

### 5. 接入 AutoDecoder / Burp

- 加密接口：`http://127.0.0.1:8888/encode`
- 解密接口：`http://127.0.0.1:8888/decode`
- 请求字段：`dataBody` / `dataHeaders` / `requestorresponse`

---

## 九、典型配置示例

### 示例 1：单参数 AES + Base64

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

### 示例 2：DES 加密

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

### 示例 3：3DES 加密

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

### 示例 4：多参数不同算法

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

### 示例 5：多层 AES → RSA → Base64

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

### 示例 6：JSON 格式

`dataBody` 为：

```json
{"encryptedData": "xxxxx", "username": "admin"}
```

脚本自动识别为 JSON，只处理 `encryptedData`，`username` 原样保留。

### 示例 7：纯编码不做加解密

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

### 示例 8：HMAC-SHA256 签名

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

> HMAC 是单向的，`/encode` 能生成签名，`/decode` 会抛 `NotImplementedError`。

---

## 十、哈希与 HMAC 的特殊说明

哈希（MD5/SHA/SM3）和 HMAC 是**单向算法**：

| 算法 | 加密（计算摘要） | 解密 |
|---|---|---|
| MD5 / SHA-1 / SHA-256 / SHA-512 / SM3 | ✅ | ❌ 不可逆 |
| HMAC-MD5 / HMAC-SHA256 / ... | ✅ | ❌ 不可逆 |

如果在 `TARGET_PARAMS` 里给某个参数配了哈希或 HMAC，`/decode` 会直接报 `NotImplementedError`，这是符合预期的。

---

## 十一、限制与注意事项

### 功能限制

1. **仅处理表单格式和 JSON 对象**。`/decode` 从 `request.form.get('dataBody')` 取值，客户端必须以 `application/x-www-form-urlencoded` 提交。
2. **JSON 只处理顶层字符串值**。`{"data": {"token": "xxx"}}` 这样的嵌套不会处理。
3. **JSON 数组、标量原样返回**，不做处理。
4. **HMAC-SM3 暂未实现**，会抛 `NotImplementedError`。

### 安全注意

1. **密钥和 IV 必须与目标系统一致**，否则报 `Padding is incorrect` 或解密出乱码。
2. **`DEBUG_PRINT` 默认开启会打印明文**，多人环境建议关闭。
3. **生产环境请关闭 `app.debug`**。
4. 仅用于合法授权的安全测试。

### 编码约定

1. 编码链中的 `url` 使用 `quote(data, safe='')` / `unquote(data)`，严格对称。
2. 表单层的 URL 编码由 `FORM_VALUE_URL_CODED` 控制，与编码链解耦。
3. `layers` 书写顺序 = 加密顺序，解密逆序执行。

---

## 十二、一句话总结

**改顶部配置，启动服务，接入工具即可。** 无论是 AES、DES、3DES、SM4、RSA、SM2，还是 MD5、SHA、SM3、HMAC，无论单层还是多层，单参数还是多参数，JSON 还是表单，都可以通过 `TARGET_PARAMS` 加 `layers` 描述出来，脚本会自动按规则加解密。所有算法的依赖库都已在配置区注释中标注，按需安装即可。
