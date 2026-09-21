<a href="README.md"><img src="https://img.shields.io/badge/-简体中文-red.svg" alt="简体中文"></a>
<a href="README_EN.md"><img src="https://img.shields.io/badge/-English-blue.svg" alt="English"></a>

# 脚本介绍

Interactive Crypto Tool 是一个基于 Flask 的 **交互式加解密配置控制台**，用于配合 AutoDecoder、Burp 插件等工具对 HTTP 请求/响应中的指定参数做加解密、编解码处理。

相比传统纯脚本模板，它把"配置"从改代码变成了**跑终端菜单**：算法、密钥、参数、编码链全部通过可视化菜单配置，自动持久化到 JSON 文件，重启脚本自动加载。

支持 **对称加密、非对称加密、国密、哈希、HMAC** 五大类算法，支持多参数、多层加解密、多重编码链，自动识别 JSON 与表单格式。

---

## 一、整体结构

```text
终端交互层（多语言 / 彩色菜单 / 输入提示）
        ↓
配置持久化层（crypto_tool_config.json，自动保存 / 自动加载）
        ↓
算法实现层
    ├─ 对称加密：AES / DES / 3DES / Blowfish / CAST / RC2 / RC4 / SM4
    ├─ 非对称加密：RSA / SM2
    ├─ 哈希：MD5 / SHA1 / SHA256 / SHA512 / SM3
    └─ HMAC：hmac-md5 / hmac-sha1 / hmac-sha256 / hmac-sha512
        ↓
编码工具层（none / url / base64 / base64url / hex / base32 / html / unicode）
        ↓
多层加解密引擎（multi_encrypt / multi_decrypt）
        ↓
数据体处理（JSON / 表单 / 自动识别）
        ↓
Flask 路由 /encode 和 /decode
```

---

## 二、主要特性

### 1. 交互式配置，不再改代码

启动脚本后进入彩色终端菜单，通过数字选项完成所有配置，无需编辑源码：

- **菜单 0**：一键安装 / 修复运行环境
- **菜单 1**：配置加解密算法
- **菜单 2**：数据格式设置（自动识别 / 强制 JSON / 强制表单）
- **菜单 3**：配置加解密参数（参数名 + 多层 + 编码链）
- **菜单 4**：进阶配置（表单 URL 编码、默认参数处理、调试输出、监听地址、配置文件管理）
- **菜单 5**：预览加解密流程 + 实时测试
- **菜单 6**：启动服务
- **菜单 a**：中英文切换

### 2. 配置自动持久化

所有配置自动保存到同目录下的 `crypto_tool_config.json`，下次启动自动加载。可以通过环境变量 `CRYPTO_TOOL_CONFIG` 指定配置文件路径。

### 3. 多语言

顶部菜单 `a` 可以随时切换中英文，语言选择也会保存到配置文件。

### 4. 依赖一键安装

菜单 `0` 会检测 Flask / pycryptodome / gmssl 的安装状态，支持选择 pip 镜像源（官方 / 清华 / 阿里 / 腾讯 / 不指定）一键安装。

### 5. 支持多层加解密

一个参数可以配置多层算法链，例如"内层 AES → 外层 RSA"，每层还能各自配置加密前、加密后的编码链。

### 6. Base64 兼容修复

针对 AutoDecoder 场景常见的"Base64 中的 `+` 被 URL 解析成空格"问题，`_b64d` 函数做了兼容处理：自动把空格还原成 `+`、兼容 URL-safe 变体、补齐 padding、去掉换行空白。

### 7. 实时预览与测试

菜单 5 会画出每个参数的加解密流程图，还能一键做往返测试，验证配置是否对称。

---

## 三、支持的算法全览

### 1. 对称加密

| 算法 | 配置键 | 依赖库 | 密钥长度 | 支持模式 |
|---|---|---|---|---|
| AES | `aes` | `pycryptodome` | 16 / 24 / 32 字节 | CBC / ECB / CFB / OFB / CTR / GCM |
| DES | `des` | `pycryptodome` | 8 字节 | CBC / ECB / CFB / OFB / CTR |
| 3DES | `3des` | `pycryptodome` | 16 / 24 字节 | CBC / ECB / CFB / OFB / CTR |
| Blowfish | `blowfish` | `pycryptodome` | 4 ~ 56 字节 | CBC / ECB / CFB / OFB / CTR |
| CAST | `cast` | `pycryptodome` | 5 ~ 16 字节 | CBC / ECB / CFB / OFB / CTR |
| RC2 | `rc2` | `pycryptodome` | 5 ~ 16 字节 | CBC / ECB / CFB / OFB / CTR |
| RC4 | `rc4` | `pycryptodome` | 5 ~ 256 字节 | 流加密，无 IV / 无填充 |
| SM4 | `sm4` | `gmssl` + `pycryptodome` | 16 字节 | CBC / ECB |

填充方式支持：`pkcs7` / `pkcs5` / `zero` / `iso7816` / `ansiX923` / `none`。

### 2. 非对称加密

| 算法 | 配置键 | 依赖库 | 说明 |
|---|---|---|---|
| RSA | `rsa` | `pycryptodome` | 支持 PKCS1_v1_5 / OAEP（sha1/sha256/sha384/sha512），自动分块 |
| SM2 | `sm2` | `gmssl` | 支持 C1C3C2 / C1C2C3 |

RSA 公钥/私钥支持 PEM 格式，也支持纯 Base64 内容，脚本会自动尝试解析。

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

### 5. 纯编码

选择算法为"不加密"时，只做编码链，不做加解密。

支持编码：`none` / `url` / `base64` / `base64url` / `hex` / `base32` / `html` / `unicode`。

---

## 四、依赖安装

脚本自带一键安装菜单（菜单 0），会检测以下依赖：

| 依赖 | 用途 |
|---|---|
| `flask` | Web 服务框架（启动 /encode 和 /decode 接口） |
| `pycryptodome` | AES / DES / 3DES / Blowfish / CAST / RC2 / RC4 / RSA 及各种填充 |
| `gmssl` | SM2 / SM3 / SM4 国密算法 |

也可以手动安装：

```bash
pip install flask pycryptodome gmssl
```

用不到的算法库可以不装，脚本只在调用对应算法时才检查。

---

## 五、对外接口

脚本启动后监听 `0.0.0.0:8888`（可在菜单 4 修改），提供两个接口：

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

### 接入 AutoDecoder / Burp

- 加密接口：`http://127.0.0.1:8888/encode`
- 解密接口：`http://127.0.0.1:8888/decode`

> 提示：即使服务监听的是 `0.0.0.0`，AutoDecoder 里填 `127.0.0.1` 也能连通。

---

## 六、快速上手

### 1. 启动脚本

```bash
python Template_v2.0.py
```

首次启动会进入主菜单。如果缺少依赖，先选 `0` 一键安装。

### 2. 配置算法（菜单 1）

按类别列出所有支持的算法，显示每个算法的依赖状态和配置状态。

- 选 `○ 未配置` 的算法进入详情页
- 可以修改密钥 / IV / 模式 / 填充 / 公钥 / 私钥等
- 也可以 `r` 恢复默认示例值，或 `c` 清空

### 3. 配置数据格式（菜单 2）

选择 `auto` / `json` / `form` 三种模式之一。

### 4. 配置参数（菜单 3）

- 新增参数名（如 `password` / `token` / `encryptedData`）
- 为参数添加一层或多层
- 每层可以单独设置算法、加密前编码链、加密后编码链

### 5. 进阶配置（菜单 4）

- 表单值自动 URL 编码/解码（`FORM_VALUE_URL_CODED`）
- 未配置参数统一处理（`ENABLE_DEFAULT` + `DEFAULT_LAYERS`）
- 调试输出开关
- 服务监听地址
- 配置文件管理（保存 / 加载 / 恢复出厂 / 删除）

### 6. 预览流程（菜单 5）

画出每个参数的加解密流程图，做往返测试。

### 7. 启动服务（菜单 6）

启动 Flask 服务，显示所有可访问地址，回车即可停止。

---

## 七、编码链与多层执行顺序

### 编码方式

| 编码 | 加密时 | 解密时 |
|---|---|---|
| `none` | 不变 | 不变 |
| `url` | `quote(data, safe='')` | `unquote(data)` |
| `base64` | Base64 编码 | Base64 解码 |
| `base64url` | Base64URL 编码（去掉 `=`） | Base64URL 解码 |
| `hex` | 十六进制编码 | 十六进制解码 |
| `base32` | Base32 编码 | Base32 解码 |
| `html` | HTML 转义 | HTML 反转义 |
| `unicode` | Unicode 转义 | Unicode 反转义 |

### 多层执行顺序

**加密**：层列表**自上而下**执行，即索引 0 先执行。

```text
明文
  → 层 0：编码(前) → 加密 → 编码(后)
  → 层 1：编码(前) → 加密 → 编码(后)
  → 最终密文
```

**解密**：层列表**自下而上**执行，即最后一层先解密。

```text
最终密文
  → 层 1：解码(后) → 解密 → 解码(前)
  → 层 0：解码(后) → 解密 → 解码(前)
  → 明文
```

记忆法：**层序 = 加密顺序；解密是它的逆序。**

---

## 八、数据格式识别

`process_payload` 会按 `data_mode` 自动判断：

1. **`auto`**：先尝试 JSON，失败则按表单处理。
2. **`json`**：强制按 JSON 处理，只处理顶层字符串值。
3. **`form`**：强制按表单处理，按 `&` 分割，只处理 `key` 在参数列表中的项。

JSON 数组、标量原样返回，不做处理。

---

## 九、配置文件

默认路径：脚本同目录下的 `crypto_tool_config.json`。

可以通过环境变量指定：

```bash
export CRYPTO_TOOL_CONFIG=/path/to/your_config.json
```

配置文件结构：

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

修改任何配置都会自动保存，退出前也会保存。

---

## 十、典型使用场景

### 场景 1：单参数 AES-CBC + Base64

1. 菜单 1 → 选 AES → 填 Key / IV → 选 CBC / pkcs7
2. 菜单 3 → 新增参数 `encryptedData` → 添加一层 → 选 AES → 加密后编码选 `base64`
3. 菜单 6 → 启动服务
4. AutoDecoder 加解密接口分别填 `http://127.0.0.1:8888/encode` 和 `/decode`

### 场景 2：多层 AES → RSA

菜单 3 → 添加两层：
- 第 1 层：AES，加密前/后编码都不填
- 第 2 层：RSA，加密后编码选 `base64`

### 场景 3：纯编码，不做加密

菜单 3 → 添加一层 → 算法选"不加密" → 加密后编码选 `base64,url`（解密时反向自动执行）

### 场景 4：HMAC-SHA256 签名

菜单 1 → 配置 HMAC-SHA256 的 key
菜单 3 → 新增参数 `sign` → 添加一层 → 选 HMAC-SHA256

> HMAC 是单向的，`/encode` 能生成签名，`/decode` 会抛 `NotImplementedError`，这是符合预期的。

### 场景 5：JSON 数据体

如果请求体是：

```json
{"encryptedData": "xxxxx", "username": "admin"}
```

菜单 2 选 `json` 或 `auto`，脚本会自动只处理 `encryptedData`，`username` 原样保留。

---

## 十一、哈希与 HMAC 说明

哈希和 HMAC 是**单向算法**：

| 算法 | 加密（计算摘要） | 解密 |
|---|---|---|
| MD5 / SHA-1 / SHA-256 / SHA-512 / SM3 | ✅ | ❌ 不可逆 |
| HMAC-MD5 / HMAC-SHA256 / ... | ✅ | ❌ 不可逆 |

如果在参数里配了哈希或 HMAC，`/decode` 会直接报 `NotImplementedError`。

---

## 十二、限制与注意事项

### 功能限制

1. **仅处理表单和 JSON 对象**。`/decode` 从 `request.form.get('dataBody')` 取值，客户端必须以 `application/x-www-form-urlencoded` 提交。
2. **JSON 只处理顶层字符串值**。嵌套对象不会处理。
3. **JSON 数组、标量原样返回**。
4. **HMAC-SM3 暂未实现**。

### 安全注意

1. **密钥和 IV 必须与目标系统一致**，否则会报 `Padding is incorrect` 或解密乱码。
2. **`DEBUG_PRINT` 默认开启会打印明文**，多人环境建议关闭。
3. **生产环境不要开启 debug**（脚本已默认关闭 Flask debug）。
4. **仅用于合法授权的安全测试**。

### 常见问题

**Q：解密报 `Padding is incorrect`？**

A：检查 Key / IV / Mode / Padding 是否与目标系统一致。脚本会在异常信息里给出当前密文长度、解密后长度、末字节，方便排查。

**Q：Base64 密文里 `+` 变成空格导致解密失败？**

A：脚本 `_b64d` 已经自动兼容这种情况，会把空格还原成 `+`、兼容 URL-safe 变体、补齐 padding。

**Q：配置在哪里？**

A：同目录 `crypto_tool_config.json`，或环境变量 `CRYPTO_TOOL_CONFIG` 指定的路径。

**Q：怎么清空配置？**

A：菜单 4 → 配置文件管理 → 恢复全部出厂默认，或者删除 `crypto_tool_config.json`。

---

## 十三、一句话总结

**跑起来 → 菜单里配 → 启动服务 → 接入工具。**  
不管是 AES / DES / 3DES / SM4 / RSA / SM2，还是 MD5 / SHA / SM3 / HMAC，无论单层多层、单参数多参数、JSON 表单，都可以通过菜单可视化配置，脚本会自动按规则加解密。配置自动保存，下次启动自动加载。
