# 偏移加密工具 v2.0

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)

基于 XOR 与随机置换的文本加密工具，提供 Tkinter 图形界面，支持 HMAC 完整性校验与 Base64 输出。  
**版本 2.0 引入多项安全增强**，同时保持对旧版密文的解密兼容。

---

## 功能特性（v2.0）

- 将明文按 **4 字节分组**，与 HMAC-SHA256 派生的 **32 位掩码** 逐组异或，消除长文本碰撞风险
- 使用 **256 位随机种子**（`secrets.randbits`）驱动 Fisher‑Yates 置换
- **会话盐** 机制：每个会话独立派生 `Enc_Key`、`Mac_Key`、`Seed_Key`，实现会话隔离，避免单点失效
- **AES-256-GCM** 加密会话种子，抗已知明文攻击，防止种子密钥泄露
- **强制嵌入参数**，彻底禁用 `seed=0` 的调试模式，杜绝 Two-Time Pad 攻击
- 仍支持用户自定义 PRNG（默认使用 SHA256Source）
- 输出可选 Base64 编码
- 内置错误日志查看器

## 安装

### 普通用户（直接运行）

前往 [Releases](https://github.com/zhubi404-jpg/encrypt-tool/releases) 页面下载 `XorShuffleCrypto-V2.0.exe`，双击即可运行，无需安装 Python。

### Python 开发者（作为库集成）

```bash
pip install XorShuffleCrypto-V2.0
```

安装后即可在 Python 代码中导入使用：

```python
from core import encrypt_with_offset, decrypt_with_offset

packet = encrypt_with_offset("hello", "", "mykey", "utf-8")
plain = decrypt_with_offset(packet, "", "mykey", "utf-8")
```

### 从源码安装

```bash
git clone https://github.com/zhubi404-jpg/XorShuffleCrypto-V2.0.git
cd XorShuffleCrypto-V2.0
pip install -e .
```

> **依赖**：版本 2.0 需要 `cryptography` 库，安装时会自动安装。

## 使用方法

**环境要求**：Python 3.8+（需安装 `cryptography`）

**启动**：
```bash
python gui.py
```

**加密**：
1. 在“输入文本”区域输入明文
2. 偏移序列留空为自动随机；填 `0` 为顺序（不置换）；填逗号分隔的数字为手动指定
3. 选择随机模式算法（仅偏移框留空时生效）
4. 输入或生成密钥（推荐点击“生成随机密钥”）
5. 点击“加密”，结果输出至下方区域

**解密**：
1. 将 Base64 密文粘贴至“输入文本”区域
2. 输入相同的密钥
3. 点击“解密”，明文恢复至结果区域

> 解密时偏移序列、编码等参数自动从密文头部读取，无需手动设置。工具会自动识别协议版本（v1 或 v2）。

## 安全说明（v2.0）

- **会话种子**：使用 AES-256-GCM 加密存储，且每个会话独立派生三个子密钥（通过会话盐），即使攻击者获得一个会话的种子也无法反推其他会话的密钥。
- **强随机密钥**：建议使用“生成随机密钥”功能（32 字节 URL-safe 随机串），提供 256 位熵。
- **强制嵌入参数**：`embed_params` 已强制启用，种子永远不会固定为 0，彻底消除 Two-Time Pad 风险。
- **32 位掩码**：替代旧版 16 位截断，消除长文本掩码碰撞问题。
- **兼容旧版**：可解密 v1 格式密文，但新加密仅产生 v2 格式。
- 本工具仍建议用户评估自身安全需求，不用于核心机密数据。

## 数据格式（协议版本 2）

加密后的原始字节包结构（Base64 编码前）：

```
[HEADER_V2 (96B)] [CIPHER (4*N B)] [TAG (16B)]
```

**HEADER_V2**（大端序）：
- 字节 0：版本号（0x02）
- 字节 1–12：AES-GCM 随机数（Nonce）
- 字节 13–44：AES-GCM 加密后的会话种子（32 字节密文）
- 字节 45–60：AES-GCM 认证标签（16 字节）
- 字节 61–92：会话盐（Session Salt，32 字节）
- 字节 93：字符编码 ID
- 字节 94：标志位（低 2 位表示偏移模式）
- 字节 95：PRNG 类型 ID

**CIPHER**：4×N 字节，大端序 32 位整数序列（每个分组 4 字节）。

**TAG**：HMAC-SHA256(HEADER + CIPHER) 前 16 字节。

> 旧版（v1）格式仍可被解密，但新版加密不再产生 v1 格式。

## 许可证

MIT License