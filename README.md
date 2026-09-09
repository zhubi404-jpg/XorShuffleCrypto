# 偏移加密工具 v1.0

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)

基于 XOR 与随机置换的文本加密工具，提供 Tkinter 图形界面，支持 HMAC 完整性校验与 Base64 输出。

---

## 功能特性

- 将明文按 2 字节分组，与 HMAC-SHA256 派生的密钥流逐组异或
- 使用 256 位随机种子（secrets.randbits）驱动 Fisher‑Yates 置换
- 通过 HKDF-SHA256 从用户密钥派生三个独立密钥（Enc_Key、Mac_Key、Seed_Key）
- 支持三种偏移模式：自动随机 / 顺序 / 手动指定
- 输出可选 Base64 编码
- 内置错误日志查看器

## 安装

### 普通用户（直接运行）

前往 [Releases](https://github.com/zhubi404-jpg/XorShuffleCrypto/releases) 页面下载 `EncryptTool.exe`，双击即可运行，无需安装 Python。

### Python 开发者（作为库集成）

```bash
pip install encrypt-tool-zhubi404-jpg
```

安装后即可在 Python 代码中导入使用：

```python
from core import encrypt_with_offset, decrypt_with_offset

packet = encrypt_with_offset("hello", "", "mykey", "utf-8")
plain = decrypt_with_offset(packet, "", "mykey", "utf-8")
```

### 从源码安装

```bash
git clone https://github.com/zhubi404-jpg/XorShuffleCrypto.git
cd encrypt-tool
pip install -e .
```


## 使用方法

**环境要求**：Python 3.6+（仅依赖标准库）

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

> 解密时偏移序列、编码等参数自动从密文头部读取，无需手动设置。

## 安全说明

- 会话种子（256 位）经 Seed_Key XOR 加密后存入头部，攻击者无法从头部直接读取种子
- 建议使用“生成随机密钥”功能（32 字节 URL‑safe 随机串）
- 必须保持“嵌入参数”为启用状态。禁用后种子固定为 0，将导致同一密钥加密不同数据时密钥流可被复用（Two-Time Pad 风险）
- 本工具未经专业密码学审计，请勿用于核心机密数据

## 数据格式（协议版本 1）

加密后的原始字节包结构（Base64 编码前）：

```
[HEADER (36B)] [CIPHER (2*N B)] [TAG (16B)]
```

**HEADER**：
- 字节 0：版本号（0x01）
- 字节 1–32：经 Seed_Key XOR 加密的会话种子
- 字节 33：字符编码 ID
- 字节 34：标志位（低 2 位表示偏移模式）
- 字节 35：PRNG 类型 ID

**CIPHER**：2×N 字节，大端序 16 位整数序列

**TAG**：HMAC-SHA256(HEADER + CIPHER) 前 16 字节

## 许可证

MIT License
