# 偏移加密工具 v2.0 技术白皮书

版本：2.0  
对应源码：core.py + gui.py

---

## 一、总体架构与数据格式

加密后的原始字节包结构：

```
[HEADER_V2 (96B)] [CIPHER (4*N B)] [TAG (16B)]
```

**HEADER_V2 字段**（大端序）：
- 字节 0：协议版本，固定为 0x02
- 字节 1–12：AES-GCM 随机数（Nonce）
- 字节 13–44：经 AES-256-GCM 加密的会话种子（32 字节密文）
- 字节 45–60：AES-GCM 认证标签（16 字节）
- 字节 61–92：会话盐（Session Salt，32 字节随机数）
- 字节 93：字符编码 ID
- 字节 94：标志位，低 2 位表示偏移模式（0 手动 / 1 顺序 / 2 随机）
- 字节 95：PRNG 类型 ID（0–3）

**CIPHER**：每 4 字节为一组（32 位无符号整数），大端序存储。组数 N 由明文长度加 4 字节长度前缀决定，不足 4 的倍数时补零。

**TAG**：HMAC-SHA256(Mac_Key, HEADER + CIPHER) 前 16 字节。

## 二、密钥派生（v2.0）

用户密钥（UTF-8 字节）经 HKDF-SHA256 派生为 **主密钥** `Master_Key`：

```
Master_Key = HKDF(PRK, "MasterKey", 32)
PRK = HMAC-SHA256(salt=b"EncryptToolV4-Salt", ikm=user_key)
```

每次加密生成 32 字节随机 `Session_Salt`，与 `Master_Key` 共同派生会话专属的三个子密钥：

```
PRK_session = HMAC-SHA256(salt=Session_Salt, ikm=Master_Key)
Enc_Key   = HKDF-Expand(PRK_session, "EncKey", 32)   — XOR 掩码生成
Mac_Key   = HKDF-Expand(PRK_session, "MacKey", 32)   — HMAC 认证
Seed_Key  = HKDF-Expand(PRK_session, "SeedKey", 32)  — 种子加密（AES-256-GCM）
```

会话盐确保每个会话的子密钥独立，即使 `Master_Key` 泄露，攻击者仍需猜测每个会话的盐（256 位），实现会话隔离。

## 三、密钥流生成（v2.0）

第 i 组的 XOR 掩码：

```
K[i] = HMAC-SHA256(Enc_Key, Seed || i) 的前 4 字节（大端整数）
```

- `Seed`：会话唯一种子（256 位），每次加密重新生成，经 AES-256-GCM 加密后存入头部
- `i`：分组原始索引（8 字节大端整数）

相比旧版 16 位掩码，32 位掩码消除了长文本的碰撞风险。

## 四、加密流程（v2.0）

1. 明文按指定编码转为字节序列，开头附加 4 字节大端长度前缀
2. 按 4 字节分组，得到 N 个 32 位整数 P[i]（大端读取）
3. 计算 K[i] = HMAC-SHA256(Enc_Key, Seed || i)[:4]，得到中间值 X[i] = P[i] XOR K[i]
4. 使用同一 Seed 和指定 PRNG，通过 Fisher‑Yates 算法生成置换 π
5. 将 X[i] 放入目标位置 π(i)：C[π(i)] = X[i]
6. CIPHER 区按位置 0..N-1 顺序输出

置换 π 与密钥流 K[i] 均依赖于 Seed，而 Seed 经 AES-256-GCM 加密存储，形成强耦合。

## 五、安全性归约（v2.0）

已知明文攻击下，攻击者已知密文 C 和明文 P，可计算 D[j] = C[j] XOR P[π^{-1}(j)]，但 π 未知且由 Seed 决定。

攻击者需同时猜测 `Master_Key`（256 位）、`Session_Salt`（256 位）和 `Seed`（256 位），联合搜索空间为 2^768。即使 `Master_Key` 被破解，每个会话仍需独立猜测盐和种子（2^512）。

在未取得用户密钥的前提下，有效破解复杂度不低于 2^256（若用户密钥为 256 位随机），实际安全强度由用户密钥熵决定。

## 六、32 位掩码的安全性

HMAC-SHA256 完整输出为 256 位，取前 4 字节（32 位）作为 XOR 掩码。输入熵充足（Enc_Key 256 位 + Seed 256 位 + 索引 64 位），输出均匀分布，生日碰撞概率极低（N < 2^16 时几乎为零，远大于普通文本长度）。

## 七、完整性认证

加密完成后计算认证标签：

```
Tag = HMAC-SHA256(Mac_Key, HEADER || CIPHER) 的前 16 字节
```

解密时重新计算 Tag，使用 `hmac.compare_digest` 进行常量时间比较，防止时序侧信道攻击。认证范围覆盖头部与密文，采用 Encrypt-then-MAC 顺序。

## 八、PRNG 类型说明

生成置换 π 的 PRNG 可由用户选择（通过 GUI 下拉菜单）：

- **SHA256Source**（默认）：基于 SHA-256 计数器，密码学安全。
- **PCG / MersenneTwister / LaggedFibonacci**：统计特性优良但非加密安全。由于 Seed 本身由 CSPRNG 生成且经 AES-GCM 加密，在未获取 Seed 的前提下，这些 PRNG 的可预测性无法被利用。

高安全需求场景推荐使用 SHA256Source。

## 九、注意事项

1. **强制嵌入参数**  
   版本 2 已强制启用“嵌入参数”，`seed` 永不固定为 0，彻底杜绝 Two-Time Pad 攻击。

2. **用户密钥强度**  
   建议使用“生成随机密钥”功能产生 32 字节 URL-safe 随机串（熵约 256 位），避免短密码或常见口令。

3. **密钥管理**  
   本工具不保存任何密钥，用户需自行保管。

4. **协议兼容性**  
   版本 2 可解密旧版（v1）密文，但加密仅产生 v2 格式。旧版工具无法解密 v2 密文。

5. **依赖**  
   版本 2 需要 `cryptography` 库（提供 AES-GCM 实现），安装时自动解决。

## 十、PRNG 扩展接口规范

本工具允许用户注册自定义伪随机数生成器，用于生成置换排列。自定义 PRNG 类必须满足以下接口规范。

**接口定义**：

```python
class CustomPRNG:
    def __init__(self, seed: int):
        """使用 256 位整数种子初始化生成器。"""
        pass

    def uniform(self, low: int, high: int) -> float:
        """返回 [low, high) 区间内的浮点数，要求分布尽可能均匀。"""
        pass
```

**安全要求**：

1. **种子敏感性**  
   构造函数的 `seed` 参数必须完全决定生成器的初始状态。不同的种子输入应产生统计上独立的输出序列。

2. **输出范围**  
   `uniform(low, high)` 的返回值必须满足 `low <= value < high`。对于 `low` 和 `high` 均为整数的常见调用场景，返回值应覆盖整个区间，不应系统性偏向任一子区间。

3. **周期长度**  
   对于非加密类 PRNG，建议周期至少为 2^64，以避免在长明文（N > 2^32）场景下出现明显的排列周期性。

4. **可复现性**  
   在相同种子输入下，生成器必须产生完全相同的输出序列。这是协议一致性的基本要求——加密方和解密方必须生成相同的置换。

**不保证声明**：

- 本工具不验证自定义 PRNG 的统计质量或加密强度
- 使用非加密安全的自定义 PRNG 可能导致置换可预测，从而降低整体安全性
- 用户自行承担注册和使用自定义 PRNG 的风险

**注册示例**：

```python
from core import register_prng

class MyPRNG:
    def __init__(self, seed: int):
        self.state = seed
    def uniform(self, low: int, high: int) -> float:
        self.state = (self.state * 1103515245 + 12345) & 0xFFFFFFFF
        return low + (self.state / 0x100000000) * (high - low)

register_prng("MyPRNG", MyPRNG)
```

注册后，调用 `generate_offsets_from_seed(seed, length, rng_id="MyPRNG")` 即可使用。
---

*本工具未经专业密码学审计，使用者应自行评估安全风险。*