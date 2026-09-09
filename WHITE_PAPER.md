# 偏移加密工具 v1.0 技术白皮书

版本：1.0  
对应源码：encrypt_tool-v1.0.py / core.py + gui.py

---

## 一、总体架构与数据格式

加密后的原始字节包结构：

```
[HEADER (36B)] [CIPHER (2*N B)] [TAG (16B)]
```

**HEADER 字段**（大端序）：
- 字节 0：协议版本，固定为 0x01
- 字节 1–32：经 Seed_Key XOR 加密的会话种子
- 字节 33：字符编码 ID
- 字节 34：标志位，低 2 位表示偏移模式（0 手动 / 1 顺序 / 2 随机）
- 字节 35：PRNG 类型 ID（0–3）

**CIPHER**：每 2 字节为一组（16 位无符号整数），大端序存储。组数 N 由明文长度加 4 字节长度前缀决定，不足偶数时补零。

**TAG**：HMAC-SHA256(Mac_Key, HEADER + CIPHER) 前 16 字节。

## 二、密钥派生

用户密钥（UTF-8 字节）经 HKDF-SHA256 派生为三个独立密钥：

- 提取：`PRK = HMAC-SHA256(salt=b"EncryptToolV4-Salt", ikm=user_key)`
- 扩展：
  - `Enc_Key  = HKDF-Expand(PRK, "EncKey", 32)`  — XOR 掩码生成
  - `Mac_Key  = HKDF-Expand(PRK, "MacKey", 32)`  — HMAC 认证
  - `Seed_Key = HKDF-Expand(PRK, "SeedKey", 32)` — 种子加密

HMAC-SHA256 的抗原像性确保即使攻击者获取某会话的密钥流片段，也无法反推派生密钥。

## 三、密钥流生成

第 i 组的 XOR 掩码：

```
K[i] = HMAC-SHA256(Enc_Key, Seed || i) 的前 2 字节（大端整数）
```

- `Seed`：会话唯一种子（256 位），每次加密重新生成，经 Seed_Key 加密后存入头部
- `i`：分组原始索引（8 字节大端整数）

会话隔离性：同一 Enc_Key 下，Seed 不同即产生完全不同的 K[i]，避免 Two-Time Pad 攻击。

## 四、加密流程

1. 明文按指定编码转为字节序列，开头附加 4 字节大端长度前缀
2. 按 2 字节分组，得到 N 个 16 位整数 P[i]（小端读取）
3. 计算 K[i] = HMAC-SHA256(Enc_Key, Seed || i)[:2]，得到中间值 X[i] = P[i] XOR K[i]
4. 使用同一 Seed 和指定 PRNG，通过 Fisher‑Yates 算法生成置换 π
5. 将 X[i] 放入目标位置 π(i)：C[π(i)] = X[i]
6. CIPHER 区按位置 0..N-1 顺序输出

置换 π 与密钥流 K[i] 均依赖于 Seed，而 Seed 在头部加密存储，形成强耦合。

## 五、安全性归约

已知明文攻击场景下，攻击者已知密文 C 和明文 P，可计算：

```
D[j] = C[j] XOR P[π^{-1}(j)]
```

但 π 未知且由 Seed 决定，Seed 被 Seed_Key 加密存储。

暴力破解需同时猜测 Enc_Key（256 位）和 Seed（256 位），联合搜索空间为 2^512。置换 π 是 Seed 的函数，不作为独立自由度参与枚举。

在未取得用户密钥的前提下，有效破解复杂度为 2^512 量级的对称密钥穷举，当前计算能力下不可行。

## 六、16 位截断的安全性

HMAC-SHA256 完整输出为 256 位，取前 2 字节（16 位）作为 XOR 掩码：

1. 输入熵充足：Enc_Key（256 位）+ Seed（256 位）+ 索引（64 位）远超 16 位输出空间
2. HMAC-SHA256 为伪随机函数，截断后仍保持均匀分布
3. 每组分组的掩码独立依赖于索引 i，且会话 Seed 每次刷新，无法通过频率分析反推
4. 攻击者无法主动构造输入，生日攻击不适用

该截断操作不降低系统有效安全强度。

## 七、完整性认证

加密完成后计算认证标签：

```
Tag = HMAC-SHA256(Mac_Key, HEADER || CIPHER) 的前 16 字节
```

解密时重新计算 Tag，使用 hmac.compare_digest 进行常量时间比较，防止时序侧信道攻击。

认证范围覆盖头部与密文，采用 Encrypt-then-MAC 顺序，符合密码学最佳实践。

## 八、PRNG 类型说明

生成置换 π 的 PRNG 可由用户选择：

- **SHA256Source**：基于 SHA-256 计数器，输出不可预测，达到密码学安全级别
- **PCG / MersenneTwister / LaggedFibonacci**：统计特性优良但非加密安全。但由于 Seed 本身由 CSPRNG 生成且加密存储，在未获取 Seed 的前提下，这些 PRNG 的可预测性无法被利用

高安全需求场景推荐使用 SHA256Source。

## 九、注意事项

1. **必须保持“嵌入参数”启用**  
   禁用后 Seed 固定为 0，会话随机性丧失，同一密钥加密多次将产生可复用的密钥流，存在 Two-Time Pad 风险。该模式仅供协议兼容性测试。

2. **用户密钥强度**  
   建议使用“生成随机密钥”功能产生 32 字节 URL-safe 随机串，避免短密码或常见口令。

3. **密钥管理**  
   本工具不保存任何密钥，用户需自行保管。

4. **协议兼容性**  
   版本 1 采用种子加密，无法与未实现该功能的版本互通。

### 十、PRNG 扩展接口规范

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