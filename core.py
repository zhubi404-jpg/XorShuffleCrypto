#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
core.py — 偏移加密引擎
协议版本：1
包结构：
  [HEADER (36B)] [CIPHER (2*N B)] [TAG (16B)]
头部格式：version(1) + encrypted_seed(32) + enc_id(1) + flags(1) + rng_id(1)
  - encrypted_seed: 由 Seed_Key XOR 加密的 256 位种子（种子本身由 CSPRNG 生成）
  - enc_id: 字符编码ID（见 ENCODING_ID）
  - flags: 低2位为偏移模式（0手动,1顺序,2随机）
  - rng_id: 伪随机数生成器类型（0~3）

加密公式：C[π(i)] = P[i] ⊕ K[i]，其中 K[i] = HMAC-SHA256(Enc_Key, seed || i) 前2字节
            π 由 seed 和 rng_id 通过 Fisher-Yates 置换生成

安全特性：
  - HKDF-SHA256 派生三个独立密钥：Enc_Key（XOR掩码）、Mac_Key（HMAC认证）、Seed_Key（种子加密）
  - 头部种子加密存储，攻击者无法仅凭密文获取种子及置换信息
  - Encrypt-then-MAC 模式，HMAC 覆盖头部和密文
  - 支持多种 PRNG（MersenneTwister, PCG, LaggedFibonacci, SHA256Source）
  - Base64 输出，纯ASCII，兼容传输
"""

import random
import hashlib
import hmac
import os
import time
import base64
import secrets
from typing import Optional, Callable, List, Tuple, Dict, Type, Union

# =================== 常量与配置 ===================
ENCODING_ID = {
    "ascii": 0,
    "utf-8": 1,
    "latin-1": 2,
    "gbk": 3,
    "gb2312": 4,
    "big5": 5,
    "shift-jis": 6,
    "base64": 7,
}
ID_ENCODING = {v: k for k, v in ENCODING_ID.items()}

OFFSET_MODE_MANUAL = 0
OFFSET_MODE_SEQUENTIAL = 1
OFFSET_MODE_RANDOM = 2

HEADER_VERSION = 1          # 协议版本 v1.0
HEADER_BYTES = 36
TAG_BYTES = 16
KEY_BYTES = 32

# 内置 PRNG 名称 -> ID 映射（向后兼容）
RNG_ID = {"MersenneTwister": 0, "PCG": 1, "LaggedFibonacci": 2, "SHA256Source": 3}
ID_RNG = {v: k for k, v in RNG_ID.items()}

_BE = 'big'
_LE = 'little'

def _u16_to_bytes_le(v: int) -> bytes:
    return v.to_bytes(2, _LE)

def _bytes_to_u16_le(b: bytes) -> int:
    return int.from_bytes(b, _LE)

def _u32_to_bytes_be(v: int) -> bytes:
    return v.to_bytes(4, _BE)

def _bytes_to_u32_be(b: bytes) -> int:
    return int.from_bytes(b, _BE)


# ================== 伪随机数生成器 ====================
def _normalize_seed(seed: int) -> bytes:
    """将整数种子压缩为32字节的确定性种子（SHA-256）"""
    seed_bytes = seed.to_bytes(32, _BE)
    return hashlib.sha256(seed_bytes).digest()

class MersenneTwister:
    """基于 Mersenne Twister 的 PRNG"""
    def __init__(self, seed: int):
        norm = _normalize_seed(seed)
        self.rng = random.Random(norm)
    def uniform(self, low: int, high: int) -> float:
        return self.rng.uniform(low, high)

class PCG:
    """PCG 随机数生成器"""
    def __init__(self, seed: int):
        norm = _normalize_seed(seed)
        self.state = int.from_bytes(norm[:8], _BE)
        self.inc = (self.state << 1) | 1
    def uniform(self, low: int, high: int) -> float:
        old = self.state
        self.state = old * 6364136223846793005 + self.inc
        word = ((old >> 18) ^ old) >> 27
        rot = old >> 59
        value = (word >> rot) | (word << ((-rot) & 31))
        rand_float = (value & 0xFFFFFFFF) / 0x100000000
        return low + rand_float * (high - low)

class LaggedFibonacci:
    """滞后斐波那契生成器"""
    def __init__(self, seed: int):
        norm = _normalize_seed(seed)
        self.buffer = []
        s = int.from_bytes(norm[:4], _BE)
        for _ in range(17):
            s = (s * 1103515245 + 12345) & 0xFFFFFFFF
            self.buffer.append(s)
        self.index = 0
    def uniform(self, low: int, high: int) -> float:
        a = self.buffer[self.index]
        b = self.buffer[(self.index + 5) % 17]
        val = (a + b) & 0xFFFFFFFF
        self.buffer[self.index] = val
        self.index = (self.index + 1) % 17
        rand_float = val / 0x100000000
        return low + rand_float * (high - low)

class SHA256Source:
    """基于 SHA-256 计数器的加密安全 PRNG"""
    def __init__(self, seed: int):
        self.seed = _normalize_seed(seed)
        self.counter = 0
    def uniform(self, low: int, high: int) -> float:
        self.counter += 1
        data = self.seed + self.counter.to_bytes(8, _BE)
        digest = hashlib.sha256(data).digest()
        num = int.from_bytes(digest[:8], _BE)
        rand_float = num / 0x10000000000000000
        return low + rand_float * (high - low)


# ================== PRNG 注册表（扩展） ====================
_PRNGS: Dict[str, Type] = {}

def register_prng(name: str, rng_class: Type) -> None:
    """
    注册自定义 PRNG 类。

    要求：
      - 类必须实现 __init__(self, seed: int)
      - 类必须实现 uniform(self, low: int, high: int) -> float
      - 返回值满足 low <= value < high

    示例：
        from core import register_prng

        class MyPRNG:
            def __init__(self, seed: int):
                self.state = seed
            def uniform(self, low: int, high: int) -> float:
                self.state = (self.state * 1103515245 + 12345) & 0xFFFFFFFF
                return low + (self.state / 0x100000000) * (high - low)

        register_prng("MyPRNG", MyPRNG)
    """
    _PRNGS[name] = rng_class

def get_prng_class(name: str) -> Type:
    """根据名称获取 PRNG 类，不存在则抛出 ValueError。"""
    cls = _PRNGS.get(name)
    if cls is None:
        available = ", ".join(_PRNGS.keys())
        raise ValueError(f"未知 PRNG: {name}，可用: {available}")
    return cls

def list_prngs() -> List[str]:
    """列出所有已注册的 PRNG 名称。"""
    return list(_PRNGS.keys())

# 自动注册内置 PRNG
register_prng("MersenneTwister", MersenneTwister)
register_prng("PCG", PCG)
register_prng("LaggedFibonacci", LaggedFibonacci)
register_prng("SHA256Source", SHA256Source)


# ==================== 偏移序列生成 ====================
def generate_offsets_from_seed(
    seed: int,
    length: int,
    rng_id: Union[int, str] = 0
) -> List[int]:
    """
    使用给定种子和 PRNG 类型生成 0..length-1 的随机排列（Fisher-Yates）。

    参数：
        seed: 256 位种子整数
        length: 排列长度
        rng_id: PRNG 标识，可以是整数 ID（0~3，向后兼容）或字符串名称

    返回：
        随机排列列表
    """
    # 解析 rng_id：支持整数 ID 或字符串名称
    if isinstance(rng_id, int):
        name = ID_RNG.get(rng_id)
        if name is None:
            raise ValueError(f"无效 rng_id: {rng_id}")
    else:
        name = rng_id

    rng_class = get_prng_class(name)
    rng = rng_class(seed)

    arr = list(range(length))
    for i in range(length - 1, 0, -1):
        j = int(rng.uniform(0, i + 1))
        arr[i], arr[j] = arr[j], arr[i]
    return arr

def parse_offsets(offset_str: str, length_hint: Optional[int] = None) -> List[int]:
    """解析用户输入的逗号分隔偏移序列"""
    raw = offset_str.strip()
    if not raw:
        raise ValueError("偏移序列不能为空")
    parts = [p.strip() for p in raw.split(',') if p.strip()]
    try:
        offsets = [int(p) for p in parts]
    except ValueError:
        raise ValueError("偏移必须为整数")
    if not offsets:
        raise ValueError("无有效偏移")
    if len(offsets) == 1 and length_hint is not None:
        start = offsets[0]
        offsets = list(range(start, start + length_hint))
    return offsets


# =================== HKDF-SHA256 ===================
def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    if salt is None:
        salt = b'\x00' * 32
    return hmac.new(salt, ikm, hashlib.sha256).digest()

def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    if length > 255 * hashlib.sha256().digest_size:
        raise ValueError("请求长度过大")
    t = b''
    okm = b''
    for i in range(1, (length // hashlib.sha256().digest_size) + 2):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]

def hkdf(ikm: bytes, salt: Optional[bytes] = None, info: bytes = b'', length: int = 32) -> bytes:
    prk = hkdf_extract(salt, ikm)
    return hkdf_expand(prk, info, length)


# ================== 密钥流 ===================
def expand_key_stream(enc_key: bytes, seed: int, index: int) -> int:
    """
    生成 16 位密钥流块
    K[i] = HMAC-SHA256(Enc_Key, seed || i) 前 2 字节
    """
    seed_bytes = seed.to_bytes(32, _BE)
    idx_bytes = index.to_bytes(8, _BE)
    nonce = seed_bytes + idx_bytes
    digest = hmac.new(enc_key, nonce, hashlib.sha256).digest()
    return int.from_bytes(digest[:2], _BE)


# ================== 头部打包/解包（种子加密） ===================
def pack_header(version: int, seed: int, enc_id: int, offset_mode: int, rng_id: int,
                seed_key: bytes) -> bytes:
    """
    打包头部，使用 Seed_Key 对种子进行 XOR 加密后存储
    """
    if version != HEADER_VERSION:
        raise ValueError(f"不支持的版本: {version}")
    seed_bytes = seed.to_bytes(32, _BE)
    encrypted_seed = bytes(a ^ b for a, b in zip(seed_bytes, seed_key))
    flags = (offset_mode & 0x03)
    header = bytes([version]) + encrypted_seed + bytes([enc_id, flags, rng_id & 0xFF])
    if len(header) != HEADER_BYTES:
        raise RuntimeError("头部长度错误")
    return header

def unpack_header(data: bytes, seed_key: bytes) -> Tuple[int, int, int, int]:
    """
    解包头部，用 Seed_Key 解密种子
    """
    if len(data) != HEADER_BYTES:
        raise ValueError(f"头部长度必须为 {HEADER_BYTES}")
    version = data[0]
    if version != HEADER_VERSION:
        raise ValueError(f"不支持的版本: {version}，本工具仅支持 v1.0")
    encrypted_seed = data[1:33]
    seed_bytes = bytes(a ^ b for a, b in zip(encrypted_seed, seed_key))
    seed = int.from_bytes(seed_bytes, _BE)
    enc_id = data[33]
    flags = data[34]
    rng_id = data[35]
    offset_mode = flags & 0x03
    return seed, enc_id, offset_mode, rng_id


# ================== HMAC =================
def compute_tag(mac_key: bytes, auth_data: bytes) -> bytes:
    return hmac.new(mac_key, auth_data, hashlib.sha256).digest()[:TAG_BYTES]


# =================== 核心加密引擎 ====================
def derive_session_keys(user_key: bytes) -> Tuple[bytes, bytes, bytes]:
    """
    从用户密钥派生三个独立密钥：
      - Enc_Key : XOR 掩码生成
      - Mac_Key : HMAC 认证
      - Seed_Key: 种子加密
    """
    salt = b"EncryptToolV4-Salt"
    master = hkdf(user_key, salt, b"MasterKey", KEY_BYTES)
    enc_key = hkdf(master, b"", b"EncKey", KEY_BYTES)
    mac_key = hkdf(master, b"", b"MacKey", KEY_BYTES)
    seed_key = hkdf(master, b"", b"SeedKey", KEY_BYTES)
    return enc_key, mac_key, seed_key

def encrypt_with_offset(plain: str, offset_str: str, key_str: str, input_encoding: str,
                        embed_params: bool = True, seed: Optional[int] = None,
                        rng_id: int = 0, error_log: Optional[Callable] = None) -> bytes:
    """
    加密主函数，返回完整数据包（字节）
    error_log: 用于记录错误信息的回调函数 (message)
    """
    if input_encoding == "base64":
        raise ValueError("加密时不支持将输入编码设为 base64")

    user_key = key_str.encode('utf-8')
    enc_key, mac_key, seed_key = derive_session_keys(user_key)

    # 编码并添加长度前缀（大端）
    plain_bytes = plain.encode(input_encoding)
    data = _u32_to_bytes_be(len(plain_bytes)) + plain_bytes
    if len(data) % 2 == 1:
        data += b'\x00'
    num_groups = len(data) // 2

    # 确定偏移序列
    if embed_params:
        raw = offset_str.strip()
        if raw == "0":
            offset_mode = OFFSET_MODE_SEQUENTIAL
            offsets = list(range(num_groups))
            if seed is None:
                seed = secrets.randbits(256)
        elif raw == "":
            offset_mode = OFFSET_MODE_RANDOM
            if seed is None:
                seed = secrets.randbits(256)
            offsets = generate_offsets_from_seed(seed, num_groups, rng_id=rng_id)
        else:
            offset_mode = OFFSET_MODE_MANUAL
            offsets = parse_offsets(raw, length_hint=num_groups)
            for off in offsets:
                if off < 0 or off >= num_groups:
                    raise ValueError(f"手动偏移 {off} 超出组范围")
            if seed is None:
                seed = secrets.randbits(256)
    else:
        if not offset_str.strip():
            raise ValueError("未启用嵌入参数时，必须提供偏移序列")
        offset_mode = OFFSET_MODE_MANUAL
        offsets = parse_offsets(offset_str, length_hint=num_groups)
        for off in offsets:
            if off < 0 or off >= num_groups:
                raise ValueError(f"手动偏移 {off} 超出组范围")
        seed = 0

    if len(offsets) != num_groups or set(offsets) != set(range(num_groups)):
        raise ValueError("偏移序列无效")

    # XOR 加密
    xor_groups = []
    for i in range(num_groups):
        base = i * 2
        val = data[base] | (data[base + 1] << 8)
        key_ext = expand_key_stream(enc_key, seed, i)
        val ^= key_ext
        xor_groups.append(val)

    # 偏移置换
    cipher_ints = [0] * num_groups
    for i in range(num_groups):
        cipher_ints[offsets[i]] = xor_groups[i]

    # 转为字节流（大端）
    cipher_bytes = bytearray()
    for v in cipher_ints:
        cipher_bytes += v.to_bytes(2, _BE)

    # 头部（嵌入模式）
    if embed_params:
        enc_id = ENCODING_ID.get(input_encoding, 1)
        header = pack_header(HEADER_VERSION, seed, enc_id, offset_mode, rng_id, seed_key)
    else:
        header = b''

    # 计算 HMAC 标签
    auth_data = header + cipher_bytes
    tag = compute_tag(mac_key, auth_data)

    packet = header + cipher_bytes + tag
    return packet


def decrypt_with_offset(packet: bytes, offset_str: str, key_str: str, input_encoding: str,
                        embed_params: bool = True, error_log: Optional[Callable] = None) -> str:
    """
    解密主函数，返回明文字符串
    error_log: 用于记录错误信息的回调函数 (message)
    """
    if not packet:
        raise ValueError("包为空")

    user_key = key_str.encode('utf-8')
    enc_key, mac_key, seed_key = derive_session_keys(user_key)

    if embed_params:
        if len(packet) < HEADER_BYTES + TAG_BYTES + 1:
            raise ValueError("包过短")
        header = packet[:HEADER_BYTES]
        cipher_bytes = packet[HEADER_BYTES:-TAG_BYTES]
        tag = packet[-TAG_BYTES:]

        # 验证 HMAC
        auth_data = header + cipher_bytes
        expected_tag = compute_tag(mac_key, auth_data)
        if not hmac.compare_digest(expected_tag, tag):
            raise ValueError("认证失败：密钥错误或数据被篡改")

        # 解析头部（解密种子）
        seed, enc_id, offset_mode, rng_id = unpack_header(header, seed_key)
        if enc_id not in ID_ENCODING:
            raise ValueError("无效的输入编码ID")
        input_encoding = ID_ENCODING[enc_id]
        num_groups = len(cipher_bytes) // 2
        if len(cipher_bytes) % 2 != 0:
            raise ValueError("密文长度不是偶数")
    else:
        # 非嵌入模式
        if len(packet) < TAG_BYTES + 1:
            raise ValueError("包过短")
        cipher_bytes = packet[:-TAG_BYTES]
        tag = packet[-TAG_BYTES:]
        auth_data = cipher_bytes
        expected_tag = compute_tag(mac_key, auth_data)
        if not hmac.compare_digest(expected_tag, tag):
            raise ValueError("认证失败：密文被篡改")

        if not offset_str.strip():
            raise ValueError("非嵌入模式需要偏移字符串")
        offset_mode = OFFSET_MODE_MANUAL
        num_groups = len(cipher_bytes) // 2
        if len(cipher_bytes) % 2 != 0:
            raise ValueError("密文长度不是偶数")
        seed = 0
        rng_id = 0

    # 获取偏移序列
    if offset_mode == OFFSET_MODE_MANUAL:
        offsets = parse_offsets(offset_str, length_hint=num_groups)
    elif offset_mode == OFFSET_MODE_SEQUENTIAL:
        offsets = list(range(num_groups))
    elif offset_mode == OFFSET_MODE_RANDOM:
        offsets = generate_offsets_from_seed(seed, num_groups, rng_id=rng_id)
    else:
        raise ValueError(f"未知 offset_mode: {offset_mode}")

    if len(offsets) != num_groups or set(offsets) != set(range(num_groups)):
        raise ValueError("偏移序列无效")

    # 读回密文整数（大端）
    cipher_ints = [int.from_bytes(cipher_bytes[i:i+2], _BE) for i in range(0, len(cipher_bytes), 2)]

    # 逆置换
    recovered_ints = [0] * num_groups
    for i in range(num_groups):
        recovered_ints[i] = cipher_ints[offsets[i]]

    # XOR 解密
    raw_bytes = bytearray(num_groups * 2)
    for i, val in enumerate(recovered_ints):
        key_ext = expand_key_stream(enc_key, seed, i)
        val ^= key_ext
        raw_bytes[2*i] = val & 0xFF
        raw_bytes[2*i+1] = (val >> 8) & 0xFF

    # 长度前缀
    if len(raw_bytes) < 4:
        raise ValueError("解密后数据过短")
    plain_len = _bytes_to_u32_be(bytes(raw_bytes[:4]))
    if plain_len > len(raw_bytes) - 4:
        raise ValueError("长度前缀错误")
    plain_bytes = bytes(raw_bytes[4:4+plain_len])

    try:
        result = plain_bytes.decode(input_encoding)
    except UnicodeDecodeError as e:
        raise ValueError(f"解码失败 ({input_encoding}): {e}")
    return result


# =================== GUI 辅助函数 ==================
def generate_offsets_manual(method: str, length: int, seed: Optional[int] = None,
                            salt: str = "", use_system_entropy: bool = False) -> List[int]:
    """GUI辅助：生成偏移序列（供预览和填入）"""
    if use_system_entropy:
        sys_entropy = int.from_bytes(os.urandom(32), _BE)
    else:
        sys_entropy = 0
    if seed is None:
        seed = int(time.time() * 1e6) ^ os.getpid()
    combined = f"{seed}{salt}{sys_entropy}".encode()
    final_seed = int.from_bytes(hashlib.sha256(combined).digest()[:8], _BE)
    # 兼容 method 可能是名称也可能是数字 ID
    if method in RNG_ID:
        rng_id = RNG_ID.get(method, 0)
    else:
        rng_id = method
    return generate_offsets_from_seed(final_seed, length, rng_id)