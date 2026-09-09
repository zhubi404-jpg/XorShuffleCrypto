#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
偏移加密引擎 v2.0
协议版本 1 和 2 兼容
版本2包结构：
  [HEADER_V2 (96B)] [CIPHER (4*N B)] [TAG (16B)]
头部格式：version(1) + nonce(12) + encrypted_seed(32) + gcm_tag(16) + session_salt(32) + enc_id(1) + flags(1) + rng_id(1)

安全改进（vs v1）：
  - 会话盐：每个会话独立派生子密钥，避免单点失效
  - AES-GCM加密种子：抗已知明文攻击，防止Seed_Key泄露
  - 分组掩码提升至32位：消除长文本碰撞风险
  - 强制嵌入参数：永远不为0种子
  - 仍支持用户自定义PRNG（通过rng_id）
"""

import random
import hashlib
import hmac
import os
import time
import base64
import secrets
from typing import Optional, Callable, List, Tuple, Dict, Type, Union
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ==================== 常量与配置 ====================
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
HEADER_VERSION_2 = 2        # 协议版本 v2.0
HEADER_BYTES = 36
TAG_BYTES = 16
KEY_BYTES = 32

# 版本2专用常量
HEADER_BYTES_V2 = 96
SESSION_SALT_BYTES = 32
GROUP_BYTES_V2 = 4          # 每个分组4字节
GROUP_BYTES_V1 = 2

# PRNG 名称与ID映射（兼容旧版）
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


# ==================== 伪随机数生成器（PRNG） ====================
def _normalize_seed(seed: int) -> bytes:
    """将整数种子归一化为32字节确定性种子（SHA-256）"""
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


# ==================== PRNG 注册与管理 ====================
_PRNGS: Dict[str, Type] = {}

def register_prng(name: str, rng_class: Type) -> None:
    """注册自定义 PRNG 类"""
    _PRNGS[name] = rng_class

def get_prng_class(name: str) -> Type:
    """根据名称获取 PRNG 类"""
    cls = _PRNGS.get(name)
    if cls is None:
        raise ValueError(f"未知 PRNG: {name}，可用: {', '.join(_PRNGS.keys())}")
    return cls

def list_prngs() -> List[str]:
    """列出所有已注册的 PRNG 名称"""
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
    使用种子和PRNG生成 0..length-1 的随机排列（Fisher-Yates）
    rng_id 可以是整数ID或字符串名称
    """
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


# ==================== HKDF-SHA256 ====================
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


# ==================== 版本1（旧版）支持 ====================
# 以下函数仅供解密旧版密文使用，新版加密不再产生版本1格式

def derive_session_keys_v1(user_key: bytes) -> Tuple[bytes, bytes, bytes]:
    """版本1的密钥派生：直接派生三个子密钥"""
    salt = b"EncryptToolV4-Salt"
    master = hkdf(user_key, salt, b"MasterKey", KEY_BYTES)
    enc_key = hkdf(master, b"", b"EncKey", KEY_BYTES)
    mac_key = hkdf(master, b"", b"MacKey", KEY_BYTES)
    seed_key = hkdf(master, b"", b"SeedKey", KEY_BYTES)
    return enc_key, mac_key, seed_key

def expand_key_stream_v1(enc_key: bytes, seed: int, index: int) -> int:
    """版本1密钥流：16位掩码"""
    seed_bytes = seed.to_bytes(32, _BE)
    idx_bytes = index.to_bytes(8, _BE)
    digest = hmac.new(enc_key, seed_bytes + idx_bytes, hashlib.sha256).digest()
    return int.from_bytes(digest[:2], _BE)

def pack_header_v1(version: int, seed: int, enc_id: int, offset_mode: int,
                   rng_id: int, seed_key: bytes) -> bytes:
    """版本1头部打包（XOR加密种子）"""
    if version != HEADER_VERSION:
        raise ValueError(f"不支持的版本: {version}")
    seed_bytes = seed.to_bytes(32, _BE)
    encrypted_seed = bytes(a ^ b for a, b in zip(seed_bytes, seed_key))
    flags = (offset_mode & 0x03)
    header = bytes([version]) + encrypted_seed + bytes([enc_id, flags, rng_id & 0xFF])
    if len(header) != HEADER_BYTES:
        raise RuntimeError("头部长度错误")
    return header

def unpack_header_v1(data: bytes, seed_key: bytes) -> Tuple[int, int, int, int]:
    """版本1头部解包（XOR解密种子）"""
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


# ==================== 版本2核心函数 ====================
def derive_master_key(user_key: bytes) -> bytes:
    """从用户密钥派生主密钥（用于会话盐派生）"""
    salt = b"EncryptToolV4-Salt"
    return hkdf(user_key, salt, b"MasterKey", KEY_BYTES)

def derive_session_subkeys(master_key: bytes, session_salt: bytes) -> Tuple[bytes, bytes, bytes]:
    """
    使用主密钥和会话盐派生会话专属的三个子密钥
    每个会话独立，实现会话隔离
    """
    prk = hkdf_extract(session_salt, master_key)
    enc_key = hkdf_expand(prk, b"EncKey", KEY_BYTES)
    mac_key = hkdf_expand(prk, b"MacKey", KEY_BYTES)
    seed_key = hkdf_expand(prk, b"SeedKey", KEY_BYTES)
    return enc_key, mac_key, seed_key

def expand_key_stream_v2(enc_key: bytes, seed: int, index: int) -> int:
    """版本2密钥流：32位掩码（消除碰撞）"""
    seed_bytes = seed.to_bytes(32, _BE)
    idx_bytes = index.to_bytes(8, _BE)
    digest = hmac.new(enc_key, seed_bytes + idx_bytes, hashlib.sha256).digest()
    return int.from_bytes(digest[:4], _BE)

def pack_header_v2(seed: int, session_salt: bytes, enc_id: int, offset_mode: int,
                   rng_id: int, seed_key: bytes) -> bytes:
    """
    版本2头部打包
    使用 AES-256-GCM 加密种子，并附加会话盐
    """
    nonce = os.urandom(12)
    aesgcm = AESGCM(seed_key)
    seed_bytes = seed.to_bytes(32, _BE)
    ciphertext_and_tag = aesgcm.encrypt(nonce, seed_bytes, None)
    encrypted_seed = ciphertext_and_tag[:-16]   # 32字节
    gcm_tag = ciphertext_and_tag[-16:]          # 16字节
    flags = offset_mode & 0x03
    header = (bytes([HEADER_VERSION_2]) + nonce + encrypted_seed + gcm_tag +
              session_salt + bytes([enc_id, flags, rng_id & 0xFF]))
    assert len(header) == HEADER_BYTES_V2
    return header

def unpack_header_v2(data: bytes, seed_key: bytes) -> Tuple[int, int, int, int, bytes]:
    """版本2头部解包，返回 (seed, enc_id, offset_mode, rng_id, session_salt)"""
    if len(data) != HEADER_BYTES_V2:
        raise ValueError("头部长度错误，期望96字节")
    version = data[0]
    if version != HEADER_VERSION_2:
        raise ValueError(f"不是版本2头部: {version}")
    nonce = data[1:13]
    encrypted_seed = data[13:45]   # 32 bytes
    gcm_tag = data[45:61]          # 16 bytes
    session_salt = data[61:93]     # 32 bytes
    enc_id = data[93]
    flags = data[94]
    rng_id = data[95]
    aesgcm = AESGCM(seed_key)
    seed_bytes = aesgcm.decrypt(nonce, encrypted_seed + gcm_tag, None)
    seed = int.from_bytes(seed_bytes, _BE)
    offset_mode = flags & 0x03
    return seed, enc_id, offset_mode, rng_id, session_salt


# ==================== HMAC认证 ====================
def compute_tag(mac_key: bytes, auth_data: bytes) -> bytes:
    """计算 HMAC-SHA256 标签，截取前16字节"""
    return hmac.new(mac_key, auth_data, hashlib.sha256).digest()[:TAG_BYTES]


# ==================== 加密主函数 ====================
def encrypt_with_offset(plain: str, offset_str: str, key_str: str, input_encoding: str,
                        embed_params: bool = True, seed: Optional[int] = None,
                        rng_id: int = 0, error_log: Optional[Callable] = None) -> bytes:
    """
    加密主函数，强制使用协议版本2
    - embed_params 强制为 True（禁用调试模式）
    - 若 rng_id 未指定，默认使用 SHA256Source (ID=3)
    """
    # 强制嵌入参数，避免 seed=0 的 Two-Time Pad 攻击
    embed_params = True
    if rng_id == 0:
        rng_id = 3   # SHA256Source

    if input_encoding == "base64":
        raise ValueError("加密时不支持将输入编码设为 base64")

    user_key = key_str.encode('utf-8')
    master_key = derive_master_key(user_key)
    session_salt = os.urandom(SESSION_SALT_BYTES)
    enc_key, mac_key, seed_key = derive_session_subkeys(master_key, session_salt)

    # 明文预处理：添加长度前缀（4字节大端），并填充到4字节倍数
    plain_bytes = plain.encode(input_encoding)
    data = _u32_to_bytes_be(len(plain_bytes)) + plain_bytes
    if len(data) % GROUP_BYTES_V2 != 0:
        data += b'\x00' * (GROUP_BYTES_V2 - (len(data) % GROUP_BYTES_V2))
    num_groups = len(data) // GROUP_BYTES_V2

    # 确定偏移序列（随机或手动）
    raw = offset_str.strip()
    if raw == "":
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

    if len(offsets) != num_groups or set(offsets) != set(range(num_groups)):
        raise ValueError("偏移序列无效")

    # XOR 加密（4字节分组，大端）
    xor_groups = []
    for i in range(num_groups):
        base = i * GROUP_BYTES_V2
        val = int.from_bytes(data[base:base+GROUP_BYTES_V2], _BE)
        key_ext = expand_key_stream_v2(enc_key, seed, i)
        val ^= key_ext
        xor_groups.append(val)

    # 置换混淆
    cipher_ints = [0] * num_groups
    for i in range(num_groups):
        cipher_ints[offsets[i]] = xor_groups[i]

    # 转为字节流（大端）
    cipher_bytes = bytearray()
    for v in cipher_ints:
        cipher_bytes += v.to_bytes(GROUP_BYTES_V2, _BE)

    enc_id = ENCODING_ID.get(input_encoding, 1)
    header = pack_header_v2(seed, session_salt, enc_id, offset_mode, rng_id, seed_key)

    # 计算 HMAC 标签
    auth_data = header + cipher_bytes
    tag = compute_tag(mac_key, auth_data)

    packet = header + cipher_bytes + tag
    return packet


# ==================== 解密主函数（自动识别版本） ====================
def decrypt_with_offset(packet: bytes, offset_str: str, key_str: str, input_encoding: str,
                        embed_params: bool = True, error_log: Optional[Callable] = None) -> str:
    """
    解密主函数，自动识别协议版本（1或2）
    """
    if not packet:
        raise ValueError("包为空")

    version = packet[0]
    user_key = key_str.encode('utf-8')

    # ---------- 版本1解密 ----------
    if version == HEADER_VERSION:
        enc_key, mac_key, seed_key = derive_session_keys_v1(user_key)
        if embed_params:
            if len(packet) < HEADER_BYTES + TAG_BYTES + 1:
                raise ValueError("包过短")
            header = packet[:HEADER_BYTES]
            cipher_bytes = packet[HEADER_BYTES:-TAG_BYTES]
            tag = packet[-TAG_BYTES:]

            auth_data = header + cipher_bytes
            expected_tag = compute_tag(mac_key, auth_data)
            if not hmac.compare_digest(expected_tag, tag):
                raise ValueError("认证失败：密钥错误或数据被篡改")

            seed, enc_id, offset_mode, rng_id = unpack_header_v1(header, seed_key)
            if enc_id not in ID_ENCODING:
                raise ValueError("无效的输入编码ID")
            input_encoding = ID_ENCODING[enc_id]
            num_groups = len(cipher_bytes) // GROUP_BYTES_V1
            if len(cipher_bytes) % GROUP_BYTES_V1 != 0:
                raise ValueError("密文长度不是偶数")
        else:
            # 非嵌入模式（仅用于调试，不推荐）
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
            num_groups = len(cipher_bytes) // GROUP_BYTES_V1
            if len(cipher_bytes) % GROUP_BYTES_V1 != 0:
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

        # 逆置换 + XOR（版本1掩码16位）
        cipher_ints = [int.from_bytes(cipher_bytes[i:i+GROUP_BYTES_V1], _BE)
                       for i in range(0, len(cipher_bytes), GROUP_BYTES_V1)]
        recovered_ints = [0] * num_groups
        for i in range(num_groups):
            recovered_ints[i] = cipher_ints[offsets[i]]

        raw_bytes = bytearray(num_groups * GROUP_BYTES_V1)
        for i, val in enumerate(recovered_ints):
            key_ext = expand_key_stream_v1(enc_key, seed, i)
            val ^= key_ext
            raw_bytes[i*GROUP_BYTES_V1:(i+1)*GROUP_BYTES_V1] = val.to_bytes(GROUP_BYTES_V1, _BE)

        # 长度前缀
        plain_len = _bytes_to_u32_be(bytes(raw_bytes[:4]))
        if plain_len > len(raw_bytes) - 4:
            raise ValueError("长度前缀错误")
        plain_bytes = bytes(raw_bytes[4:4+plain_len])

        try:
            return plain_bytes.decode(input_encoding)
        except UnicodeDecodeError as e:
            raise ValueError(f"解码失败 ({input_encoding}): {e}")

    # ---------- 版本2解密 ----------
    elif version == HEADER_VERSION_2:
        if len(packet) < HEADER_BYTES_V2 + TAG_BYTES + 1:
            raise ValueError("包过短（版本2）")
        master_key = derive_master_key(user_key)

        header = packet[:HEADER_BYTES_V2]
        cipher_bytes = packet[HEADER_BYTES_V2:-TAG_BYTES]
        tag = packet[-TAG_BYTES:]

        # 提取会话盐
        session_salt = header[61:93]
        enc_key, mac_key, seed_key = derive_session_subkeys(master_key, session_salt)

        # 解包头部获取种子
        seed, enc_id, offset_mode, rng_id, session_salt = unpack_header_v2(header, seed_key)

        # MAC验证
        auth_data = header + cipher_bytes
        expected_tag = compute_tag(mac_key, auth_data)
        if not hmac.compare_digest(expected_tag, tag):
            raise ValueError("认证失败：密钥错误或数据被篡改")

        num_groups = len(cipher_bytes) // GROUP_BYTES_V2
        if len(cipher_bytes) % GROUP_BYTES_V2 != 0:
            raise ValueError("密文长度不是4的倍数")

        # 读回密文整数（4字节大端）
        cipher_ints = [int.from_bytes(cipher_bytes[i:i+GROUP_BYTES_V2], _BE)
                       for i in range(0, len(cipher_bytes), GROUP_BYTES_V2)]

        # 获取偏移序列
        if offset_mode == OFFSET_MODE_MANUAL:
            if not offset_str.strip():
                raise ValueError("手动模式需要偏移字符串")
            offsets = parse_offsets(offset_str, length_hint=num_groups)
        elif offset_mode == OFFSET_MODE_SEQUENTIAL:
            offsets = list(range(num_groups))
        elif offset_mode == OFFSET_MODE_RANDOM:
            offsets = generate_offsets_from_seed(seed, num_groups, rng_id=rng_id)
        else:
            raise ValueError(f"未知 offset_mode: {offset_mode}")

        if len(offsets) != num_groups or set(offsets) != set(range(num_groups)):
            raise ValueError("偏移序列无效")

        # 逆置换 + XOR（版本2掩码32位）
        recovered_ints = [0] * num_groups
        for i in range(num_groups):
            recovered_ints[i] = cipher_ints[offsets[i]]

        raw_bytes = bytearray(num_groups * GROUP_BYTES_V2)
        for i, val in enumerate(recovered_ints):
            key_ext = expand_key_stream_v2(enc_key, seed, i)
            val ^= key_ext
            raw_bytes[i*GROUP_BYTES_V2:(i+1)*GROUP_BYTES_V2] = val.to_bytes(GROUP_BYTES_V2, _BE)

        # 长度前缀
        plain_len = _bytes_to_u32_be(bytes(raw_bytes[:4]))
        if plain_len > len(raw_bytes) - 4:
            raise ValueError("长度前缀错误")
        plain_bytes = bytes(raw_bytes[4:4+plain_len])

        # 解码
        enc_map = ID_ENCODING.get(enc_id, 'utf-8')
        try:
            return plain_bytes.decode(enc_map)
        except UnicodeDecodeError as e:
            raise ValueError(f"解码失败 ({enc_map}): {e}")

    else:
        raise ValueError(f"不支持的协议版本: {version}")


# ==================== GUI 辅助函数 ====================
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
    if method in RNG_ID:
        rng_id = RNG_ID.get(method, 0)
    else:
        rng_id = method
    return generate_offsets_from_seed(final_seed, length, rng_id)