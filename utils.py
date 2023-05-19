
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from os import urandom
import hashlib



__all__ = ['gen_iv', 'gen_key']

METHODS = [
    {"cipher": "AES-128-CFB", "name": "AES-128-CFB", "key_len": 16, "iv_len": 16},
    {"cipher": "AES-192-CFB", "name": "AES-192-CFB", "key_len": 24, "iv_len": 16},
    {"cipher": "AES-256-CFB", "name": "AES-256-CFB", "key_len": 32, "iv_len": 16},
    {"cipher": "AES-128-CTR", "name": "AES-128-CTR", "key_len": 16, "iv_len": 16},
    {"cipher": "AES-192-CTR", "name": "AES-192-CTR", "key_len": 24, "iv_len": 16},
    {"cipher": "AES-256-CTR", "name": "AES-256-CTR", "key_len": 32, "iv_len": 16},
]


def get_iv_len(name: str) -> int:
    for method in METHODS:
        if method["name"] == name:
            return method["iv_len"]
    raise ValueError(f"Unsupported cipher name: {name}")


def get_key_len(name: str) -> int:
    for method in METHODS:
        if method["name"] == name:
            return method["key_len"]
    raise ValueError(f"Unsupported cipher name: {name}")


def gen_iv(seed: str, iv_len: int) -> bytes:
    # 使用seed生成伪随机数生成器的种子
    seed_bytes = seed.encode('utf-8')

    # 生成随机的salt
    salt = urandom(iv_len)

    # 使用HKDF算法从seed中派生iv
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=iv_len,
        salt=salt,
        info=None
    )
    iv = hkdf.derive(seed_bytes)

    return iv


def gen_key(seed: str, key_len: int) -> bytes:
    seed_bytes = seed.encode('utf-8')

    result = b''

    rm_len = key_len
    pos = None

    while rm_len > 0:
        if pos:
            buf = pos + seed_bytes
        else:
            buf = seed_bytes

        digest = hashlib.md5(buf).digest()
        cpy_len = min(rm_len, len(digest))

        result += digest[:cpy_len]

        pos = digest
        rm_len -= cpy_len

    return result


# async def async_dns_query(domain: str, query_type: str = 'A') -> str:
#     resolver = aiodns.DNSResolver()
#     try:
#         result = await resolver.query(domain, query_type)
#         if result:
#             return result[0].host
#     except aiodns.error.DNSError as e:
#         return None


