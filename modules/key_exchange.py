"""
Module 4: Thỏa thuận khóa (Diffie-Hellman số nhỏ, ECDH P-256, DH-2048) và HKDF-SHA256.
Đáp ứng yêu cầu Phần B.2.5 của đề bài.
"""
from Crypto.Protocol.DH import key_agreement
from Crypto.PublicKey import ECC
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256

def toy_dh(p: int, g: int, a: int, b: int) -> dict:
    """
    Diffie-Hellman số nhỏ tự cài bằng pow() của Python.
    Mẫu chuẩn: p=23, g=5, a=6, b=15 -> A=8, B=19, K=2.
    """
    A = pow(g, a, p)
    B = pow(g, b, p)
    K_alice = pow(B, a, p)
    K_bob = pow(A, b, p)
    
    return {
        "A": A,
        "B": B,
        "K_alice": K_alice,
        "K_bob": K_bob
    }

def generate_ephemeral(kind: str):
    """
    Sinh cặp khóa tạm thời (ephemeral) cho ECDH P-256 hoặc DH-2048.
    kind: "ecdh" hoặc "dh2048"
    """
    if kind == "ecdh":
        private_obj = ECC.generate(curve='p256')
        public_bytes = private_obj.public_key().export_key(format='DER')
        return private_obj, public_bytes
    elif kind == "dh2048":
        # Sử dụng nhóm chuẩn RFC 3526 (MODP Group 14 - 2048 bit) thông qua pycryptodome key_agreement
        # Hoặc sinh khóa DH theo chuẩn RFC
        # pycryptodome hỗ trợ key_agreement cho DH
        priv, pub = key_agreement.generate("dh_2048")
        return priv, pub
    else:
        raise ValueError(f"Loại thỏa thuận khóa không hỗ trợ: {kind}")

def derive_session_key(kind: str, my_private, peer_public_bytes: bytes, info: bytes = b"secure-channel-session") -> bytes:
    """
    Dẫn xuất khóa phiên 32 byte (256 bit) từ khóa chung qua HKDF-SHA256.
    """
    if kind == "ecdh":
        peer_pub_obj = ECC.import_key(peer_public_bytes)
        shared_point = my_private.d * peer_pub_obj.point()
        # Lấy tọa độ x làm secret thô
        shared_secret = int(shared_point.x).to_bytes(32, byteorder='big')
    elif kind == "dh2048":
        shared_secret = key_agreement.compute(my_private, peer_public_bytes, "dh_2048")
    else:
        raise ValueError(f"Loại thỏa thuận khóa không hỗ trợ: {kind}")

    # HKDF-SHA256 dẫn xuất ra 32 bytes (256 bit)
    derived_key = HKDF(
        master=shared_secret,
        key_len=32,
        salt=b"secure-channel-salt-fixed",
        hashmod=SHA256,
        context=info
    )
    return derived_key
