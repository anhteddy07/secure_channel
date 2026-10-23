"""Module chữ ký số cho dự án Secure Channel.

API theo README nhóm:
    ALGORITHMS
    generate_keypair(algo) -> (private_pem: str, public_pem: str)
    fingerprint(public_pem) -> str
    sign(algo, private_pem, message: bytes) -> bytes
    verify(algo, public_pem, message, signature) -> (valid: bool, reason: str)

Thư viện: cryptography
"""
from __future__ import annotations

import hashlib
from typing import Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

ALGORITHMS = ["RSA-PSS", "ECDSA-P256", "Ed25519"]


def _normalize_algo(algo: str) -> str:
    """Chuẩn hóa tên thuật toán; tên trả về dùng đúng theo ALGORITHMS."""
    if not isinstance(algo, str):
        raise ValueError("Tên thuật toán phải là chuỗi.")
    name = algo.strip().upper().replace("_", "-")
    aliases = {
        "RSA": "RSA-PSS",
        "RSA-PSS": "RSA-PSS",
        "ECDSA": "ECDSA-P256",
        "ECDSA-P256": "ECDSA-P256",
        "P256": "ECDSA-P256",
        "ED25519": "Ed25519",
    }
    if name not in aliases:
        raise ValueError(
            f"Sai thuật toán: {algo!r}. Các lựa chọn: {', '.join(ALGORITHMS)}."
        )
    return aliases[name]


def generate_keypair(algo: str) -> Tuple[str, str]:
    """Sinh khóa và trả về (private_pem, public_pem), cả hai là chuỗi PEM."""
    name = _normalize_algo(algo)

    if name == "RSA-PSS":
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
    elif name == "ECDSA-P256":
        private_key = ec.generate_private_key(ec.SECP256R1())
    else:
        private_key = ed25519.Ed25519PrivateKey.generate()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")

    return private_pem, public_pem


def fingerprint(public_pem: str) -> str:
    """Trả về hex của 16 byte đầu SHA-256 trên khóa công khai ở dạng DER."""
    if not isinstance(public_pem, str):
        raise TypeError("public_pem phải là chuỗi PEM.")

    public_key = serialization.load_pem_public_key(public_pem.encode("ascii"))
    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(public_der).digest()[:16].hex()


def _load_private_key(private_pem: str):
    if not isinstance(private_pem, str):
        raise TypeError("private_pem phải là chuỗi PEM.")
    return serialization.load_pem_private_key(
        private_pem.encode("ascii"),
        password=None,
    )


def _load_public_key(public_pem: str):
    if not isinstance(public_pem, str):
        raise TypeError("public_pem phải là chuỗi PEM.")
    return serialization.load_pem_public_key(public_pem.encode("ascii"))


def sign(algo: str, private_pem: str, message: bytes) -> bytes:
    """Ký message bytes; thư viện thực hiện băm và ký theo chuẩn thuật toán."""
    name = _normalize_algo(algo)
    if not isinstance(message, bytes):
        raise TypeError("message phải là bytes.")

    private_key = _load_private_key(private_pem)

    if name == "RSA-PSS":
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise ValueError("Sai thuật toán: khóa riêng không phải khóa RSA.")
        return private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

    if name == "ECDSA-P256":
        if not isinstance(private_key, ec.EllipticCurvePrivateKey):
            raise ValueError("Sai thuật toán: khóa riêng không phải khóa ECC.")
        if not isinstance(private_key.curve, ec.SECP256R1):
            raise ValueError("Sai thuật toán: khóa ECDSA không dùng đường cong P-256.")
        return private_key.sign(message, ec.ECDSA(hashes.SHA256()))

    if not isinstance(private_key, ed25519.Ed25519PrivateKey):
        raise ValueError("Sai thuật toán: khóa riêng không phải khóa Ed25519.")
    return private_key.sign(message)


def verify(
    algo: str,
    public_pem: str,
    message: bytes,
    signature: bytes,
) -> Tuple[bool, str]:
    """Trả về (hợp_lệ, lý_do).

    Không thể luôn phân biệt chắc chắn chữ ký sai do thông điệp bị sửa hay
    do dùng khóa công khai khác nếu chỉ có public key, message, signature.
    """
    try:
        name = _normalize_algo(algo)
    except ValueError as exc:
        return False, str(exc)

    if not isinstance(message, bytes):
        return False, "Dữ liệu không hợp lệ: message phải là bytes."
    if not isinstance(signature, bytes):
        return False, "Dữ liệu không hợp lệ: signature phải là bytes."

    try:
        public_key = _load_public_key(public_pem)
    except (ValueError, TypeError, UnicodeError):
        return False, "Sai khóa: khóa công khai PEM không hợp lệ."

    try:
        if name == "RSA-PSS":
            if not isinstance(public_key, rsa.RSAPublicKey):
                return False, "Sai thuật toán: khóa công khai không phải RSA."
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )

        elif name == "ECDSA-P256":
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                return False, "Sai thuật toán: khóa công khai không phải ECC."
            if not isinstance(public_key.curve, ec.SECP256R1):
                return False, "Sai thuật toán: khóa công khai không dùng P-256."
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))

        else:
            if not isinstance(public_key, ed25519.Ed25519PublicKey):
                return False, "Sai thuật toán: khóa công khai không phải Ed25519."
            public_key.verify(signature, message)

        return True, "Chữ ký hợp lệ."

    except InvalidSignature:
        return (
            False,
            "Chữ ký không hợp lệ: nội dung/chữ ký có thể bị sửa hoặc khóa công khai không khớp.",
        )
    except (ValueError, TypeError):
        return False, "Không thể xác minh: dữ liệu chữ ký hoặc khóa không hợp lệ."
