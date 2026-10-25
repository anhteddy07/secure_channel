"""Mini-PKI module for the Secure Channel practical assignment.

Certificates are JSON-serializable dictionaries. The CA signs the canonical
JSON representation of every certificate field except ``signature``.
Requires PyCryptodome: pip install pycryptodome
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any

from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC, RSA
from Crypto.Signature import DSS, eddsa, pss


SUPPORTED_ALGORITHMS = {"RSA-PSS", "ECDSA-P256", "Ed25519"}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _format_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_time(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError("thời gian chứng thư không hợp lệ")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _canonical_bytes(cert: dict[str, Any]) -> bytes:
    """Return canonical JSON bytes for all fields except the signature."""
    unsigned = {key: value for key, value in cert.items() if key != "signature"}
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _load_private_key(private_pem: str, algo: str):
    if algo == "RSA-PSS":
        key = RSA.import_key(private_pem)
        if key.size_in_bits() < 2048:
            raise ValueError("RSA-PSS cần khóa tối thiểu 2048 bit")
        return key
    if algo == "ECDSA-P256":
        key = ECC.import_key(private_pem)
        if key.curve not in ("NIST P-256", "prime256v1", "secp256r1"):
            raise ValueError("ECDSA-P256 yêu cầu đường cong P-256")
        if not key.has_private():
            raise ValueError("không có khóa riêng")
        return key
    if algo == "Ed25519":
        key = ECC.import_key(private_pem)
        if not key.has_private() or key.curve != "Ed25519":
            raise ValueError("khóa riêng Ed25519 không hợp lệ")
        return key
    raise ValueError(f"thuật toán không được hỗ trợ: {algo}")


def _load_public_key(public_pem: str, algo: str):
    if algo == "RSA-PSS":
        return RSA.import_key(public_pem)
    if algo in ("ECDSA-P256", "Ed25519"):
        key = ECC.import_key(public_pem)
        expected_curve = "Ed25519" if algo == "Ed25519" else "NIST P-256"
        if key.curve != expected_curve:
            raise ValueError(f"khóa công khai không thuộc {expected_curve}")
        return key
    raise ValueError(f"thuật toán không được hỗ trợ: {algo}")


def _sign(algo: str, private_pem: str, message: bytes) -> bytes:
    key = _load_private_key(private_pem, algo)
    digest = SHA256.new(message)
    if algo == "RSA-PSS":
        return pss.new(key).sign(digest)
    if algo == "ECDSA-P256":
        return DSS.new(key, "fips-186-3", encoding="binary").sign(digest)
    if algo == "Ed25519":
        return eddsa.new(key, "rfc8032").sign(digest.digest())
    raise ValueError(f"thuật toán không được hỗ trợ: {algo}")


def _verify_signature(algo: str, public_pem: str, message: bytes, signature: bytes) -> bool:
    try:
        key = _load_public_key(public_pem, algo)
        digest = SHA256.new(message)
        if algo == "RSA-PSS":
            pss.new(key).verify(digest, signature)
        elif algo == "ECDSA-P256":
            DSS.new(key, "fips-186-3", encoding="binary").verify(digest, signature)
        elif algo == "Ed25519":
            eddsa.new(key, "rfc8032").verify(digest.digest(), signature)
        else:
            return False
        return True
    except (ValueError, TypeError, KeyError, IndexError):
        return False
    except Exception:
        return False


class CertificateAuthority:
    """Small in-memory CA implementing issue, revoke and certificate verify."""

    def __init__(
        self,
        private_pem: str,
        public_pem: str,
        algo: str,
        name: str = "Root CA",
        valid_days: int = 3650,
    ):
        if algo not in SUPPORTED_ALGORITHMS:
            raise ValueError(f"thuật toán không được hỗ trợ: {algo}")
        if not name or not isinstance(name, str):
            raise ValueError("tên CA không hợp lệ")
        self.private_pem = private_pem
        self.public_pem = public_pem
        self.algo = algo
        self.name = name
        self.crl: list[int] = []
        self._next_serial = 1

        now = _utc_now()
        root = {
            "subject": name,
            "public_key": public_pem,
            "key_algo": algo,
            "not_before": _format_time(now),
            "not_after": _format_time(now + timedelta(days=valid_days)),
            "serial": 0,
            "issuer": name,
            "sig_alg": algo,
        }
        root["signature"] = base64.b64encode(_sign(algo, private_pem, _canonical_bytes(root))).decode("ascii")
        self.root_cert = root

    def issue(
        self,
        subject: str,
        public_key_pem: str,
        key_algo: str,
        valid_days: int = 365,
    ) -> dict[str, Any]:
        """Issue a certificate for a subject. Negative valid_days creates an expired cert for demos."""
        if not isinstance(subject, str) or not subject.strip():
            raise ValueError("tên chủ thể không được để trống")
        if key_algo not in SUPPORTED_ALGORITHMS:
            raise ValueError(f"thuật toán khóa không được hỗ trợ: {key_algo}")
        # Validate that the supplied public key matches its declared algorithm.
        _load_public_key(public_key_pem, key_algo)
        now = _utc_now()
        cert: dict[str, Any] = {
            "subject": subject,
            "public_key": public_key_pem,
            "key_algo": key_algo,
            "not_before": _format_time(now),
            "not_after": _format_time(now + timedelta(days=valid_days)),
            "serial": self._next_serial,
            "issuer": self.name,
            "sig_alg": self.algo,
        }
        self._next_serial += 1
        cert["signature"] = base64.b64encode(_sign(self.algo, self.private_pem, _canonical_bytes(cert))).decode("ascii")
        return cert

    def revoke(self, serial: int) -> None:
        """Add a certificate serial number to the revocation list (idempotently)."""
        if isinstance(serial, bool) or not isinstance(serial, int) or serial < 0:
            raise ValueError("serial phải là số nguyên không âm")
        if serial not in self.crl:
            self.crl.append(serial)

    def verify(self, cert: dict[str, Any], expected_subject: str) -> tuple[bool, str]:
        """Verify CA signature, validity period, expected subject and revocation.

        Returns (True, reason) on success, otherwise (False, a Vietnamese reason).
        """
        if not isinstance(cert, dict):
            return False, "chứng thư không hợp lệ"

        required = {
            "subject", "public_key", "key_algo", "not_before", "not_after",
            "serial", "issuer", "sig_alg", "signature",
        }
        if not required.issubset(cert):
            return False, "chứng thư thiếu trường bắt buộc"

        # Verify the signature over every field except signature before trusting fields.
        try:
            signature = base64.b64decode(cert["signature"], validate=True)
        except (ValueError, TypeError):
            return False, "chữ ký CA sai: chữ ký không đúng định dạng"
        if cert.get("issuer") != self.name or cert.get("sig_alg") != self.algo:
            return False, "chữ ký CA sai hoặc CA phát hành không hợp lệ"
        if not _verify_signature(self.algo, self.public_pem, _canonical_bytes(cert), signature):
            return False, "chữ ký CA sai: chứng thư có thể đã bị sửa"

        try:
            now = _utc_now()
            not_before = _parse_time(cert["not_before"])
            not_after = _parse_time(cert["not_after"])
        except (ValueError, TypeError, OverflowError):
            return False, "thời hạn chứng thư không hợp lệ"
        if now < not_before:
            return False, "chứng thư chưa có hiệu lực"
        if now > not_after:
            return False, "chứng thư đã hết hạn"

        if cert.get("subject") != expected_subject:
            return False, "sai tên chủ thể: không khớp với danh tính mong đợi"

        serial = cert.get("serial")
        if isinstance(serial, bool) or not isinstance(serial, int):
            return False, "serial chứng thư không hợp lệ"
        if serial in self.crl:
            return False, "chứng thư đã bị thu hồi"

        # Also reject malformed public keys or a mismatch between key and declared algorithm.
        try:
            _load_public_key(cert["public_key"], cert["key_algo"])
        except (ValueError, TypeError, KeyError):
            return False, "khóa công khai trong chứng thư không hợp lệ"

        return True, "chứng thư hợp lệ"


def _canonical_certificate_bytes(cert: dict[str, Any]) -> bytes:
    """Public helper useful for tests and demonstrations."""
    return _canonical_bytes(cert)


def _tamper_certificate_for_test(cert: dict[str, Any], **changes: Any) -> dict[str, Any]:
    """Return a modified copy; intended for tests/demo only, never for production."""
    result = dict(cert)
    result.update(changes)
    return result
