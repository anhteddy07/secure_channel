import copy
from datetime import datetime, timedelta, timezone

import pytest
from Crypto.PublicKey import ECC, RSA

from modules.pki import CertificateAuthority, _format_time


def make_keypair(algo):
    if algo == "RSA-PSS":
        key = RSA.generate(2048)
        return key.export_key().decode("ascii"), key.public_key().export_key().decode("ascii")
    if algo == "ECDSA-P256":
        key = ECC.generate(curve="P-256")
        return key.export_key(format="PEM"), key.public_key().export_key(format="PEM")
    if algo == "Ed25519":
        key = ECC.generate(curve="Ed25519")
        return key.export_key(format="PEM"), key.public_key().export_key(format="PEM")
    raise ValueError(algo)


@pytest.fixture(params=["RSA-PSS", "ECDSA-P256", "Ed25519"])
def pki(request):
    algo = request.param
    ca_private, ca_public = make_keypair(algo)
    alice_private, alice_public = make_keypair("Ed25519")
    ca = CertificateAuthority(ca_private, ca_public, algo)
    cert = ca.issue("Alice", alice_public, "Ed25519")
    return ca, cert, alice_private, alice_public


def test_root_certificate_is_self_signed(pki):
    ca, _, _, _ = pki
    ok, reason = ca.verify(ca.root_cert, "Root CA")
    assert ok, reason


def test_valid_certificate_passes(pki):
    ca, cert, _, _ = pki
    ok, reason = ca.verify(cert, "Alice")
    assert ok
    assert reason == "chứng thư hợp lệ"


def test_tampered_certificate_signature_is_rejected(pki):
    ca, cert, _, _ = pki
    changed = copy.deepcopy(cert)
    changed["public_key"] = ca.public_pem
    ok, reason = ca.verify(changed, "Alice")
    assert not ok
    assert "chữ ký CA sai" in reason


def test_expired_certificate_is_rejected(pki):
    ca, _, _, alice_public = pki
    cert = ca.issue("Expired Alice", alice_public, "Ed25519", valid_days=-1)
    ok, reason = ca.verify(cert, "Expired Alice")
    assert not ok
    assert "hết hạn" in reason


def test_wrong_subject_is_rejected(pki):
    ca, cert, _, _ = pki
    ok, reason = ca.verify(cert, "Bob")
    assert not ok
    assert "sai tên chủ thể" in reason


def test_revoked_certificate_is_rejected(pki):
    ca, cert, _, _ = pki
    ca.revoke(cert["serial"])
    ok, reason = ca.verify(cert, "Alice")
    assert not ok
    assert "thu hồi" in reason


def test_revoke_is_idempotent(pki):
    ca, cert, _, _ = pki
    ca.revoke(cert["serial"])
    ca.revoke(cert["serial"])
    assert ca.crl.count(cert["serial"]) == 1


def test_issue_increments_serial(pki):
    ca, cert, _, alice_public = pki
    second = ca.issue("Alice 2", alice_public, "Ed25519")
    assert second["serial"] == cert["serial"] + 1


def test_invalid_algorithm_is_rejected():
    with pytest.raises(ValueError):
        CertificateAuthority("x", "y", "UNKNOWN")


def test_empty_subject_is_rejected(pki):
    ca, _, _, alice_public = pki
    with pytest.raises(ValueError):
        ca.issue("", alice_public, "Ed25519")


def test_certificate_contains_required_fields(pki):
    _, cert, _, _ = pki
    assert {
        "subject", "public_key", "key_algo", "not_before", "not_after",
        "serial", "issuer", "sig_alg", "signature",
    }.issubset(cert)
