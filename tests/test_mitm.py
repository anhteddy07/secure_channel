"""Kiểm thử modules/mitm.py (Người 5). Cần signatures, pki, key_exchange, encryption đã xong."""
import pytest

from modules import mitm, pki, signatures

MSG = "Chuyển khoản cho Bob 100.000 đồng"


@pytest.fixture(scope="module", params=["Ed25519", "ECDSA-P256"])
def world(request):
    algo = request.param
    ids = {}
    for n in ("CA", "Alice", "Bob"):
        priv, pub = signatures.generate_keypair(algo)
        ids[n] = {"name": n, "algo": algo, "private_pem": priv, "public_pem": pub, "cert": None}
    ca = pki.CertificateAuthority(ids["CA"]["private_pem"], ids["CA"]["public_pem"], algo)
    for n in ("Alice", "Bob"):
        ids[n]["cert"] = ca.issue(n, ids[n]["public_pem"], algo)
    return ca, ids["Alice"], ids["Bob"]


def test_unauth_eve_reads_and_keys_differ():
    r = mitm.run_unauthenticated(MSG)
    assert r["attack_succeeded"] is True
    assert r["eve_read"] == MSG and r["bob_received"] == MSG
    assert r["keys"]["alice_eve"] != r["keys"]["eve_bob"]
    assert len(r["log"]) >= 8


def test_unauth_eve_can_modify():
    r = mitm.run_unauthenticated(MSG, modified_message="Chuyển khoản cho Eve 100.000 đồng")
    assert r["eve_read"] == MSG
    assert r["bob_received"] == "Chuyển khoản cho Eve 100.000 đồng"


@pytest.mark.parametrize("eve_has_cert", [False, True])
def test_auth_attack_fails(world, eve_has_cert):
    ca, alice, bob = world
    r = mitm.run_authenticated(MSG, ca, alice, bob, eve_has_cert=eve_has_cert)
    assert r["attack_succeeded"] is False
    assert r["eve_read"] is None
    assert r["bob_received"] == MSG                      # kênh thật vẫn hoạt động
    assert len(r["attempts"]) == (4 if eve_has_cert else 3)
    assert all(a["rejected"] for a in r["attempts"])


def test_auth_eve_valid_cert_rejected_for_subject(world):
    ca, alice, bob = world
    last = mitm.run_authenticated(MSG, ca, alice, bob, eve_has_cert=True)["attempts"][-1]
    assert last["stage"] == "kiểm tra chứng thư"          # bị chặn ngay ở tên chủ thể, chưa cần xét chữ ký


def test_auth_reports_success_if_verification_is_broken(world):
    """Nếu bước kiểm tra bị hỏng (luôn chấp nhận) thì mô phỏng phải báo tấn công thành công."""
    ca, alice, bob = world

    class BrokenCA:
        issue = staticmethod(ca.issue)
        verify = staticmethod(lambda cert, subject: (True, "hợp lệ"))

    orig = signatures.verify
    signatures.verify = lambda *a, **k: (True, "hợp lệ")
    try:
        assert mitm.run_authenticated(MSG, BrokenCA, alice, bob)["attack_succeeded"] is True
    finally:
        signatures.verify = orig


def test_auth_requires_certificates(world):
    ca, alice, bob = world
    with pytest.raises(ValueError):
        mitm.run_authenticated(MSG, ca, {**alice, "cert": None}, bob)


@pytest.mark.parametrize("bad", ["", "x" * 201])
def test_message_validation(bad):
    with pytest.raises(ValueError):
        mitm.run_unauthenticated(bad)