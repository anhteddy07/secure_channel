import pytest

from modules.signatures import ALGORITHMS, fingerprint, generate_keypair, sign, verify


@pytest.mark.parametrize("algo", ALGORITHMS)
def test_valid_signature(algo):
    private_pem, public_pem = generate_keypair(algo)
    message = "Alice chuyển cho Bob 100.000 đồng".encode("utf-8")
    signature = sign(algo, private_pem, message)
    valid, reason = verify(algo, public_pem, message, signature)
    assert valid is True
    assert reason == "Chữ ký hợp lệ."


@pytest.mark.parametrize("algo", ALGORITHMS)
def test_modified_message_fails(algo):
    private_pem, public_pem = generate_keypair(algo)
    signature = sign(algo, private_pem, b"amount=100")
    valid, reason = verify(algo, public_pem, b"amount=900", signature)
    assert valid is False
    assert "không hợp lệ" in reason.lower()


@pytest.mark.parametrize("algo", ALGORITHMS)
def test_wrong_public_key_fails(algo):
    private_pem, _ = generate_keypair(algo)
    _, other_public_pem = generate_keypair(algo)
    message = b"Secure Channel"
    signature = sign(algo, private_pem, message)
    valid, _ = verify(algo, other_public_pem, message, signature)
    assert valid is False


@pytest.mark.parametrize("algo", ALGORITHMS)
def test_fingerprint_format(algo):
    _, public_pem = generate_keypair(algo)
    fp = fingerprint(public_pem)
    assert len(fp) == 32
    int(fp, 16)


def test_unknown_algorithm():
    with pytest.raises(ValueError, match="Sai thuật toán"):
        generate_keypair("UNKNOWN")


def test_wrong_key_type_reports_algorithm_error():
    private_pem, public_pem = generate_keypair("Ed25519")
    signature = sign("Ed25519", private_pem, b"hello")
    valid, reason = verify("RSA-PSS", public_pem, b"hello", signature)
    assert valid is False
    assert "Sai thuật toán" in reason
