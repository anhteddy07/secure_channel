"""
Module 5: Mã hóa có xác thực (AEAD) gồm AES-256-GCM và ChaCha20-Poly1305.
Đáp ứng yêu cầu Phần B.2.5 của đề bài.
"""
from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Random import get_random_bytes

AEADS = ["AES-256-GCM", "ChaCha20-Poly1305"]

def encrypt(aead: str, key: bytes, plaintext: bytes, aad: bytes) -> dict:
    """
    Mã hóa dữ liệu sử dụng AEAD (AES-256-GCM hoặc ChaCha20-Poly1305).
    Trả về dict chứa nonce, ciphertext, tag (dạng hex string).
    """
    if aead == "AES-256-GCM":
        nonce = get_random_bytes(12) # 96-bit nonce chuẩn cho GCM
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update(aad)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    elif aead == "ChaCha20-Poly1305":
        nonce = get_random_bytes(12) # 96-bit nonce chuẩn cho ChaCha20-Poly1305
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        cipher.update(aad)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    else:
        raise ValueError(f"Thuật toán AEAD không hỗ trợ: {aead}")

    return {
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "tag": tag.hex()
    }

def decrypt(aead: str, key: bytes, nonce_hex: str, ciphertext_hex: str, tag_hex: str, aad: bytes) -> tuple[bool, bytes | str]:
    """
    Giải mã và xác thực bản mã.
    Nếu thất bại (sai tag, sai AAD, bản mã bị sửa), trả về (False, "thẻ xác thực không hợp lệ").
    """
    try:
        nonce = bytes.fromhex(nonce_hex)
        ciphertext = bytes.fromhex(ciphertext_hex)
        tag = bytes.fromhex(tag_hex)

        if aead == "AES-256-GCM":
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            cipher.update(aad)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        elif aead == "ChaCha20-Poly1305":
            cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
            cipher.update(aad)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        else:
            return False, f"Thuật toán AEAD không hỗ trợ: {aead}"

        return True, plaintext
    except (ValueError, KeyError):
        return False, "thẻ xác thực không hợp lệ"
