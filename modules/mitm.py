"""
modules/mitm.py - Mô phỏng tấn công người ở giữa (MITM) (đề bài B.2.6).

Mọi thứ chạy trong một tiến trình: "máy chủ trung gian" chính là Eve, nên Eve thấy và
thay được mọi gói tin giữa Alice và Bob. Module này KHÔNG tự cài mật mã; nó chỉ gọi
signatures / key_exchange / encryption và đối tượng CA do app.py truyền vào, nên kết quả
phản ánh đúng chất lượng của các module đó (nếu chúng sai, tấn công sẽ "thành công").

Hai chế độ:
  1. run_unauthenticated: DH (ECDH) không xác thực -> Eve đọc và sửa được tin.
  2. run_authenticated:   mỗi bên ký giá trị DH tạm thời bằng khóa dài hạn và đính kèm chứng thư;
                          người nhận kiểm tra chuỗi CA -> chứng thư -> chữ ký trước khi tính khóa chung.

Hợp đồng trả về (xem README): {"mode", "log": [str], "eve_read": str | None,
"keys": {...sha256 của khóa phiên...}, "attack_succeeded": bool, ...trường bổ sung...}.

Chạy thử riêng (cần các module khác đã xong):  python -m modules.mitm
"""
from __future__ import annotations

import copy
import hashlib

from . import encryption, key_exchange, signatures

MODE_UNAUTH = "DH không xác thực"
MODE_AUTH = "DH có chữ ký và chứng thư"
MAX_LEN = 200

INFO = b"secure_channel|Alice<->Bob"   # ngữ cảnh HKDF, là thông tin công khai của giao thức
AAD = b"Alice|Bob|1"                   # tiêu đề: người gửi, người nhận, số thứ tự


# ----------------------------------------------------------------- tiện ích --
def _check_message(message) -> None:
    if not isinstance(message, str) or not message:
        raise ValueError("Tin nhắn không được để trống")
    if len(message) > MAX_LEN:
        raise ValueError(f"Tin nhắn tối đa {MAX_LEN} ký tự")


def _short(data, n: int = 8) -> str:
    """Rút gọn bytes/hex để log dễ đọc."""
    h = data.hex() if isinstance(data, (bytes, bytearray)) else str(data)
    return h[: 2 * n] + "..."


def _fp(key: bytes) -> str:
    """Khóa phiên chỉ hiển thị dạng băm SHA-256."""
    return hashlib.sha256(key).hexdigest()


def _seal(aead: str, key: bytes, text: str, aad: bytes) -> dict:
    return encryption.encrypt(aead, key, text.encode("utf-8"), aad)


def _open(aead: str, key: bytes, pkt: dict, aad: bytes):
    """Trả (ok, văn bản hoặc thông báo lỗi)."""
    ok, out = encryption.decrypt(aead, key, pkt["nonce"], pkt["ciphertext"], pkt["tag"], aad)
    return ok, (out.decode("utf-8", "replace") if ok else str(out))


def _require_identity(ent: dict, name: str) -> None:
    for field in ("algo", "private_pem", "public_pem", "cert"):
        if not ent.get(field):
            raise ValueError(f"{name} chưa có đủ khóa/chứng thư (thiếu '{field}')")


# =========================================================================== #
# Chế độ 1: DH không xác thực
# =========================================================================== #
def run_unauthenticated(message: str, modified_message: str | None = None,
                        kex: str = "ecdh", aead: str = "AES-256-GCM") -> dict:
    """
    Eve chặn giá trị công khai của hai bên và thay bằng của mình.
    modified_message: nếu có, Eve chuyển cho Bob nội dung này thay vì tin gốc (chứng minh Eve sửa được).
    """
    _check_message(message)
    if modified_message is not None:
        _check_message(modified_message)
    forwarded = modified_message if modified_message is not None else message
    log: list[str] = []

    a_priv, a_pub = key_exchange.generate_ephemeral(kex)   # Alice: (a, A)
    b_priv, b_pub = key_exchange.generate_ephemeral(kex)   # Bob:   (b, B)
    e_priv, e_pub = key_exchange.generate_ephemeral(kex)   # Eve:   (e, E)

    log.append(f"Alice tạo cặp khóa DH tạm thời (a, A) và gửi A cho Bob. A = {_short(a_pub)}")
    log.append("Eve nằm trên đường truyền: chặn A, không chuyển tiếp cho Bob.")
    log.append(f"Eve tạo cặp khóa riêng (e, E) và gửi E = {_short(e_pub)} cho Bob, giả làm Alice. "
               "Gói tin không có chữ ký hay chứng thư nên Bob không có gì để kiểm tra.")
    log.append(f"Bob tạo (b, B) và gửi B = {_short(b_pub)} cho Alice. Eve chặn B và gửi E cho Alice, giả làm Bob.")

    k_alice = key_exchange.derive_session_key(kex, a_priv, e_pub, INFO)   # Alice tưởng là khóa với Bob
    k_eve_a = key_exchange.derive_session_key(kex, e_priv, a_pub, INFO)   # Eve tính cùng khóa với Alice
    k_bob = key_exchange.derive_session_key(kex, b_priv, e_pub, INFO)     # Bob tưởng là khóa với Alice
    k_eve_b = key_exchange.derive_session_key(kex, e_priv, b_pub, INFO)   # Eve tính cùng khóa với Bob
    if k_alice != k_eve_a or k_bob != k_eve_b:
        raise RuntimeError("Hai phía tính ra khóa khác nhau: kiểm tra lại key_exchange.derive_session_key")

    log.append(f"Alice tính khóa K_AE từ (a, E). SHA-256 của khóa: {_fp(k_alice)[:24]}... "
               "Eve tính ra đúng khóa này từ (e, A).")
    log.append(f"Bob tính khóa K_EB từ (b, E). SHA-256 của khóa: {_fp(k_bob)[:24]}... "
               "Eve tính ra đúng khóa này từ (e, B).")
    log.append("Kết quả: Alice-Eve dùng khóa K_AE, Eve-Bob dùng khóa K_EB, và hai khóa này khác nhau. "
               "Không có khóa chung nào giữa Alice và Bob, nhưng mỗi người đều tưởng mình đang nói chuyện trực tiếp với người kia.")

    pkt = _seal(aead, k_alice, message, AAD)
    log.append(f"Alice mã hóa tin \"{message}\" bằng {aead} dưới K_AE (AAD = {AAD.decode()}, "
               f"nonce = {_short(pkt['nonce'], 6)}) và gửi cho Bob.")

    ok, eve_text = _open(aead, k_eve_a, pkt, AAD)
    if ok:
        log.append(f"Eve chặn gói tin và giải mã bằng K_AE: thẻ xác thực hợp lệ, Eve đọc được \"{eve_text}\".")
    else:
        log.append(f"Eve giải mã bằng K_AE thất bại: {eve_text}")

    bob_received = None
    if ok:
        pkt2 = _seal(aead, k_eve_b, forwarded, AAD)   # AAD là thông tin công khai nên Eve đặt lại được
        if modified_message is not None:
            log.append(f"Eve sửa nội dung thành \"{forwarded}\", mã hóa lại bằng K_EB (nonce mới) và chuyển cho Bob.")
        else:
            log.append("Eve giữ nguyên nội dung, mã hóa lại bằng K_EB (nonce mới) rồi chuyển cho Bob. "
                       "Eve hoàn toàn có thể sửa tin ở bước này.")
        ok_b, bob_received = _open(aead, k_bob, pkt2, AAD)
        if ok_b:
            log.append(f"Bob giải mã bằng K_EB thành công và nhận \"{bob_received}\". Bob không phát hiện được gì bất thường.")
        else:
            log.append(f"Bob giải mã thất bại: {bob_received}")
            bob_received = None

    log.append("Kết luận: DH thuần túy chỉ chống được kẻ nghe lén thụ động (không giải được logarit rời rạc/ECDLP). "
               "Nó không xác thực ai đang ở đầu bên kia nên không chống được kẻ tấn công chủ động.")

    return {
        "mode": MODE_UNAUTH,
        "attack_succeeded": bool(ok),
        "eve_read": eve_text if ok else None,
        "bob_received": bob_received,
        "keys": {"alice_eve": _fp(k_alice), "eve_bob": _fp(k_bob)},
        "log": log,
    }


# =========================================================================== #
# Chế độ 2: DH có chữ ký và chứng thư
# =========================================================================== #
def _blob(sender: str, receiver: str, eph_pub: bytes) -> bytes:
    """Dữ liệu được ký: ràng buộc giá trị DH với người gửi và người nhận."""
    return b"DH-AUTH|" + sender.encode() + b"|" + receiver.encode() + b"|" + eph_pub


def _make_hello(sender: str, receiver: str, eph_pub: bytes, sign_algo: str, sign_priv: str, cert: dict) -> dict:
    sig = signatures.sign(sign_algo, sign_priv, _blob(sender, receiver, eph_pub))
    return {"sender": sender, "receiver": receiver, "eph_pub": eph_pub, "signature": sig, "cert": cert}


def _check_hello(ca, hello: dict, expected_subject: str):
    """Người nhận kiểm tra theo thứ tự: chứng thư (CA -> tên chủ thể -> hạn -> CRL), rồi chữ ký. Trả (ok, bước, lý do)."""
    ok, reason = ca.verify(hello["cert"], expected_subject)
    if not ok:
        return False, "kiểm tra chứng thư", reason
    cert = hello["cert"]
    blob = _blob(hello["sender"], hello["receiver"], hello["eph_pub"])
    ok, reason = signatures.verify(cert["key_algo"], cert["public_key"], blob, hello["signature"])
    if not ok:
        return False, "kiểm tra chữ ký trên giá trị DH", reason
    return True, "", "hợp lệ"


def run_authenticated(message: str, ca, alice: dict, bob: dict, eve_has_cert: bool = False,
                      kex: str = "ecdh", aead: str = "AES-256-GCM") -> dict:
    """
    alice, bob: dict thực thể {"name","algo","private_pem","public_pem","fingerprint","cert"}.
    ca: đối tượng pki.CertificateAuthority (cần .verify và .issue).
    eve_has_cert: Eve xin CA một chứng thư HỢP LỆ cho tên "Eve" (câu hỏi C2).
    """
    _check_message(message)
    _require_identity(alice, "Alice")
    _require_identity(bob, "Bob")
    log: list[str] = []
    attempts: list[dict] = []

    # ---- Phần 1: bắt tay bình thường, Eve chỉ nghe ----
    log.append("Phần 1. Bắt tay bình thường, Eve chỉ quan sát đường truyền.")
    a_priv, a_pub = key_exchange.generate_ephemeral(kex)
    b_priv, b_pub = key_exchange.generate_ephemeral(kex)
    e_priv, e_pub = key_exchange.generate_ephemeral(kex)

    hello_a = _make_hello("Alice", "Bob", a_pub, alice["algo"], alice["private_pem"], alice["cert"])
    hello_b = _make_hello("Bob", "Alice", b_pub, bob["algo"], bob["private_pem"], bob["cert"])
    log.append(f"Alice tạo (a, A), ký (Alice, Bob, A) bằng khóa dài hạn {alice['algo']} và gửi kèm chứng thư. "
               f"A = {_short(a_pub)}, chữ ký {len(hello_a['signature'])} byte.")
    log.append(f"Bob tạo (b, B), ký (Bob, Alice, B) bằng khóa dài hạn {bob['algo']} và gửi kèm chứng thư. "
               f"B = {_short(b_pub)}, chữ ký {len(hello_b['signature'])} byte.")

    ok_b, step, reason = _check_hello(ca, hello_a, "Alice")
    log.append("Bob kiểm tra chuỗi tin cậy của Alice: CA -> chứng thư Alice -> chữ ký trên A. "
               + ("Kết quả: hợp lệ." if ok_b else f"Thất bại ở bước {step}: {reason}"))
    ok_a, step_a, reason_a = _check_hello(ca, hello_b, "Bob")
    log.append("Alice kiểm tra chuỗi tin cậy của Bob: CA -> chứng thư Bob -> chữ ký trên B. "
               + ("Kết quả: hợp lệ." if ok_a else f"Thất bại ở bước {step_a}: {reason_a}"))
    if not (ok_a and ok_b):
        raise ValueError("Bắt tay bình thường bị từ chối: hãy kiểm tra chứng thư của Alice và Bob còn hiệu lực "
                         f"và chưa bị thu hồi (lý do: {reason if not ok_b else reason_a})")

    k_alice = key_exchange.derive_session_key(kex, a_priv, b_pub, INFO)
    k_bob = key_exchange.derive_session_key(kex, b_priv, a_pub, INFO)
    if k_alice != k_bob:
        raise RuntimeError("Alice và Bob tính ra khóa khác nhau: kiểm tra lại key_exchange.derive_session_key")
    log.append(f"Cả hai tính cùng một khóa phiên. SHA-256 của khóa: {_fp(k_alice)[:24]}...")

    pkt = _seal(aead, k_alice, message, AAD)
    log.append(f"Alice mã hóa tin \"{message}\" bằng {aead} và gửi cho Bob (nonce = {_short(pkt['nonce'], 6)}).")
    k_guess = key_exchange.derive_session_key(kex, e_priv, a_pub, INFO)   # khóa Eve tính được từ giá trị công khai
    ok_e, why = _open(aead, k_guess, pkt, AAD)
    log.append("Eve thấy A, B, chữ ký, chứng thư và bản mã, nhưng không biết a hay b. Eve thử giải mã bằng khóa tính từ "
               + ("giá trị công khai: " + ("thành công (BẤT THƯỜNG)." if ok_e else f"thất bại ({why}).")))
    ok_bob, bob_text = _open(aead, k_bob, pkt, AAD)
    log.append(f"Bob giải mã thành công và nhận \"{bob_text}\"." if ok_bob else f"Bob giải mã thất bại: {bob_text}")
    eve_read = why if ok_e else None

    # ---- Phần 2: Eve tấn công chủ động, thay giá trị DH của Alice gửi cho Bob ----
    log.append("Phần 2. Eve tấn công chủ động: chặn gói bắt tay của Alice và thay giá trị DH bằng E của mình. "
               "Bob kiểm tra từng gói giả theo thứ tự chứng thư rồi chữ ký, với tên chủ thể mong đợi là Alice.")
    e_sig_priv, e_sig_pub = signatures.generate_keypair(alice["algo"])   # khóa dài hạn của Eve, CA chưa từng chứng nhận

    forged_cert = copy.deepcopy(alice["cert"])
    forged_cert["public_key"] = e_sig_pub                                 # Eve thay khóa trong chứng thư của Alice

    tries = [
        ("Cách 1: thay giá trị DH, giữ nguyên chữ ký và chứng thư của Alice",
         {**hello_a, "eph_pub": e_pub}),
        ("Cách 2: thay giá trị DH, tự ký bằng khóa của Eve nhưng đính kèm chứng thư thật của Alice",
         _make_hello("Alice", "Bob", e_pub, alice["algo"], e_sig_priv, alice["cert"])),
        ("Cách 3: giả mạo chứng thư, đổi khóa công khai trong chứng thư của Alice thành khóa của Eve",
         _make_hello("Alice", "Bob", e_pub, alice["algo"], e_sig_priv, forged_cert)),
    ]
    if eve_has_cert:
        eve_cert = ca.issue("Eve", e_sig_pub, alice["algo"])
        log.append("Eve xin CA cấp chứng thư hợp lệ cho chính mình (chủ thể \"Eve\", khóa công khai của Eve). CA cấp được.")
        tries.append(("Cách 4: dùng chứng thư hợp lệ của chính Eve, ký giá trị DH bằng khóa của Eve",
                      _make_hello("Alice", "Bob", e_pub, alice["algo"], e_sig_priv, eve_cert)))

    for name, hello in tries:
        ok, step, reason = _check_hello(ca, hello, "Alice")
        attempts.append({"name": name, "rejected": not ok, "stage": step, "reason": reason})
        if ok:
            log.append(f"{name}. CẢNH BÁO: Bob chấp nhận gói giả. Hãy kiểm tra lại pki.verify và signatures.verify.")
        else:
            log.append(f"{name}. Bob từ chối ở bước {step}: {reason}. Bob không tính khóa chung và dừng bắt tay.")

    succeeded = any(not a["rejected"] for a in attempts)
    log.append("Kết luận: Eve không thể thay giá trị DH mà không bị phát hiện. Chữ ký ràng buộc giá trị DH với khóa dài hạn, "
               "chứng thư ràng buộc khóa đó với tên chủ thể. Ngay cả chứng thư hợp lệ của Eve cũng vô dụng "
               "vì tên chủ thể trong đó là Eve, không phải Alice." if not succeeded else
               "Kết luận: tấn công thành công, cần xem lại cách cài đặt các bước kiểm tra.")

    return {
        "mode": MODE_AUTH,
        "attack_succeeded": succeeded,
        "eve_read": eve_read,
        "bob_received": bob_text if ok_bob else None,
        "keys": {"alice_bob": _fp(k_alice)},
        "attempts": attempts,
        "log": log,
    }


# --------------------------------------------------------------------------- #
# Chạy thử độc lập: python -m modules.mitm  (cần signatures, pki, key_exchange, encryption đã xong)
# --------------------------------------------------------------------------- #
def _demo() -> None:
    from . import pki

    algo = "Ed25519"
    ids = {}
    for n in ("CA", "Alice", "Bob"):
        priv, pub = signatures.generate_keypair(algo)
        ids[n] = {"name": n, "algo": algo, "private_pem": priv, "public_pem": pub, "cert": None}
    ca = pki.CertificateAuthority(ids["CA"]["private_pem"], ids["CA"]["public_pem"], algo)
    for n in ("Alice", "Bob"):
        ids[n]["cert"] = ca.issue(n, ids[n]["public_pem"], algo)

    for res in (run_unauthenticated("Chuyển khoản cho Bob 100.000 đồng"),
                run_authenticated("Chuyển khoản cho Bob 100.000 đồng", ca, ids["Alice"], ids["Bob"], eve_has_cert=True)):
        print(f"\n=== {res['mode']} | Eve thành công: {res['attack_succeeded']} | Eve đọc được: {res['eve_read']} ===")
        for i, line in enumerate(res["log"], 1):
            print(f"{i:2}. {line}")


if __name__ == "__main__":
    _demo()