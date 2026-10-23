"""
app.py - Điểm vào của ứng dụng "Kênh liên lạc an toàn" (Flask).

Vai trò: CHỈ là tầng ghép nối (glue). File này không tự cài đặt thuật toán mật mã nào;
nó nhận request từ giao diện web, gọi các hàm trong modules/ theo "hợp đồng" ghi trong
README.md, đo thời gian, rồi trả JSON về cho frontend.

Chạy:  python app.py   ->  http://127.0.0.1:5000
"""
from __future__ import annotations

import base64
import functools
import hashlib
import importlib
import os
import time

from flask import Flask, jsonify, render_template, request
from jinja2 import TemplateNotFound

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024 * 1024  # cho phép upload file tới 64 MB


# --------------------------------------------------------------------------- #
# 1. Nạp module một cách "chịu lỗi": module nào chưa viết xong thì app vẫn chạy,
#    chỉ riêng endpoint dùng module đó trả về HTTP 501. Giúp 5 người code song song.
# --------------------------------------------------------------------------- #
class _Missing:
    def __init__(self, name: str, err: Exception):
        self._name, self._err = name, err

    def __getattr__(self, attr):
        raise NotImplementedError(f"Module '{self._name}' chưa sẵn sàng: {self._err}")


def _load(path: str):
    try:
        return importlib.import_module(path)
    except ImportError as e:
        print(f"[WARN] Không nạp được {path}: {e}")
        return _Missing(path, e)


hashing = _load("modules.hashing")            # Người 1
signatures = _load("modules.signatures")      # Người 2
pki = _load("modules.pki")                    # Người 3
key_exchange = _load("modules.key_exchange")  # Người 4
encryption = _load("modules.encryption")      # Người 4
mitm = _load("modules.mitm")                  # Người 5
benchmarks = _load("benchmarks.run_benchmarks")

# --------------------------------------------------------------------------- #
# 2. Trạng thái trong bộ nhớ (đề cho phép, không cần database)
# --------------------------------------------------------------------------- #
ENTITIES = ("CA", "Alice", "Bob")
STATE = {
    "keys": {},   # tên -> {"name","algo","private_pem","public_pem","fingerprint","cert"}
    "ca": None,   # đối tượng pki.CertificateAuthority
    "seq": 0,     # số thứ tự tin nhắn (đưa vào AAD)
}


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def b64d(s: str) -> bytes:
    return base64.b64decode(s)


def flip_bit(data: bytes, bit: int = 0) -> bytes:
    """Đảo 1 bit ở byte đầu tiên (dùng cho các nút 'sửa 1 bit/1 byte')."""
    if not data:
        return b"\x00"
    out = bytearray(data)
    out[0] ^= 1 << bit
    return bytes(out)


def timed(fn, *args, **kwargs):
    t0 = time.perf_counter()
    out = fn(*args, **kwargs)
    return out, (time.perf_counter() - t0) * 1000.0  # ms


def public_view(ent: dict) -> dict:
    """Chỉ trả phần CÔNG KHAI của một thực thể. TUYỆT ĐỐI không trả private_pem."""
    return {k: ent[k] for k in ("name", "algo", "public_pem", "fingerprint", "cert")}


def get_entity(name: str) -> dict:
    ent = STATE["keys"].get(name)
    if ent is None:
        raise ValueError(f"Chưa sinh khóa cho {name}")
    return ent


def get_ca():
    if STATE["ca"] is None:
        raise ValueError("Chưa khởi tạo CA (gọi /api/pki/init trước)")
    return STATE["ca"]


def get_params() -> dict:
    """Hỗ trợ cả JSON lẫn multipart/form-data (khi có upload file)."""
    if request.files or request.form:
        return request.form.to_dict()
    return request.get_json(silent=True) or {}


def get_input_bytes(p: dict) -> bytes:
    """Lấy dữ liệu đầu vào: ưu tiên file tải lên, nếu không thì trường 'text'."""
    f = request.files.get("file")
    if f is not None:
        return f.read()
    return p["text"].encode("utf-8")


def api(fn):
    """Bọc endpoint: trả {"ok": true, ...} hoặc {"ok": false, "error": ...} với mã HTTP phù hợp."""
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return jsonify({"ok": True, **fn(*args, **kwargs)})
        except NotImplementedError as e:
            return jsonify(ok=False, error=str(e)), 501
        except KeyError as e:
            return jsonify(ok=False, error=f"Thiếu tham số: {e}"), 400
        except ValueError as e:
            return jsonify(ok=False, error=str(e)), 400
        except Exception as e:  # noqa: BLE001 - app demo, trả lỗi để dễ debug
            return jsonify(ok=False, error=f"{type(e).__name__}: {e}"), 500
    return wrapper


# --------------------------------------------------------------------------- #
# 3. Các hàm dùng chung (endpoint lẻ và /api/setup/demo cùng gọi)
# --------------------------------------------------------------------------- #
def gen_entity(name: str, algo: str) -> dict:
    if name not in ENTITIES:
        raise ValueError(f"Thực thể phải là một trong {ENTITIES}")
    priv, pub = signatures.generate_keypair(algo)
    ent = {
        "name": name, "algo": algo, "private_pem": priv, "public_pem": pub,
        "fingerprint": signatures.fingerprint(pub), "cert": None,
    }
    STATE["keys"][name] = ent
    if name == "CA":
        STATE["ca"] = None  # khóa CA đổi -> phải khởi tạo lại CA, chứng thư cũ vô hiệu
    return ent


def init_ca():
    ca_key = get_entity("CA")
    STATE["ca"] = pki.CertificateAuthority(
        ca_key["private_pem"], ca_key["public_pem"], ca_key["algo"]
    )
    ca_key["cert"] = STATE["ca"].root_cert
    return STATE["ca"]


def issue_cert(subject: str, valid_days: int = 365) -> dict:
    if subject == "CA":
        raise ValueError("CA dùng chứng thư tự ký (gọi /api/pki/init)")
    ent = get_entity(subject)
    ent["cert"] = get_ca().issue(subject, ent["public_pem"], ent["algo"], valid_days)
    return ent["cert"]


# --------------------------------------------------------------------------- #
# 4. Routes
# --------------------------------------------------------------------------- #
@app.get("/")
def index():
    try:
        return render_template("index.html")
    except TemplateNotFound:
        routes = sorted(r.rule for r in app.url_map.iter_rules() if r.rule.startswith("/api"))
        return "<h3>Chưa có templates/index.html</h3><pre>" + "\n".join(routes) + "</pre>"


@app.get("/api/state")
@api
def state():
    return {
        "entities": {n: public_view(e) for n, e in STATE["keys"].items()},
        "crl": list(STATE["ca"].crl) if STATE["ca"] else [],
        "algorithms": list(getattr(signatures, "ALGORITHMS", [])),
    }


@app.post("/api/setup/demo")
@api
def setup_demo():
    """Một nút: sinh khóa CA/Alice/Bob, khởi tạo CA, cấp chứng thư cho Alice và Bob."""
    algo = get_params().get("algo", "Ed25519")
    for name in ENTITIES:
        gen_entity(name, algo)
    init_ca()
    issue_cert("Alice")
    issue_cert("Bob")
    return {"entities": {n: public_view(e) for n, e in STATE["keys"].items()}}


# ---- B.2.1 Sinh khóa ------------------------------------------------------- #
@app.post("/api/keys/generate")
@api
def keys_generate():
    p = get_params()
    ent, ms = timed(gen_entity, p["entity"], p.get("algo", "Ed25519"))
    return {**public_view(ent), "keygen_ms": ms}


# ---- B.2.2 Hàm băm / HMAC / hiệu ứng thác ---------------------------------- #
@app.post("/api/hash")
@api
def hash_route():
    data = get_input_bytes(get_params())
    return {
        "digests": hashing.digest_all(data),  # {"sha256","sha1","md5"} dạng hex
        "warning": "MD5 và SHA-1 chỉ để so sánh, KHÔNG dùng cho mục đích bảo mật.",
    }


@app.post("/api/hash/avalanche")
@api
def hash_avalanche():
    p = get_params()
    a = p["text"]
    if "text_b" in p:
        b = p["text_b"]
    else:  # mặc định: tăng ký tự cuối lên 1 ("abc" -> "abd")
        b = a[:-1] + chr(ord(a[-1]) + 1)
    res = hashing.avalanche(a.encode(), b.encode())
    return {"text_a": a, "text_b": b, **res}  # hash_a, hash_b, diff_bits, total_bits


@app.post("/api/hmac")
@api
def hmac_route():
    p = get_params()
    key, msg = p["key"].encode(), p["text"].encode()
    out = {"tag": hashing.hmac_sha256(key, msg)}
    if p.get("tag"):  # so sánh thẻ đúng/sai bằng hmac.compare_digest (nằm trong module)
        out["tag_match"] = hashing.hmac_verify(key, msg, p["tag"])
    return out


@app.get("/api/hash/benchmark")
@api
def hash_benchmark():
    data = os.urandom(10 * 1024 * 1024)  # file 10 MB theo đề bài
    return {"size_mb": 10, "times_ms": hashing.benchmark(data)}  # {"sha256": ms, ...}


# ---- B.2.3 Ký số / xác minh ------------------------------------------------ #
@app.post("/api/sign")
@api
def sign_route():
    p = get_params()
    ent = get_entity(p["signer"])
    sig, ms = timed(signatures.sign, ent["algo"], ent["private_pem"], get_input_bytes(p))
    return {"signature": b64e(sig), "size_bytes": len(sig), "sign_ms": ms, "algo": ent["algo"]}


@app.post("/api/verify")
@api
def verify_route():
    """
    mode: normal | tamper_message | swap_signature | wrong_algo
    'signer' là người mà ta dùng KHÓA CÔNG KHAI để kiểm tra.
    """
    p = get_params()
    ent = get_entity(p["signer"])
    msg, sig = get_input_bytes(p), b64d(p["signature"])
    algo, mode = ent["algo"], p.get("mode", "normal")

    if mode == "tamper_message":      # sửa 1 byte của thông điệp
        msg = flip_bit(msg)
    elif mode == "swap_signature":    # thay bằng chữ ký của người khác trên cùng thông điệp
        other = next((e for n, e in STATE["keys"].items()
                      if n != p["signer"] and n != "CA"), None)
        if other is None:
            raise ValueError("Cần sinh khóa cho ít nhất 2 người dùng để thử 'thay chữ ký'")
        sig = signatures.sign(other["algo"], other["private_pem"], get_input_bytes(p))
    elif mode == "wrong_algo":        # kiểm tra bằng thuật toán sai
        algo = next(a for a in signatures.ALGORITHMS if a != algo)
    elif mode != "normal":
        raise ValueError(f"mode không hợp lệ: {mode}")

    (valid, reason), ms = timed(signatures.verify, algo, ent["public_pem"], msg, sig)
    # reason: chuỗi nêu rõ "nội dung bị sửa" / "sai khóa" / "sai thuật toán" / "hợp lệ"
    return {"valid": valid, "reason": reason, "verify_ms": ms, "mode": mode}


# ---- B.2.4 Mini-PKI -------------------------------------------------------- #
@app.post("/api/pki/init")
@api
def pki_init():
    ca = init_ca()
    return {"root_cert": ca.root_cert}


@app.post("/api/pki/issue")
@api
def pki_issue():
    """valid_days âm (ví dụ -1) để tạo chứng thư đã hết hạn phục vụ demo lỗi."""
    p = get_params()
    return {"cert": issue_cert(p["subject"], int(p.get("valid_days", 365)))}


@app.post("/api/pki/revoke")
@api
def pki_revoke():
    ca = get_ca()
    ca.revoke(int(get_params()["serial"]))
    return {"crl": list(ca.crl)}


@app.post("/api/pki/verify")
@api
def pki_verify():
    """
    Body: {"cert": {...}  (hoặc "of": "Alice" để lấy chứng thư đã cấp),
           "expected_subject": "Alice"}
    Frontend có thể cho sửa JSON của cert trước khi gửi để demo lỗi 'chữ ký CA sai'.
    """
    p = get_params()
    cert = p["cert"] if "cert" in p else get_entity(p["of"])["cert"]
    ok, reason = get_ca().verify(cert, p["expected_subject"])
    return {"valid": ok, "reason": reason}  # 4 lỗi: chữ ký sai / hết hạn / sai tên / bị thu hồi


# ---- B.2.5 Thỏa thuận khóa + mã hóa lai ------------------------------------ #
@app.post("/api/dh/toy")
@api
def dh_toy():
    p = get_params()
    args = (int(p.get("p", 23)), int(p.get("g", 5)), int(p.get("a", 6)), int(p.get("b", 15)))
    return key_exchange.toy_dh(*args)  # {"A","B","K_alice","K_bob"}; mẫu: A=8, B=19, K=2


@app.post("/api/message/send")
@api
def message_send():
    """
    Alice -> Bob: (ECDH | DH-2048) -> HKDF -> AEAD(AAD = 'sender|receiver|seq').
    tamper: none | flip_ciphertext | flip_aad
    """
    p = get_params()
    sender, receiver = p.get("sender", "Alice"), p.get("receiver", "Bob")
    kex, aead, tamper = p.get("kex", "ecdh"), p.get("aead", "AES-256-GCM"), p.get("tamper", "none")
    info = f"secure_channel|{sender}->{receiver}".encode()

    a_priv, a_pub = key_exchange.generate_ephemeral(kex)
    b_priv, b_pub = key_exchange.generate_ephemeral(kex)
    k_send = key_exchange.derive_session_key(kex, a_priv, b_pub, info)  # 32 byte
    k_recv = key_exchange.derive_session_key(kex, b_priv, a_pub, info)

    STATE["seq"] += 1
    aad = f"{sender}|{receiver}|{STATE['seq']}".encode()
    pkt, enc_ms = timed(encryption.encrypt, aead, k_send, p["text"].encode(), aad)

    ct, aad_rx = bytes.fromhex(pkt["ciphertext"]), aad
    if tamper == "flip_ciphertext":
        ct = flip_bit(ct)
    elif tamper == "flip_aad":
        aad_rx = flip_bit(aad)

    (ok, out), dec_ms = timed(
        encryption.decrypt, aead, k_recv, pkt["nonce"], ct.hex(), pkt["tag"], aad_rx
    )
    return {
        "aead": aead, "kex": kex, "tamper": tamper,
        "keys_equal": k_send == k_recv,
        "session_key_sha256": hashlib.sha256(k_send).hexdigest(),  # chỉ hiển thị dạng băm
        "aad": aad.decode(), "nonce": pkt["nonce"], "ciphertext": pkt["ciphertext"],
        "tag": pkt["tag"], "decrypt_ok": ok,
        "plaintext": out.decode("utf-8", "replace") if ok else None,
        "error": None if ok else "thẻ xác thực không hợp lệ",
        "encrypt_ms": enc_ms, "decrypt_ms": dec_ms,
    }


# ---- B.2.6 MITM ------------------------------------------------------------ #
@app.post("/api/mitm/unauth")
@api
def mitm_unauth():
    return mitm.run_unauthenticated(get_params().get("message", "Xin chào Bob"))


@app.post("/api/mitm/auth")
@api
def mitm_auth():
    """eve_has_cert=true: Eve có chứng thư hợp lệ của CHÍNH Eve (câu hỏi C2)."""
    p = get_params()
    for n in ("Alice", "Bob"):
        if get_entity(n)["cert"] is None:
            raise ValueError(f"{n} chưa có chứng thư (gọi /api/setup/demo hoặc /api/pki/issue)")
    return mitm.run_authenticated(
        p.get("message", "Xin chào Bob"), get_ca(),
        get_entity("Alice"), get_entity("Bob"),
        eve_has_cert=str(p.get("eve_has_cert", "false")).lower() == "true",
    )


# ---- B.2.7 Đo lường -------------------------------------------------------- #
@app.get("/api/benchmark")
@api
def benchmark_route():
    runs = max(20, int(request.args.get("runs", 20)))  # đề yêu cầu >= 20 lần đo
    return {"runs": runs, "results": benchmarks.run_all(runs)}


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)