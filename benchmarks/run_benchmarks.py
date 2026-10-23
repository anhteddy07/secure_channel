"""
benchmarks/run_benchmarks.py - Đo lường và so sánh (đề bài B.2.7).

Đo trung bình của `runs` lần (mặc định 20, đúng yêu cầu >= 20):
  1. Chữ ký: RSA-2048, RSA-3072 (RSA-PSS) và ECDSA P-256
     -> thời gian sinh khóa / ký / kiểm tra, kích thước khóa công khai và chữ ký.
  2. Thỏa thuận khóa: ECDH P-256 so với DH-2048 (nhóm RFC 3526 số 14).
  3. AEAD: AES-256-GCM so với ChaCha20-Poly1305 trên cùng thông điệp 1 MB.

Dùng trực tiếp pycryptodome để số đo độc lập với các module khác của nhóm.
Chạy riêng:  python -m benchmarks.run_benchmarks --runs 20
Dùng từ app:  run_all(runs) -> dict (xem README, mục hợp đồng).
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import statistics
import time

from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Hash import SHA256
from Crypto.Protocol.DH import key_agreement
from Crypto.PublicKey import ECC, RSA
from Crypto.Signature import DSS, pss

MESSAGE = b"A" * 1024            # thông điệp ký (băm rồi ký)
AEAD_SIZE = 1 << 20              # 1 MB theo đề bài
AAD = b"Alice|Bob|1"

# Nhóm MODP 2048 bit, RFC 3526 mục 3 (g = 2). p là số nguyên tố an toàn.
RFC3526_G14_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
DH_G = 2
DH_EXPONENT_BITS = 256           # số mũ riêng 256 bit (đủ cho ~128 bit an toàn, như thực tế)


def _mean_ms(fn, runs: int, warmup: int = 1) -> float:
    """Trung bình thời gian chạy fn() (ms) qua `runs` lần; bỏ qua `warmup` lần khởi động."""
    for _ in range(warmup):
        fn()
    samples = []
    for _ in range(runs):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1000.0)
    return statistics.fmean(samples)


# ------------------------------------------------------------------ chữ ký --
def _sign(kind: str, key, digest) -> bytes:
    if kind == "rsa":
        return pss.new(key).sign(digest)                     # RSA-PSS, không ký RSA thô
    return DSS.new(key, "fips-186-3").sign(digest)           # ECDSA P-256, chữ ký 64 byte


def _verify(kind: str, pub, digest, sig: bytes) -> None:
    if kind == "rsa":
        pss.new(pub).verify(digest, sig)
    else:
        DSS.new(pub, "fips-186-3").verify(digest, sig)


SIGNATURES = [
    ("RSA-2048", 2048, "rsa", lambda: RSA.generate(2048)),
    ("RSA-3072", 3072, "rsa", lambda: RSA.generate(3072)),
    ("ECDSA-P256", 256, "ecdsa", lambda: ECC.generate(curve="P-256")),
]


def bench_signatures(runs: int) -> list[dict]:
    out = []
    for label, bits, kind, gen in SIGNATURES:
        keygen_ms = _mean_ms(gen, runs, warmup=0)
        key = gen()
        pub = key.public_key()
        sig = _sign(kind, key, SHA256.new(MESSAGE))
        out.append({
            "algo": label,
            "key_bits": bits,
            "keygen_ms": keygen_ms,
            "sign_ms": _mean_ms(lambda: _sign(kind, key, SHA256.new(MESSAGE)), runs),
            "verify_ms": _mean_ms(lambda: _verify(kind, pub, SHA256.new(MESSAGE), sig), runs),
            "pub_key_bytes": len(pub.export_key(format="DER")),
            "sig_bytes": len(sig),
        })
    return out


# ---------------------------------------------------------- thỏa thuận khóa --
def bench_key_exchange(runs: int) -> list[dict]:
    """Chi phí của MỘT bên: sinh khóa tạm của mình + tính khóa chung với khóa công khai của đối phương."""
    peer_ecc = ECC.generate(curve="P-256").public_key()
    peer_dh = pow(DH_G, secrets.randbits(DH_EXPONENT_BITS) | 1, RFC3526_G14_P)

    def ecdh():
        mine = ECC.generate(curve="P-256")
        key_agreement(static_priv=mine, static_pub=peer_ecc, kdf=lambda z: z)

    def dh():
        x = secrets.randbits(DH_EXPONENT_BITS) | 1
        pow(DH_G, x, RFC3526_G14_P)           # khóa công khai g^x mod p
        pow(peer_dh, x, RFC3526_G14_P)        # khóa chung (g^y)^x mod p

    return [
        {"algo": "ECDH P-256", "time_ms": _mean_ms(ecdh, runs)},
        {"algo": "DH-2048", "time_ms": _mean_ms(dh, runs)},
    ]


# -------------------------------------------------------------------- AEAD --
AEADS = [
    ("AES-256-GCM", lambda key, nonce: AES.new(key, AES.MODE_GCM, nonce=nonce)),
    ("ChaCha20-Poly1305", lambda key, nonce: ChaCha20_Poly1305.new(key=key, nonce=nonce)),
]


def bench_aead(runs: int) -> list[dict]:
    key, data = os.urandom(32), os.urandom(AEAD_SIZE)
    out = []
    for label, make in AEADS:
        def enc():
            nonce = os.urandom(12)            # nonce 96 bit mới cho MỌI lần mã hóa
            c = make(key, nonce)
            c.update(AAD)
            ct, tag = c.encrypt_and_digest(data)
            return nonce, ct, tag

        nonce, ct, tag = enc()

        def dec():
            c = make(key, nonce)
            c.update(AAD)
            c.decrypt_and_verify(ct, tag)

        out.append({
            "algo": label,
            "message_bytes": AEAD_SIZE,
            "encrypt_ms": _mean_ms(enc, runs),
            "decrypt_ms": _mean_ms(dec, runs),
        })
    return out


# ------------------------------------------------------------------- tổng hợp --
def run_all(runs: int = 20) -> dict:
    runs = max(1, int(runs))
    return {
        "runs": runs,
        "signatures": bench_signatures(runs),
        "key_exchange": bench_key_exchange(runs),
        "aead": bench_aead(runs),
    }


def _print_table(title: str, rows: list[dict]) -> None:
    print(f"\n== {title} ==")
    cols = list(rows[0])
    print("  ".join(f"{c:>18}" for c in cols))
    for r in rows:
        print("  ".join(f"{(f'{v:.3f}' if isinstance(v, float) else v)!s:>18}" for v in r.values()))


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--runs", type=int, default=20, help="số lần đo mỗi phép (mặc định 20)")
    ap.add_argument("--json", action="store_true", help="in JSON thay vì bảng")
    args = ap.parse_args()
    result = run_all(args.runs)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"Số lần đo mỗi phép: {result['runs']} (đơn vị ms, giá trị trung bình)")
        _print_table("Chữ ký", result["signatures"])
        _print_table("Thỏa thuận khóa", result["key_exchange"])
        _print_table("AEAD (1 MB)", result["aead"])