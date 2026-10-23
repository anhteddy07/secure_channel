# Secure Channel — Kênh liên lạc an toàn (Bài thực hành số 2, Mật mã lý thuyết)

Ứng dụng web (Flask) mô phỏng kênh liên lạc giữa **Alice** và **Bob** qua một máy chủ trung gian không
đáng tin cậy (**Eve**). Chuỗi minh họa: tạo khóa → cấp chứng thư (mini-PKI) → thỏa thuận khóa (DH/ECDH + HKDF)
→ mã hóa có xác thực (AES-256-GCM / ChaCha20-Poly1305) → ký số, kèm mô phỏng tấn công người ở giữa (MITM).

## Chạy nhanh

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py                    # mở http://127.0.0.1:5000
```

> Lưu ý: chỉ cài `pycryptodome`, **không** cài cùng `pycrypto` (hai gói trùng namespace `Crypto`).

Chạy kiểm thử: `pytest tests/ -v`  ·  Chạy đo lường độc lập: `python -m benchmarks.run_benchmarks`

## Cấu trúc & phân công

| Đường dẫn | Phụ trách | Nội dung |
|---|---|---|
| `app.py` | Nhóm trưởng / tích hợp | Flask routes, giữ trạng thái trong bộ nhớ, gọi các module |
| `modules/hashing.py` | Người 1 | SHA-256/SHA-1/MD5, hiệu ứng thác, HMAC, đo thời gian băm |
| `modules/signatures.py` | Người 2 | Sinh khóa, dấu vân tay, ký/xác minh (RSA-PSS, ECDSA P-256, Ed25519) |
| `modules/pki.py` | Người 3 | CA tự ký, cấp chứng thư JSON, CRL, kiểm tra chứng thư |
| `modules/key_exchange.py` | Người 4 | DH số nhỏ, ECDH P-256, DH-2048, HKDF |
| `modules/encryption.py` | Người 4 | AES-256-GCM, ChaCha20-Poly1305 |
| `modules/mitm.py` | Người 5 | Mô phỏng MITM (không xác thực / có chữ ký + chứng thư) + nhật ký |
| `benchmarks/run_benchmarks.py` | Đã có sẵn | Đo ≥ 20 lần bằng pycryptodome trực tiếp (độc lập với module khác): sinh khóa/ký/kiểm tra, ECDH vs DH-2048, AES-GCM vs ChaCha20. Chạy riêng: `python -m benchmarks.run_benchmarks --runs 20` (khoảng 40 giây) |
| `templates/index.html`, `static/style.css`, `static/app.js` | Đã có sẵn | Giao diện 7 tab, chỉ gọi API của `app.py`; ai thêm chức năng thì thêm tab/nút tương ứng |
| `tests/` | Mỗi người test module của mình | Dùng bộ dữ liệu ở cuối file này |

Mỗi thư mục `modules/`, `benchmarks/`, `tests/` cần một file `__init__.py` (có thể rỗng).

## Hợp đồng giữa các module (QUAN TRỌNG — đừng tự đổi chữ ký hàm)

Nếu cần đổi, báo nhóm trưởng để sửa `app.py` cùng lúc. Quy ước chung: khóa là chuỗi **PEM**; dữ liệu nhị phân
ở mức module là `bytes`; nonce/ciphertext/tag trong `encryption` là chuỗi **hex**.

### `modules/hashing.py`
| Hàm | Trả về |
|---|---|
| `digest_all(data: bytes)` | `{"sha256": hex, "sha1": hex, "md5": hex}` |
| `avalanche(a: bytes, b: bytes)` | `{"hash_a", "hash_b", "diff_bits": int, "total_bits": 256}` |
| `hmac_sha256(key: bytes, msg: bytes)` | hex |
| `hmac_verify(key, msg, tag_hex: str)` | `bool` (dùng `hmac.compare_digest`) |
| `benchmark(data: bytes)` | `{"sha256": ms, "sha1": ms, "md5": ms}` |

### `modules/signatures.py`
| Hàm | Trả về |
|---|---|
| `ALGORITHMS` | `["RSA-PSS", "ECDSA-P256", "Ed25519"]` (tối thiểu 2) |
| `generate_keypair(algo: str)` | `(private_pem: str, public_pem: str)` |
| `fingerprint(public_pem: str)` | hex của 16 byte đầu SHA-256(khóa công khai) |
| `sign(algo, private_pem, message: bytes)` | `signature: bytes` (luôn băm rồi ký, RSA dùng PSS) |
| `verify(algo, public_pem, message, signature)` | `(valid: bool, reason: str)` — reason nêu rõ: hợp lệ / nội dung bị sửa / sai khóa / sai thuật toán |

### `modules/pki.py`
`class CertificateAuthority(private_pem, public_pem, algo, name="Root CA", valid_days=3650)`

| Thành viên | Ý nghĩa |
|---|---|
| `.root_cert` | chứng thư gốc tự ký (dict) |
| `.crl` | danh sách serial đã thu hồi |
| `.issue(subject, public_key_pem, key_algo, valid_days=365)` | cấp chứng thư; `valid_days < 0` → đã hết hạn (phục vụ demo) |
| `.revoke(serial: int)` | thêm vào CRL |
| `.verify(cert, expected_subject)` | `(ok: bool, reason: str)`; phải phân biệt 4 lỗi: **chữ ký CA sai / hết hạn / sai tên chủ thể / bị thu hồi** |

Định dạng chứng thư (JSON, ký trên `json.dumps(..., sort_keys=True)` của các trường trừ `signature`):

```json
{"subject": "Alice", "public_key": "<PEM>", "key_algo": "Ed25519",
 "not_before": "2026-10-23T00:00:00Z", "not_after": "2027-10-23T00:00:00Z",
 "serial": 1, "issuer": "Root CA", "sig_alg": "Ed25519", "signature": "<base64>"}
```
(`key_algo` và `sig_alg` là hai trường bổ sung so với đề để biết dùng thuật toán nào khi kiểm tra.)

### `modules/key_exchange.py`
| Hàm | Trả về |
|---|---|
| `toy_dh(p, g, a, b)` | `{"A", "B", "K_alice", "K_bob"}` (tự cài bằng `pow`; mẫu p=23, g=5, a=6, b=15 → A=8, B=19, K=2) |
| `generate_ephemeral(kind)` | `(private_obj, public_bytes)`, `kind` ∈ `"ecdh"` (P-256), `"dh2048"` (RFC 3526) |
| `derive_session_key(kind, my_private, peer_public_bytes, info: bytes)` | khóa phiên `bytes` 32 byte, qua HKDF-SHA256 |

### `modules/encryption.py`
| Hàm | Trả về |
|---|---|
| `AEADS` | `["AES-256-GCM", "ChaCha20-Poly1305"]` |
| `encrypt(aead, key, plaintext: bytes, aad: bytes)` | `{"nonce": hex (96 bit ngẫu nhiên), "ciphertext": hex, "tag": hex}` |
| `decrypt(aead, key, nonce_hex, ciphertext_hex, tag_hex, aad)` | `(ok: bool, plaintext: bytes \| str)`; lỗi → `"thẻ xác thực không hợp lệ"` |

### `modules/mitm.py`
| Hàm | Trả về |
|---|---|
| `run_unauthenticated(message: str)` | `{"mode", "log": [str, ...], "eve_read": str, "keys": {"alice_eve": sha256, "eve_bob": sha256}, "attack_succeeded": True}` |
| `run_authenticated(message, ca, alice, bob, eve_has_cert=False)` | cùng dạng; `attack_succeeded` phải là `False` và log nêu rõ Bob phát hiện ở bước nào |

`alice` / `bob` là dict thực thể: `{"name","algo","private_pem","public_pem","fingerprint","cert"}`.
Với `eve_has_cert=True`, Eve tự xin chứng thư hợp lệ cho tên "Eve"; Bob so tên chủ thể với "Alice" nên vẫn từ chối (câu hỏi C2).

### `benchmarks/run_benchmarks.py`
`run_all(runs: int)` → dict JSON-serializable gồm 3 nhóm:
`signatures` (RSA-2048, RSA-3072, ECDSA P-256: keygen/sign/verify ms, kích thước khóa/chữ ký),
`key_exchange` (ECDH P-256 vs DH-2048), `aead` (AES-256-GCM vs ChaCha20-Poly1305 trên 1 MB). Trả giá trị **trung bình** của `runs` lần đo.

## API do `app.py` cung cấp

Mọi response có dạng `{"ok": true, ...}` hoặc `{"ok": false, "error": "..."}` (HTTP 400/501/500).
Module chưa viết xong → endpoint tương ứng trả 501, các endpoint khác vẫn chạy.

| Endpoint | Chức năng |
|---|---|
| `POST /api/setup/demo` | Sinh khóa CA/Alice/Bob + khởi tạo CA + cấp chứng thư (một nút để demo nhanh) |
| `GET /api/state` | Khóa công khai, vân tay, chứng thư, CRL (không bao giờ có khóa riêng) |
| `POST /api/keys/generate` | `{entity, algo}` sinh cặp khóa |
| `POST /api/hash` · `/api/hash/avalanche` · `/api/hmac` · `GET /api/hash/benchmark` | Băm, hiệu ứng thác, HMAC, đo thời gian băm 10 MB |
| `POST /api/sign` · `/api/verify` | Ký / xác minh; `mode` = `normal`, `tamper_message`, `swap_signature`, `wrong_algo` |
| `POST /api/pki/init` · `/issue` · `/revoke` · `/verify` | Mini-PKI |
| `POST /api/dh/toy` | DH số nhỏ |
| `POST /api/message/send` | ECDH/DH-2048 → HKDF → AEAD; `tamper` = `none`, `flip_ciphertext`, `flip_aad` |
| `POST /api/mitm/unauth` · `/api/mitm/auth` | Hai chế độ MITM |
| `GET /api/benchmark?runs=20` | Bảng đo lường (tối thiểu 20 lần) |

Các endpoint băm/ký nhận JSON `{"text": "..."}` hoặc `multipart/form-data` với trường `file`.

## Bộ dữ liệu kiểm thử (dùng trong `tests/`)

| Nội dung | Đầu vào | Kết quả mong đợi |
|---|---|---|
| SHA-256 | `"abc"` | `ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad` |
| Hiệu ứng thác | `"abc"` vs `"abd"` | khác nhau 122/256 bit |
| HMAC-SHA256 | khóa `"key"`, `"The quick brown fox jumps over the lazy dog"` | `f7bc83f4 30538424 b13298e6 aa6fb143 ef4d59a1 49461759 97479dbc 2d1a3cd8` |
| DH số nhỏ | p=23, g=5, a=6, b=15 | A=8, B=19, K=2 |
| RSA số nhỏ (lý thuyết) | n=1247, e=59, d=299, m=20 | s=198; 198^59 mod 1247 = 20 |

## Quy ước làm việc với Git

- Mỗi người một nhánh: `feat/hashing`, `feat/signatures`, `feat/pki`, `feat/kex-enc`, `feat/mitm`; merge vào `main` qua Pull Request.
- **Không commit khóa riêng thật** hay file `.venv/`, `__pycache__/` (xem `.gitignore`).
- Không tự cài RSA/ECDSA/AES/SHA từ đầu (trừ phần DH số nhỏ và các phần "toy"); không ECB; không dùng MD5/SHA-1 cho bảo mật;
  không tái sử dụng (khóa, nonce) trong AEAD; khóa chung DH luôn qua HKDF.

## Sản phẩm nộp

File Word (Phần A, thiết kế + sơ đồ Alice–Eve–Bob, trả lời C1–C6), ảnh chụp màn hình (chữ ký hợp lệ/bị sửa; MITM hai chế độ;
bảng đo lường) và file `.zip` mã nguồn kèm README này.