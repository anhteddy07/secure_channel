/* Giao diện "Kênh liên lạc an toàn": chỉ gọi API của app.py, không tự xử lý mật mã. */
(() => {
  'use strict';
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const esc = s => String(s ?? '').replace(/[&<>"']/g,
    c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const ENT = ['CA', 'Alice', 'Bob'];
  const DEFAULT_ALGOS = ['RSA-PSS', 'ECDSA-P256', 'Ed25519'];
  let S = { entities: {}, crl: [], algorithms: DEFAULT_ALGOS };
  let lastSig = null;

  /* ---------- Gọi API ---------- */
  async function api(path, body) {
    let opt = {};
    if (body instanceof FormData) opt = { method: 'POST', body };
    else if (body !== undefined) {
      opt = { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) };
    }
    const r = await fetch(path, opt);
    let j;
    try { j = await r.json(); } catch { throw new Error(`Server trả về dữ liệu không phải JSON (HTTP ${r.status})`); }
    if (!j.ok) throw new Error(j.error || `Lỗi HTTP ${r.status}`);
    return j;
  }
  // Gom đầu vào văn bản/file của một khung (prefix 'h' hoặc 's'); có file thì gửi multipart.
  function input(prefix, extra = {}) {
    const f = $(`#${prefix}-file`).files[0];
    if (f) {
      const fd = new FormData();
      fd.append('file', f);
      Object.entries(extra).forEach(([k, v]) => fd.append(k, v));
      return fd;
    }
    return { text: $(`#${prefix}-text`).value, ...extra };
  }

  /* ---------- Hiển thị ---------- */
  const num = (v, d = 2) => (+v).toFixed(d);
  const ms = v => `${num(v, v < 10 ? 3 : 1)} ms`;
  const badge = (ok, t) => `<span class="badge ${ok ? 'ok' : 'bad'}">${esc(t)}</span>`;
  const table = rows => '<table class="kv">' + rows.map(([k, v, raw]) =>
    `<tr><th>${esc(k)}</th><td>${raw ? v : esc(v)}</td></tr>`).join('') + '</table>';
  const grid = (head, rows) => '<table class="grid"><thead><tr>' + head.map(h => `<th>${esc(h)}</th>`).join('')
    + '</tr></thead><tbody>' + rows.map(r => '<tr>' + r.map(c => `<td>${esc(c)}</td>`).join('') + '</tr>').join('')
    + '</tbody></table>';
  const bars = (title, items, unit) => {
    const max = Math.max(...items.map(i => i.v)) || 1;
    return `<h4>${esc(title)}</h4>` + items.map(i => `<div class="bar"><span>${esc(i.l)}</span>`
      + `<span class="tr"><i style="width:${Math.max(2, i.v / max * 100)}%"></i></span>`
      + `<span class="vl">${num(i.v)} ${unit}</span></div>`).join('');
  };
  const show = (sel, html) => { $(sel).innerHTML = html; };
  let tt;
  function toast(m, bad) {
    const t = $('#toast');
    t.textContent = m; t.className = 'show' + (bad ? ' bad' : '');
    clearTimeout(tt); tt = setTimeout(() => { t.className = ''; }, 3800);
  }
  // Gắn hành động cho nút: hiện "đang xử lý", hiện kết quả HTML hoặc lỗi.
  function act(btn, out, fn, wait = 'Đang xử lý...') {
    $(btn).addEventListener('click', async ev => {
      const b = ev.currentTarget;
      b.disabled = true; show(out, `<span class="muted">${wait}</span>`);
      try { show(out, await fn()); }
      catch (e) { show(out, `<div class="err">${esc(e.message)}</div>`); }
      finally { b.disabled = false; }
    });
  }
  // Hành động không có vùng kết quả riêng (báo bằng toast).
  async function run(fn) { try { await fn(); } catch (e) { toast(e.message, true); } }

  /* ---------- Điều hướng ---------- */
  function openTab(name) {
    $$('.side [data-tab]').forEach(b => b.classList.toggle('on', b.dataset.tab === name));
    $$('.tab').forEach(s => s.classList.toggle('on', s.id === 'tab-' + name));
  }
  $$('.side [data-tab]').forEach(b => b.addEventListener('click', () => {
    openTab(b.dataset.tab); history.replaceState(null, '', '#' + b.dataset.tab);
  }));
  if ($(`.side [data-tab="${location.hash.slice(1)}"]`)) openTab(location.hash.slice(1));

  /* ---------- Trạng thái và thẻ khóa ---------- */
  async function refresh() {
    try {
      const j = await api('/api/state');
      S = { entities: j.entities, crl: j.crl, algorithms: j.algorithms.length ? j.algorithms : DEFAULT_ALGOS };
      $('#status').textContent = ''; $('#status').className = 'muted small';
    } catch (e) {
      $('#status').textContent = e.message; $('#status').className = 'warn small';
    }
    renderEntities(); loadCertBox();
  }
  function fillAlgos() {
    $$('select.algo').forEach(s => {
      const cur = s.value;
      s.innerHTML = S.algorithms.map(a => `<option>${esc(a)}</option>`).join('');
      if (cur) s.value = cur;
    });
  }
  function renderEntities() {
    $('#entities').innerHTML = ENT.map(n => {
      const e = S.entities[n];
      const body = e
        ? table([['Thuật toán', e.algo], ['Dấu vân tay', e.fingerprint],
          ['Chứng thư', e.cert ? `serial ${e.cert.serial}, hết hạn ${e.cert.not_after}` : 'chưa có']])
          + `<details><summary>Khóa công khai</summary><pre>${esc(e.public_pem)}</pre></details>`
          + (e.cert ? `<details><summary>Chứng thư (JSON)</summary><pre>${esc(JSON.stringify(e.cert, null, 2))}</pre></details>` : '')
        : '<p class="muted">Chưa có khóa.</p>';
      return `<article class="ent ${n.toLowerCase()}"><h3>${n}</h3><div class="row">`
        + `<select class="algo" data-ent="${n}"></select><button data-gen="${n}">Sinh khóa</button></div>${body}</article>`;
    }).join('');
    fillAlgos();
    ENT.forEach(n => { if (S.entities[n]) $(`select[data-ent="${n}"]`).value = S.entities[n].algo; });
    $$('[data-gen]').forEach(b => b.addEventListener('click', () => run(async () => {
      const n = b.dataset.gen;
      const j = await api('/api/keys/generate', { entity: n, algo: $(`select[data-ent="${n}"]`).value });
      await refresh();
      toast(`${n}: đã sinh khóa ${j.algo} trong ${ms(j.keygen_ms)}`);
    })));
  }
  $('#btn-demo').addEventListener('click', () => run(async () => {
    await api('/api/setup/demo', { algo: $('#demo-algo').value });
    await refresh(); toast('Đã sinh khóa, khởi tạo CA và cấp chứng thư cho Alice và Bob');
  }));
  $('#btn-ca').addEventListener('click', () => run(async () => {
    await api('/api/pki/init', {}); await refresh(); toast('CA đã tự ký chứng thư gốc');
  }));
  [['#btn-issue-a', 'Alice'], ['#btn-issue-b', 'Bob']].forEach(([sel, n]) =>
    $(sel).addEventListener('click', () => run(async () => {
      await api('/api/pki/issue', { subject: n, valid_days: 365 }); await refresh(); toast(`Đã cấp chứng thư cho ${n}`);
    })));

  /* ---------- Băm, HMAC, hiệu ứng thác ---------- */
  act('#h-go', '#h-out', async () => {
    const j = await api('/api/hash', input('h')), d = j.digests;
    return table([['SHA-256', d.sha256], ['SHA-1 (chỉ để so sánh)', d.sha1], ['MD5 (chỉ để so sánh)', d.md5]])
      + `<p class="warn-t">${esc(j.warning)}</p>`;
  });
  const bitsGrid = (a, b) => {
    const bin = h => [...h].map(c => parseInt(c, 16).toString(2).padStart(4, '0')).join('');
    const x = bin(a), y = bin(b);
    return '<div class="bits" aria-hidden="true">' + [...x].map((c, i) => `<i class="${c !== y[i] ? 'd' : ''}"></i>`).join('') + '</div>'
      + '<p class="muted small">Mỗi ô là một bit của SHA-256; ô đỏ là bit khác nhau.</p>';
  };
  act('#h-av', '#h-out2', async () => {
    const j = await api('/api/hash/avalanche', { text: $('#h-text').value, text_b: $('#h-textb').value || undefined });
    return table([['Văn bản A', j.text_a], ['Văn bản B', j.text_b], ['Băm của A', j.hash_a], ['Băm của B', j.hash_b],
      ['Số bit khác nhau', `${j.diff_bits} trên ${j.total_bits} (${num(j.diff_bits / j.total_bits * 100, 1)}%), kỳ vọng khoảng 128`]])
      + bitsGrid(j.hash_a, j.hash_b);
  });
  act('#h-hmac', '#h-out3', async () => {
    const j = await api('/api/hmac', { key: $('#h-key').value, text: $('#h-text').value, tag: $('#h-tag').value.trim() || undefined });
    const rows = [['HMAC-SHA256', j.tag]];
    if (j.tag_match !== undefined) rows.push(['So sánh thẻ', badge(j.tag_match, j.tag_match ? 'Thẻ đúng' : 'Thẻ sai'), true]);
    return table(rows);
  });
  act('#h-bench', '#h-out4', async () => {
    const j = await api('/api/hash/benchmark');
    return grid(['Hàm băm', `Thời gian cho ${j.size_mb} MB`], Object.entries(j.times_ms).map(([k, v]) => [k.toUpperCase(), ms(v)]));
  }, 'Đang băm 10 MB...');

  /* ---------- Ký số ---------- */
  act('#s-sign', '#s-out', async () => {
    const signer = $('#s-signer').value;
    const j = await api('/api/sign', input('s', { signer }));
    lastSig = j.signature; $('#s-vsigner').value = signer;
    return table([['Người ký', signer], ['Thuật toán', j.algo], ['Kích thước chữ ký', `${j.size_bytes} byte`],
      ['Thời gian ký', ms(j.sign_ms)], ['Chữ ký (base64)', j.signature]]);
  });
  $$('.vbtn').forEach(b => b.addEventListener('click', async () => {
    if (!lastSig) { toast('Hãy ký thông điệp trước khi xác minh', true); return; }
    $$('.vbtn').forEach(x => { x.disabled = true; });
    try {
      const j = await api('/api/verify', input('s', { signer: $('#s-vsigner').value, signature: lastSig, mode: b.dataset.mode }));
      show('#s-out2', badge(j.valid, j.valid ? 'Chữ ký hợp lệ' : 'Chữ ký không hợp lệ')
        + table([['Lý do', j.reason], ['Thao tác', b.textContent], ['Thời gian kiểm tra', ms(j.verify_ms)]]));
    } catch (e) { show('#s-out2', `<div class="err">${esc(e.message)}</div>`); }
    $$('.vbtn').forEach(x => { x.disabled = false; });
  }));

  /* ---------- Mini-PKI ---------- */
  const pv = (cert, exp) => api('/api/pki/verify', { cert, expected_subject: exp });
  const issue = (n, days = 365) => api('/api/pki/issue', { subject: n, valid_days: days }).then(j => j.cert);
  const verdict = j => badge(j.valid, j.valid ? 'Hợp lệ' : 'Bị từ chối');
  function loadCertBox() {
    const e = S.entities[$('#p-subject').value];
    $('#p-json').value = e && e.cert ? JSON.stringify(e.cert, null, 2) : '';
    $('#p-exp').value = $('#p-subject').value;
  }
  $('#p-subject').addEventListener('change', loadCertBox);
  $('#p-issue').addEventListener('click', () => run(async () => {
    const n = $('#p-subject').value;
    await issue(n, +$('#p-days').value); await refresh(); toast(`Đã cấp chứng thư mới cho ${n}`);
  }));
  act('#p-scen', '#p-out', async () => {
    const n = $('#p-subject').value, o = n === 'Alice' ? 'Bob' : 'Alice', rows = [];
    await refresh();
    if (!S.entities[o]) throw new Error(`Cần sinh khóa cho cả Alice và Bob (hãy dùng Thiết lập nhanh)`);
    let c = await issue(n);
    rows.push(['Chứng thư bình thường', await pv(c, n)]);
    rows.push(['Lỗi 1: chứng thư bị sửa (thay khóa công khai)', await pv({ ...c, public_key: S.entities[o].public_pem }, n)]);
    c = await issue(n, -1);
    rows.push(['Lỗi 2: hết hạn', await pv(c, n)]);
    c = await issue(n);
    rows.push([`Lỗi 3: sai tên chủ thể (mong đợi ${o})`, await pv(c, o)]);
    await api('/api/pki/revoke', { serial: c.serial });
    rows.push([`Lỗi 4: bị thu hồi (serial ${c.serial} nằm trong CRL)`, await pv(c, n)]);
    await issue(n); await refresh();
    return '<table class="grid"><thead><tr><th>Tình huống</th><th>Kết quả</th><th>Lý do server báo</th></tr></thead><tbody>'
      + rows.map(([t, j]) => `<tr><td>${esc(t)}</td><td>${verdict(j)}</td><td>${esc(j.reason)}</td></tr>`).join('')
      + `</tbody></table><p class="muted small">CRL hiện tại: ${esc(JSON.stringify(S.crl))}. Chứng thư hợp lệ mới đã được cấp lại cho ${esc(n)}.</p>`;
  }, 'Đang chạy bốn tình huống...');
  act('#p-verify', '#p-out2', async () => {
    let cert;
    try { cert = JSON.parse($('#p-json').value); } catch { throw new Error('Nội dung trong khung không phải JSON hợp lệ'); }
    const j = await pv(cert, $('#p-exp').value);
    return `${verdict(j)}<p>${esc(j.reason)}</p>`;
  });

  /* ---------- Trao khóa và mã hóa ---------- */
  act('#d-go', '#d-out', async () => {
    const v = id => $(id).value;
    const j = await api('/api/dh/toy', { p: v('#d-p'), g: v('#d-g'), a: v('#d-a'), b: v('#d-b') });
    return table(Object.entries(j).filter(([k]) => k !== 'ok').map(([k, x]) => [k, x]));
  });
  const msgHtml = j => `<div><h4>${esc(j.aead)} với ${j.kex === 'ecdh' ? 'ECDH P-256' : 'DH-2048'}</h4>` + table([
    ['AAD', j.aad], ['Nonce (96 bit)', j.nonce], ['Bản mã', j.ciphertext], ['Thẻ xác thực', j.tag],
    ['Khóa phiên (SHA-256)', j.session_key_sha256], ['Hai bên cùng khóa', j.keys_equal ? 'có' : 'không'],
    ['Thao tác phá', j.tamper], ['Giải mã', j.decrypt_ok
      ? badge(true, 'Thành công') + ' ' + esc(j.plaintext) : badge(false, 'Bị từ chối') + ' ' + esc(j.error), true],
    ['Thời gian', `mã hóa ${ms(j.encrypt_ms)}, giải mã ${ms(j.decrypt_ms)}`]]) + '</div>';
  const send = (aead, tamper) => api('/api/message/send',
    { text: $('#e-text').value, kex: $('#e-kex').value, aead, tamper });
  $$('.sbtn').forEach(b => b.addEventListener('click', async () => {
    $$('.sbtn,#e-cmp').forEach(x => { x.disabled = true; });
    try { show('#e-out', msgHtml(await send($('#e-aead').value, b.dataset.t))); }
    catch (e) { show('#e-out', `<div class="err">${esc(e.message)}</div>`); }
    $$('.sbtn,#e-cmp').forEach(x => { x.disabled = false; });
  }));
  act('#e-cmp', '#e-out', async () => {
    const [a, c] = [await send('AES-256-GCM', 'none'), await send('ChaCha20-Poly1305', 'none')];
    return `<div class="grid2">${msgHtml(a)}${msgHtml(c)}</div>`;
  });

  /* ---------- MITM ---------- */
  function mitmHtml(j) {
    const ok = j.attack_succeeded;
    $('#chan').dataset.state = ok ? 'intercepted' : 'blocked';
    $('#eve-note').textContent = ok ? 'đọc được tin' : 'bị phát hiện';
    const keys = j.keys && Object.keys(j.keys).length ? table(Object.entries(j.keys)) : '';
    return `<p>${badge(!ok, ok ? 'Tấn công thành công, Eve đọc được tin' : 'Tấn công thất bại')}</p>`
      + table([['Chế độ', j.mode || ''], ['Eve đọc được', j.eve_read ?? 'không đọc được gì']]) + keys
      + '<h4>Nhật ký từng bước</h4><ol class="log">' + (j.log || []).map(l => `<li>${esc(l)}</li>`).join('') + '</ol>';
  }
  act('#m-un', '#m-out', async () => mitmHtml(await api('/api/mitm/unauth', { message: $('#m-msg').value })));
  act('#m-au', '#m-out', async () => mitmHtml(await api('/api/mitm/auth',
    { message: $('#m-msg').value, eve_has_cert: $('#m-eve').checked })));

  /* ---------- Đo lường ---------- */
  const NOTES = [
    'ECDSA P-256 ký nhanh hơn RSA vì chỉ cần một phép nhân điểm với số mũ 256 bit; RSA phải lũy thừa modulo bằng khóa riêng d dài cỡ modulus (2048 hoặc 3072 bit).',
    'RSA kiểm tra nhanh hơn ECDSA vì số mũ công khai e thường là 65537 (17 bit). ECDSA khi kiểm tra phải làm hai phép nhân điểm.',
    'Tăng RSA từ 2048 lên 3072 bit làm sinh khóa và ký chậm đi nhiều lần, còn kiểm tra chỉ chậm thêm chút ít. Khóa và chữ ký RSA cũng lớn gấp nhiều lần ECDSA.',
    'ECDSA P-256 (khóa 256 bit) có độ an toàn gần với RSA-3072 nhưng khóa công khai và chữ ký nhỏ hơn rất nhiều, rất hợp với chứng thư và giao thức cần gửi nhiều gói.',
    'ECDH P-256 nhanh hơn DH-2048 và gói tin trao đổi nhỏ hơn; DH-2048 cần lũy thừa modulo trên số 2048 bit.',
    'AES-256-GCM thường nhanh hơn ChaCha20-Poly1305 trên CPU có lệnh AES-NI; trên thiết bị không có phần cứng AES, ChaCha20 thường là lựa chọn nhanh hơn. Kết quả phụ thuộc máy bạn.',
    'Mọi phép khóa công khai đều chậm hơn mã hóa đối xứng hàng chục đến hàng trăm lần nếu tính trên mỗi byte dữ liệu, và RSA còn không mã hóa được thông điệp dài. Vì vậy thực tế dùng mô hình lai: khóa công khai để trao khóa và ký, khóa bí mật để mã hóa dữ liệu.',
  ];
  const find = (arr, a) => arr.find(x => x.algo === a);
  const ratio = (a, b) => num(Math.max(a, b) / Math.min(a, b), 1);
  act('#b-go', '#b-out', async () => {
    const runs = Math.max(20, +$('#b-runs').value || 20);
    const R = (await api('/api/benchmark?runs=' + runs)).results;
    const g2 = find(R.signatures, 'RSA-2048'), ec = find(R.signatures, 'ECDSA-P256'), g3 = find(R.signatures, 'RSA-3072');
    const ecdh = find(R.key_exchange, 'ECDH P-256'), dh = find(R.key_exchange, 'DH-2048');
    const aes = find(R.aead, 'AES-256-GCM'), cha = find(R.aead, 'ChaCha20-Poly1305');
    const facts = [];
    if (g2 && ec) {
      facts.push(`Ký: ECDSA P-256 nhanh hơn RSA-2048 khoảng ${num(g2.sign_ms / ec.sign_ms, 1)} lần.`);
      facts.push(`Kiểm tra: ${g2.verify_ms < ec.verify_ms ? 'RSA-2048 nhanh hơn' : 'ECDSA nhanh hơn'} khoảng ${ratio(g2.verify_ms, ec.verify_ms)} lần.`);
    }
    if (g2 && g3) facts.push(`Sinh khóa RSA-3072 chậm hơn RSA-2048 khoảng ${num(g3.keygen_ms / g2.keygen_ms, 1)} lần.`);
    if (ecdh && dh) facts.push(`ECDH P-256 nhanh hơn DH-2048 khoảng ${num(dh.time_ms / ecdh.time_ms, 1)} lần.`);
    if (aes && cha) facts.push(`${aes.encrypt_ms < cha.encrypt_ms ? 'AES-256-GCM' : 'ChaCha20-Poly1305'} mã hóa 1 MB nhanh hơn khoảng ${ratio(aes.encrypt_ms, cha.encrypt_ms)} lần trên máy này.`);
    const pick = (k) => R.signatures.map(s => ({ l: s.algo, v: s[k] }));
    return `<p class="muted small">Mỗi số là trung bình của ${R.runs} lần đo.</p>`
      + '<h3>Chữ ký</h3>' + grid(['Thuật toán', 'Sinh khóa', 'Ký', 'Kiểm tra', 'Khóa công khai (byte)', 'Chữ ký (byte)'],
        R.signatures.map(s => [s.algo, ms(s.keygen_ms), ms(s.sign_ms), ms(s.verify_ms), s.pub_key_bytes, s.sig_bytes]))
      + bars('Thời gian ký', pick('sign_ms'), 'ms') + bars('Thời gian kiểm tra', pick('verify_ms'), 'ms')
      + bars('Thời gian sinh khóa', pick('keygen_ms'), 'ms')
      + '<h3>Thỏa thuận khóa (một bên)</h3>' + grid(['Thuật toán', 'Thời gian'], R.key_exchange.map(k => [k.algo, ms(k.time_ms)]))
      + bars('Thời gian trao khóa', R.key_exchange.map(k => ({ l: k.algo, v: k.time_ms })), 'ms')
      + '<h3>Mã hóa có xác thực (thông điệp 1 MB)</h3>'
      + grid(['Thuật toán', 'Mã hóa', 'Giải mã'], R.aead.map(a => [a.algo, ms(a.encrypt_ms), ms(a.decrypt_ms)]))
      + bars('Thời gian mã hóa 1 MB', R.aead.map(a => ({ l: a.algo, v: a.encrypt_ms })), 'ms')
      + '<h3>Nhận xét theo số liệu vừa đo</h3><ul class="notes">' + facts.map(f => `<li>${esc(f)}</li>`).join('') + '</ul>'
      + '<h3>Giải thích</h3><ul class="notes">' + NOTES.map(f => `<li>${esc(f)}</li>`).join('') + '</ul>';
  }, 'Đang đo, việc này mất khoảng nửa phút đến một phút...');

  refresh();
})();