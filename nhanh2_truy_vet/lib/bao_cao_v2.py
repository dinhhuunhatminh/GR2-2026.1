# -*- coding: utf-8 -*-
"""Báo cáo HTML so sánh truy vết bản cũ (v1, luật L0–L4) và bản mới (v2, đồ thị tài sản). Không có phần chấm đúng/sai vì cần đáp án."""
import json, html, collections

CSS = """:root{--line:#e3e6ea;--soft:#f6f7f9;--ink:#1d2433;--mute:#5b6476;--acc:#1f5fbf;--ok:#1d7a46;--okbg:#eaf6ef;--warn:#b25d00;--warnbg:#fff4e5}
*{box-sizing:border-box}body{margin:0;background:#fff;color:var(--ink);font:15px/1.6 "Segoe UI",system-ui,Arial,sans-serif}
.w{max-width:1080px;margin:0 auto;padding:24px 16px 50px}h1{font-size:24px;margin:0 0 4px}h2{font-size:19px;margin:28px 0 8px;border-bottom:1px solid var(--line);padding-bottom:5px}
.m{color:var(--mute)}table{width:100%;border-collapse:collapse;font-size:14px;margin:8px 0 14px}th,td{border:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}th{background:var(--soft)}
td.n{text-align:right;white-space:nowrap}.t{overflow-x:auto}code{background:var(--soft);border:1px solid var(--line);border-radius:4px;padding:0 4px;font-size:13px;overflow-wrap:anywhere}
.card{border:1px solid var(--line);border-left:4px solid var(--ok);border-radius:6px;padding:10px 12px;margin:10px 0;background:#fff}.card.w2{border-left-color:var(--warn)}
.tag{display:inline-block;font-size:12px;padding:1px 7px;border-radius:10px;border:1px solid var(--line);background:var(--soft);margin-right:4px}.ok{background:var(--okbg);color:var(--ok)}.wa{background:var(--warnbg);color:var(--warn)}
ol.ev{margin:6px 0 0 18px;padding:0;color:var(--mute);font-size:13.5px}details{margin:8px 0}summary{cursor:pointer;color:var(--acc)}"""
NHAN = {'cung_loi': ('cùng lỗi', 'ok'), 'chua_ro_ho': ('cùng chỗ, chưa rõ loại lỗi', 'wa'), 'cung_tai_san': ('cùng chỗ, khác loại lỗi', 'wa')}
LOAI = {'V1': 'mã nguồn ↔ quét động', 'V2': 'bí mật: repo → image → HTTP', 'V3': 'thư viện: lockfile ↔ image', 'V4': 'cấu hình: IaC ↔ image ↔ container', 'L0': 'cùng tệp, khác công cụ'}


def _e(x): return html.escape(str(x))


def _mo_ta(f):
    a = f['anchors']; o = a.get('file_path') and f"{a['file_path']}:{a.get('line_start')}" or a.get('url_route') or a.get('package_name') or a.get('container_target') or ''
    return f"<b>{_e(f['tool'])}</b> <code>{_e(str(f['raw_rule_id']).split('.')[-1])}</code> tại <code>{_e(str(o)[-90:])}</code> <span class='m'>({_e(f['phase'])})</span>"


def sinh(v1_file, v2_file, ra_html, toi_da=60):
    R1 = json.load(open(v1_file, encoding='utf-8')); R2 = json.load(open(v2_file, encoding='utf-8')); F2 = {f['finding_id']: f for f in R2['phat_hien']}
    c1 = {k: v for k, v in R1['so_canh'].items()}; c2 = collections.Counter((e['luat'], e['nhan']) for e in R2['canh'])
    xuyen1 = sum(v for k, v in c1.items() if k != 'L0')
    loi = [e for e in R2['canh'] if e['nhan'] == 'cung_loi' and e['luat'] != 'L0']; khac = [e for e in R2['canh'] if e['nhan'] != 'cung_loi']
    h = [f"<!doctype html><html lang='vi'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>So sánh truy vết</title><style>{CSS}</style></head><body><div class='w'>",
         f"<h1>So sánh truy vết: bản cũ (v1) và bản mới (v2)</h1><p class='m'>Cùng {R1['tong_phat_hien']} cảnh báo từ: {_e(', '.join(sorted(R1['theo_cong_cu'])))}. Repo: <code>{_e(R2.get('repo'))}</code></p>",
         "<h2>1. Tóm tắt</h2><div class='t'><table><tr><th></th><th>Bản cũ v1 (luật L0–L4: cùng CWE / cùng tên tệp)</th><th>Bản mới v2 (mối quan hệ lấy từ repo)</th></tr>",
         f"<tr><td>Cặp ghép xuyên pha</td><td class='n'>{xuyen1}</td><td class='n'>{sum(v for (l, n), v in c2.items() if l != 'L0')}</td></tr>",
         f"<tr><td>— trong đó <span class='tag ok'>cùng lỗi</span> (đáng tin để báo người dùng)</td><td class='n'>–</td><td class='n'><b>{len(loi)}</b></td></tr>",
         f"<tr><td>Số cụm (vết) có ≥ 2 cảnh báo</td><td class='n'>{sum(1 for c in R1.get('cum', []) if c.get('so_phat_hien', 0) > 1) if isinstance(R1.get('cum'), list) else '–'}</td><td class='n'>{len(R2.get('cum_list', []))}</td></tr>",
         f"<tr><td>Theo luật / loại</td><td>{_e(', '.join(f'{k}={v}' for k, v in c1.items()))}</td><td>{_e(', '.join(f'{LOAI.get(l, l)} [{NHAN.get(n, (n,))[0]}]={v}' for (l, n), v in sorted(c2.items())))}</td></tr></table></div>",
         "<p class='m'>Bản mới ghép theo <b>chỗ trong repo</b> (trang web ↔ hàm xử lý ↔ hàm được gọi; tệp → lệnh COPY trong Dockerfile → image → container; thư viện ↔ image), rồi so loại lỗi (CWE) để gắn nhãn. Chỉ nhãn <i>cùng lỗi</i> nên dùng để kết luận; nhãn <i>cùng chỗ</i> là gợi ý.</p>"]
    h.append(f"<h2>2. Các cặp ghép <span class='tag ok'>cùng lỗi</span> xuyên pha ({len(loi)})</h2>")
    seen = set()
    for e in loi[:toi_da]:
        a, b = F2[e['a']], F2[e['b']]; k = (a['tool'], str(a['anchors'].get('file_path')), a['anchors'].get('line_start'), b['tool'], b['raw_rule_id'], b['anchors'].get('url_route'))
        if k in seen: continue
        seen.add(k)
        h.append(f"<div class='card'><span class='tag'>{_e(LOAI.get(e['luat'], e['luat']))}</span><span class='tag ok'>cùng lỗi</span><div>{_mo_ta(a)}</div><div>↔ {_mo_ta(b)}</div><ol class='ev'>" + ''.join(f'<li>{_e(x)}</li>' for x in e['bang_chung']) + "</ol></div>")
    if not loi: h.append("<p class='m'>Không có cặp nào. Thường do thiếu quét động, hoặc quét động không xác nhận được lỗi nào trùng loại với cảnh báo mã nguồn.</p>")
    lan = R2.get('lan_truyen_bi_mat') or []
    h.append(f"<h2>3. Bí mật trong repo đi vào image/container ({len(lan)})</h2>")
    if lan:
        h.append("<div class='t'><table><tr><th>Tệp trong repo (gitleaks)</th><th>Đường dẫn trong image</th><th>Bằng chứng (Dockerfile)</th><th>Container</th></tr>" + ''.join(f"<tr><td><code>{_e(x[1])}</code></td><td><code>/{_e(x[2])}</code></td><td>{_e(x[3])}</td><td>{_e(', '.join(x[4]) or '–')}</td></tr>" for x in lan) + "</table></div>")
    else: h.append("<p class='m'>Không có (không có cảnh báo gitleaks, hoặc tệp không được COPY vào image).</p>")
    h.append(f"<h2>4. Các cặp <span class='tag wa'>cùng chỗ</span> (gợi ý, chưa chắc cùng lỗi) – {len(khac)}</h2><details><summary>Mở danh sách (tối đa {toi_da})</summary>")
    for e in khac[:toi_da]:
        a, b = F2[e['a']], F2[e['b']]; t, c = NHAN.get(e['nhan'], (e['nhan'], 'wa'))
        h.append(f"<div class='card w2'><span class='tag'>{_e(LOAI.get(e['luat'], e['luat']))}</span><span class='tag {c}'>{_e(t)}</span><div>{_mo_ta(a)}</div><div>↔ {_mo_ta(b)}</div><ol class='ev'>" + ''.join(f'<li>{_e(x)}</li>' for x in e['bang_chung'][:4]) + "</ol></div>")
    h.append("</details><p class='m'>Kiểm độc lập ở bước 30–31 (Juice Shop): cặp <i>cùng lỗi</i> đúng 11/12; cặp <i>cùng chỗ</i> chỉ khoảng 25–32% đúng. Báo cáo này không chấm đúng/sai vì cần đáp án.</p></div></body></html>")
    open(ra_html, 'w', encoding='utf-8').write('\n'.join(h))
    return {'html': ra_html, 'cung_loi_xuyen_pha': len(loi), 'cung_cho': len(khac), 'lan_truyen_bi_mat': len(lan), 'v1_canh': c1}
