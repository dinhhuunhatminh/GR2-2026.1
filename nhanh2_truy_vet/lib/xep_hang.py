# -*- coding: utf-8 -*-
"""Xếp hạng lỗi bằng QUY TẮC (không dùng AI). Công thức chốt trong PHIEU_BUOC23.md (mục "Xếp hạng lỗi bằng QUY TẮC").
Khóa sắp xếp (so sánh theo thứ tự, không cộng điểm): mức nặng giảm dần, tier tăng dần, xác nhận động (có trước), rồi tên luật + vị trí để ổn định."""
import html, json, os, re

RANK = {'Critical': 5, 'High': 4, 'Medium': 3, 'Low': 2, 'Info': 1}
LIB_TOOLS = ('osv-scanner', 'grype')


def dich_vu(f):
    a = f['anchors']; fp = (a.get('file_path') or '').replace('\\', '/')
    m = re.search(r'services/([^/]+)', fp)
    if m: return m.group(1)
    if 'deploy' in fp: return 'deploy'
    r = a.get('url_route')
    if r: return (r.strip('/').split('/') or ['?'])[0]
    ct = a.get('container_target') or ''
    if f['tool'] == 'dockle': return ct.replace('\\', '/').split('/')[-1].replace('dockle_', '').replace('.json', '')
    return ct[:40] or fp.split('/')[0] or '?'


def khoa_nhom(f):
    a = f['anchors']
    if f['tool'] in LIB_TOOLS: return ('thu_vien', a.get('cve_id'), a.get('package_name'))
    return (f['tool'], f['raw_rule_id'], dich_vu(f))


def xep_hang(R):
    pha_cum = {c['id']: set(c['pha']) for c in R['cum']}
    G = {}
    for f in R['phat_hien']:
        k = khoa_nhom(f); g = G.setdefault(k, {'khoa': k, 'thanh_vien': [], 'sev': 'Info', 'tier': 3, 'xac_nhan_dong': False, 'cong_cu': set(), 'pha': set(), 'vi_tri': None, 'luat': f['raw_rule_id'].split('.')[-1]})
        g['thanh_vien'].append(f['finding_id'])
        if RANK[f['sev']] > RANK[g['sev']]: g['sev'] = f['sev']
        g['tier'] = min(g['tier'], f['tier']); g['cong_cu'].add(f['tool']); g['pha'].add(f['phase'])
        if (f['phase'] == 'TEST' and RANK[f['sev']] >= RANK['Medium']) or 'TEST' in pha_cum.get(f['cum'], ()): g['xac_nhan_dong'] = True
        a = f['anchors']
        if g['vi_tri'] is None: g['vi_tri'] = (a.get('file_path') or a.get('url_route') or a.get('package_name') or a.get('container_target') or '')
    L = list(G.values())
    L.sort(key=lambda g: (-RANK[g['sev']], g['tier'], not g['xac_nhan_dong'], str(g['luat']), str(g['vi_tri'])))
    for i, g in enumerate(L, 1):
        g['hang'] = i; g['n'] = len(g['thanh_vien']); g['cong_cu'] = sorted(g['cong_cu']); g['pha'] = sorted(g['pha'])
    return L


def mo_ta_ngan(g):
    k = g['khoa']
    if k[0] == 'thu_vien': return f"Thư viện {k[2]} dính lỗi {k[1]}"
    return f"{g['luat']} ({k[0]}) ở {k[2]}"


def html_bao_cao(L, ra, N_tong, top=40):
    e = html.escape; dem = {s: sum(1 for g in L if g['sev'] == s) for s in RANK}
    cls = {'Critical': '#c0392b', 'High': '#e67e22', 'Medium': '#d4ac0d', 'Low': '#7f8c8d', 'Info': '#bdc3c7'}
    rows = ''.join('<tr><td>%d</td><td style="color:#fff;background:%s;text-align:center">%s</td><td>%s</td><td>%s</td><td style="text-align:right">%d</td><td>%s</td><td style="text-align:center">%d</td><td style="text-align:center">%s</td></tr>' % (
        g['hang'], cls[g['sev']], g['sev'], e(mo_ta_ngan(g)), e(str(g['vi_tri'])[:70]), g['n'], e(', '.join(g['cong_cu'])), g['tier'], 'có' if g['xac_nhan_dong'] else '–') for g in L[:top])
    page = '''<!doctype html><html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Danh sách lỗi ưu tiên</title><style>
body{font-family:Segoe UI,Arial,sans-serif;max-width:1080px;margin:24px auto;padding:0 16px;color:#222;line-height:1.5}table{border-collapse:collapse;width:100%%}td,th{border:1px solid #ccc;padding:5px 7px;font-size:13px}th{background:#eee}
.box{background:#f5f5f5;padding:10px 14px;border-left:5px solid #888;margin:12px 0}</style></head><body>
<h1>Danh sách lỗi ưu tiên</h1>
<div class="box">Thứ tự do <b>hệ thống xếp bằng quy tắc cố định</b>, không phải AI: (1) mức nặng do chính công cụ báo, (2) tier (tin cậy: 1 = nhiều pha cùng thấy), (3) đã được quét động xác nhận, rồi tên luật. Các lỗi giống nhau được gom thành một nhóm. Công thức do Claude đề xuất, chưa có chuẩn bên ngoài.</div>
<p>%d phát hiện gộp thành <b>%d nhóm</b>. Theo mức nặng: %s.</p>
<h2>%d nhóm đứng đầu</h2><table><tr><th>#</th><th>Mức nặng</th><th>Lỗi</th><th>Ở đâu</th><th>Số mục gộp</th><th>Công cụ</th><th>Tier</th><th>Xác nhận động</th></tr>%s</table>
</body></html>''' % (N_tong, len(L), ', '.join('%s %d' % (s, dem[s]) for s in ('Critical', 'High', 'Medium', 'Low', 'Info')), min(top, len(L)), rows)
    open(ra, 'w', encoding='utf-8').write(page)
    return ra


# ---- v1.2 (21/10/2026): bảng xếp hạng RIÊNG theo loại lỗi. Điều chỉnh sau khi chấm, chốt trong PHIEU_BUOC23.md ("Điều chỉnh SAU khi chấm #2"). ----
LOAI_CONG_CU = {'semgrep': 'ma_nguon', 'bandit': 'ma_nguon', 'njsscan': 'ma_nguon', 'eslint_security': 'ma_nguon', 'gitleaks': 'bi_mat',
                'osv-scanner': 'thu_vien', 'grype': 'thu_vien', 'kics': 'cau_hinh', 'dockle': 'cau_hinh', 'docker_bench': 'cau_hinh', 'nuclei': 'dong_web', 'zap': 'dong_web'}
LOAI_TEN = {'ma_nguon': 'Lỗi trong mã nguồn', 'bi_mat': 'Bí mật lộ trong mã', 'thu_vien': 'Thư viện có lỗ hổng đã biết (CVE)', 'cau_hinh': 'Cấu hình Docker / hạ tầng', 'dong_web': 'Lỗi thấy khi chạy ứng dụng (quét động)'}
THU_TU_LOAI = ('ma_nguon', 'bi_mat', 'dong_web', 'cau_hinh', 'thu_vien')


def loai_cua(g):
    k = g['khoa'][0]
    return 'thu_vien' if k == 'thu_vien' else LOAI_CONG_CU.get(k, 'cau_hinh')


def xep_hang_theo_loai(L):
    """L = kết quả xep_hang (đã sắp theo khóa chung). Lọc theo loại, giữ nguyên thứ tự => cùng khóa sắp xếp trong từng loại. Gắn g['loai'], g['hang_trong_loai']."""
    D = {}
    for g in L:
        g['loai'] = loai_cua(g); D.setdefault(g['loai'], []).append(g)
    for ds in D.values():
        for i, g in enumerate(ds, 1): g['hang_trong_loai'] = i
    return {k: D[k] for k in THU_TU_LOAI if k in D}


def html_theo_loai(D, ra, N_tong, top=15):
    e = html.escape
    cls = {'Critical': '#c0392b', 'High': '#e67e22', 'Medium': '#d4ac0d', 'Low': '#7f8c8d', 'Info': '#bdc3c7'}
    sec = ''
    for k, ds in D.items():
        rows = ''.join('<tr><td>%d</td><td style="color:#fff;background:%s;text-align:center">%s</td><td>%s</td><td>%s</td><td style="text-align:right">%d</td><td style="text-align:center">%d</td><td style="text-align:center">%s</td></tr>' % (
            g['hang_trong_loai'], cls[g['sev']], g['sev'], e(mo_ta_ngan(g)), e(str(g['vi_tri'])[:70]), g['n'], g['tier'], 'có' if g['xac_nhan_dong'] else '–') for g in ds[:top])
        sec += '<h2>%s — %d nhóm</h2><table><tr><th>#</th><th>Mức nặng</th><th>Lỗi</th><th>Ở đâu</th><th>Số mục gộp</th><th>Tier</th><th>Xác nhận động</th></tr>%s</table>' % (e(LOAI_TEN[k]), len(ds), rows)
    page = '''<!doctype html><html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Lỗi ưu tiên theo loại</title><style>
body{font-family:Segoe UI,Arial,sans-serif;max-width:1080px;margin:24px auto;padding:0 16px;color:#222;line-height:1.5}table{border-collapse:collapse;width:100%%}td,th{border:1px solid #ccc;padding:5px 7px;font-size:13px;text-align:left}th{background:#eee}
.box{background:#f5f5f5;padding:10px 14px;border-left:5px solid #888;margin:12px 0}</style></head><body><h1>Lỗi ưu tiên, xếp riêng theo loại</h1>
<div class="box">Mỗi loại có bảng riêng, cùng quy tắc cố định (mức nặng, tier, xác nhận động), không dùng AI. Mục đích: lỗi thư viện không còn che lỗi mã/cấu hình. <b>Không so được mức nặng giữa các loại</b> (thang của từng công cụ khác nhau).</div>
<p>%d phát hiện.</p>%s</body></html>''' % (N_tong, sec)
    open(ra, 'w', encoding='utf-8').write(page)
    return ra
