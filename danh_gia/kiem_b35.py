# -*- coding: utf-8 -*-
"""Bước 35 – kiểm các tiêu chí CỨNG H1–H4, H6–H9 trong PHIEU_BUOC35.md (H5 chạy riêng bằng Chromium: kiem_h5_chromium.py).
Chạy: PYTHONDONTWRITEBYTECODE=1 python kiem_b35.py   (cần Python có gói mcp). Gọi máy chủ MỚI mcp_truy_vet_v3_2 qua stdio như client thật; máy chủ cũ chỉ để so tool cũ.
KHÔNG ghi gì vào thư mục cũ: kết quả ghi vào buoc35/ket_qua/."""
import sys, os, re, json, html, hashlib, asyncio, pathlib, collections
sys.dont_write_bytecode = True
os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
HERE = pathlib.Path(__file__).resolve().parent
B35 = HERE.parent; DATASET = B35.parent; B34 = DATASET / 'buoc34_nhanh2_tinh_va_vi_mo'; GR2 = DATASET.parent
sys.path.insert(0, str(B34 / 'kiem_thu'))
import common as C   # chỉ dùng mo/goi/Bao; common ghi ket_qua vào thư mục cũ NẾU gọi Bao.ket(ra) -> không gọi
NEW = B35 / 'mcp_truy_vet_v3_2' / 'server.py'; OLD = B34 / 'mcp_truy_vet_v3' / 'server.py'
N02 = B34 / 'kiem_thu_lop2_nhanh2' / 'ra' / 'v3_JuiceShop_N02.json'
QUET = DATASET / 'buoc31_juiceshop' / 'quet'
KQ = B35 / 'ket_qua'; KQ.mkdir(exist_ok=True)
ENV = {'VSECOPS_ALLOWED_ROOTS': str(GR2), 'PYTHONDONTWRITEBYTECODE': '1'}
B = C.Bao('Bước 35 – báo cáo v3 và xếp hạng v3')
R = json.load(open(N02, encoding='utf-8')); F = {f['finding_id']: f for f in R['phat_hien']}


def vi_tri(f):
    a = f['anchors']
    if a.get('file_path'): return '%s:%s' % (a['file_path'], a['line_start']) if a.get('line_start') else a['file_path']
    return a.get('url_route') or a.get('package_name') or a.get('container_target') or ''


def doc(p): return open(p, encoding='utf-8').read()


async def main():
    async with C.mo(NEW, ENV) as S, C.mo(OLD, ENV) as SO:
        tools = {t.name for t in (await S.list_tools()).tools}
        B.kt('B35-00 máy chủ mới có bao_cao_v3, xep_hang_loi_v3 và đủ tool cũ', tools >= {'bao_cao_v3', 'xep_hang_loi_v3', 'truy_vet_v3', 'bao_cao_vet', 'xep_hang_loi', 'xem_vet', 'phien_ban'}, sorted(tools))
        # ---------- H1 ----------
        out1 = KQ / 'bao_cao_juiceshop.html'
        r = await C.goi(S, 'bao_cao_v3', ket_qua_file=str(N02), ra_html=str(out1), quet_tho_dir=str(QUET))
        B.kt('H1a bao_cao_v3 chạy được và tạo tệp', '__loi__' not in r and 'loi' not in r and out1.exists(), str(r)[:300])
        H = doc(out1); sz = out1.stat().st_size
        B.kt('H1b dung lượng ≤ 5 MB (giả định A1)', sz <= 5 * 1024 * 1024, '%d byte' % sz)
        ngoai = re.findall(r'''(?:src|href|action)\s*=\s*["']?\s*(?:https?:)?//''', H) + re.findall(r'''url\(\s*["']?\s*(?:https?:)?//''', H) + re.findall(r'<link\b', H) + re.findall(r'<script[^>]*\bsrc=', H) + re.findall(r'@import', H)
        B.kt('H1c không tham chiếu tài nguyên ngoài (src/href/url()/link/@import)', not ngoai, ngoai[:3])
        # ---------- H2 ----------
        def tile(k):
            m = re.search(r'data-k="%s"><div class="n">(\d+)</div>' % k, H); return int(m.group(1)) if m else None

        def cell(k):
            m = re.search(r'<td data-k="%s">(\d+)</td>' % re.escape(k), H); return int(m.group(1)) if m else None
        exp = {'tong_phat_hien': 213, 'so_cum': 182, 'cum_xuyen_pha': 5, 'phat_hien_trong_cum_xuyen_pha': 33, 'tong_canh': 52, 'canh_bi_loai': 87, 'ham_hub': 15}
        got = {k: tile(k) for k in exp}
        B.kt('H2a ô tóm tắt khớp giá trị viết trong phiếu', got == exp, {k: (got[k], exp[k]) for k in exp if got[k] != exp[k]} or got)
        expn = {'v1_cung_loi': 13, 'v1_cung_tai_san': 22, 'v1_chua_ro_ho': 11, 'intra_cung_loi': 6, 'intra_cung_tai_san': 0, 'intra_chua_ro_ho': 0}
        gotn = {k: cell(k) for k in expn}
        B.kt('H2b bảng nhãn cạnh khớp (V1: 13/22/11; V1_intra: cung_loi 6)', gotn == expn, gotn)
        expm = {'M1': 64, 'M2': 32, 'M3': 27, 'M4': 25}
        gotm = {k: cell(k) for k in expm}
        B.kt('H2c mức phơi nhiễm M1–M4 khớp (64/32/27/25)', gotm == expm, gotm)
        B.kt('H2d tổng theo công cụ và V1/V1_intra có trong chữ', 'codeql 93, semgrep 55, zap 65' in H and 'V1 (mã↔động) 46 · V1_intra (mã↔mã) 6' in H, '')
        # ---------- H3 ----------
        cum = {c['id']: c for c in R['cum']}; xp = sorted(c['id'] for c in R['cum'] if len(c['pha']) >= 2)
        T = html.unescape(H)
        ncard = len(re.findall(r'<article class="card', H))
        B.kt('H3a có đúng 5 thẻ truy vết, đúng các cụm ≥2 pha', ncard == 5 and all(('data-cum="%s"' % html.escape(c)) in H for c in xp), (ncard, xp))
        thieu = []; tong = 0
        for e in R['canh']:
            ca, cb = F[e['a']]['cum'], F[e['b']]['cum']
            if ca not in xp and cb not in xp: continue
            tong += 1
            for x in (e['a'], e['b'], vi_tri(F[e['a']]), vi_tri(F[e['b']]), *e['bang_chung']):
                if x not in T: thieu.append((e['a'], e['b'], x[:60]))
        B.kt('H3b mọi cạnh của 5 cụm: hai đầu, vị trí và từng chuỗi bằng chứng có nguyên văn trong HTML', tong > 0 and not thieu, 'cạnh %d, thiếu %d %s' % (tong, len(thieu), thieu[:2]))
        # ---------- H4 ----------
        ids = re.findall(r'<tr data-tool="[^"]*" data-pha="[^"]*" data-tier="[^"]*" data-m="[^"]*" data-t="[^"]*"><td class="id">([^<]+)</td>', H)
        B.kt('H4 bảng có đúng 213 dòng, mỗi finding_id đúng một lần', len(ids) == 213 and len(set(ids)) == 213 and set(ids) == set(F), (len(ids), len(set(ids))))
        # ---------- H6 ----------
        can = ['chưa chứng minh hai cảnh báo là cùng một điểm khai thác', 'heuristic', 'in-sample', 'kết quả có sẵn']
        thieu6 = [c for c in can if c not in T]
        cam = [c for c in ('đã xác nhận khai thác', 'đã vá', 'đã được khai thác') if c.lower() in T.lower()]
        B.kt('H6a phần Giới hạn có đủ 4 ý', not thieu6, thieu6)
        B.kt('H6b không chứa các cụm bị cấm', not cam, cam)
        sai = []
        for cid in xp:
            for f in R['phat_hien']:
                if f['cum'] != cid: continue
                m = re.search(r'<li>((?:(?!</li>).)*?<span class="id">%s</span>)</li>' % re.escape(f['finding_id']), H)
                if not m or ('họ lỗi theo tệp: %s' % html.escape(str(f.get('family')))) not in m.group(1): sai.append(f['finding_id'])
        B.kt('H6c họ lỗi hiển thị trong thẻ đúng như tệp (không tự gán loại lỗi)', not sai, sai[:5])
        B.kt('H6d tên cảnh báo ZAP chỉ xuất hiện kèm nhãn "tên từ tệp quét thô"', all(('tên từ tệp quét thô' in x) for x in re.findall(r'<i>\([^<]*\)</i>', H)), len(re.findall(r'<i>\(', H)))
        # ---------- H7 ----------
        out2 = KQ / 'bao_cao_juiceshop_lan2.html'
        await C.goi(S, 'bao_cao_v3', ket_qua_file=str(N02), ra_html=str(out2), quet_tho_dir=str(QUET))
        B.kt('H7 sinh lại hai lần cho cùng tệp (khớp từng byte)', out1.read_bytes() == out2.read_bytes(), hashlib.sha256(out1.read_bytes()).hexdigest()[:16])
        # ---------- H8 ----------
        v3 = await C.goi(S, 'xep_hang_loi_v3', ket_qua_file=str(N02), top=100)
        old = await C.goi(S, 'xep_hang_loi', ket_qua_file=str(N02), top=100)
        oldtop = old.get('top', []); nt = v3.get('top', [])
        B.kt('H8i số nhóm bằng xep_hang_loi cũ (kỳ vọng 90)', v3.get('so_nhom') == old.get('so_nhom') == 90 and len(nt) == 90, (v3.get('so_nhom'), old.get('so_nhom')))
        flags = [g['chi_m4'] for g in nt]
        mono = all(not (flags[i] and not flags[i + 1]) for i in range(len(flags) - 1))
        B.kt('H8ii mọi nhóm "chỉ M4" nằm sau mọi nhóm còn lại, và có ít nhất một nhóm như vậy', mono and any(flags) and sum(flags) == v3.get('so_nhom_chi_m4_xuong_cuoi'), (sum(flags), v3.get('so_nhom_chi_m4_xuong_cuoi')))
        ok_ord = True; ok_map = True
        for part in (False, True):
            hs = [g['hang_goc'] for g in nt if g['chi_m4'] == part]
            ok_ord &= all(hs[i] < hs[i + 1] for i in range(len(hs) - 1))
        for g in nt:
            o = oldtop[g['hang_goc'] - 1]
            ok_map &= (o['loi'] == g['loi'] and o['o_dau'] == g['o_dau_goc'] and o['muc_nang'] == g['muc_nang'])   # sửa sau lần chạy 1: o_dau nay là vị trí đầu tiên không thuộc M4, o_dau_goc là vị trí cũ
        B.kt('H8iii thứ tự tương đối trong mỗi phần giống xep_hang_loi cũ; hang_goc trỏ đúng nhóm cũ', ok_ord and ok_map, '')
        B.kt('H8iv top 10 không còn nhóm trong data/static/codefixes/', not any('codefixes' in g['o_dau'] for g in nt[:10]), [g['o_dau'][:60] for g in nt[:10]])
        B.kt('H8v (thông tin) các nhóm chỉ-M4 bị đẩy xuống', True, [g['o_dau'][:50] for g in nt if g['chi_m4']][:8], muc='MEM')
        v3l = await C.goi(S, 'xep_hang_loi_v3', ket_qua_file=str(N02), top=5, theo_loai=True)
        B.kt('H8vi theo_loai chạy được', '__loi__' not in v3l and 'loai' in v3l, str(v3l)[:150])
        # ---------- H9 ----------
        a = await C.goi(S, 'xep_hang_loi', ket_qua_file=str(N02), top=10); b = await C.goi(SO, 'xep_hang_loi', ket_qua_file=str(N02), top=10)
        B.kt('H9a xep_hang_loi cũ trên máy chủ mới = trên máy chủ cũ', a == b and a.get('so_nhom') == 90, '')
        o1 = KQ / 'bao_cao_vet_cu_moi.html'; o2 = KQ / 'bao_cao_vet_cu_cu.html'
        r1 = await C.goi(S, 'bao_cao_vet', ket_qua_file=str(N02), ra_html=str(o1)); r2 = await C.goi(SO, 'bao_cao_vet', ket_qua_file=str(N02), ra_html=str(o2))
        B.kt('H9b bao_cao_vet cũ trên máy chủ mới = trên máy chủ cũ (cùng hành vi, kể cả hạn chế 0 vết)', r1 == {**r2, 'tep': r1.get('tep')} and o1.read_bytes() == o2.read_bytes(), (r1, r2))
        res = {}
        for app in ('DVWA', 'NodeGoat', 'VAmPI', 'crAPI', 'AIBook'):
            f = B34 / 'ket_qua_lan2_v31b' / 'do_thi_v3' / ('v3_%s.json' % app); o = KQ / ('bao_cao_%s.html' % app)
            r = await C.goi(S, 'bao_cao_v3', ket_qua_file=str(f), ra_html=str(o))
            res[app] = ('loi' if ('__loi__' in r or 'loi' in r) else 'ok', o.stat().st_size if o.exists() else None)
            x = await C.goi(S, 'xep_hang_loi_v3', ket_qua_file=str(f), top=5)
            res[app] += ('xh_loi' if ('__loi__' in x or 'loi' in x) else 'xh_ok',)
        B.kt('H9c bao_cao_v3 và xep_hang_loi_v3 không sập trên đầu ra v3 của 5 ứng dụng khác (chỉ kiểm chạy được)', all(v[0] == 'ok' and v[1] and v[2] == 'xh_ok' for v in res.values()), res)
        r = await C.goi(S, 'bao_cao_v3', ket_qua_file=str(N02), ra_html='/tmp/ngoai_vung/x.html')
        B.kt('H9d ra_html ngoài vùng cho phép bị từ chối', '__loi__' in r or 'loi' in r, str(r)[:120])
        r = await C.goi(S, 'bao_cao_v3', ket_qua_file=str(GR2 / '..' / '..' / 'etc' / 'passwd'), ra_html=str(KQ / 'x.html'))
        B.kt('H9e ket_qua_file ngoài vùng bị từ chối', '__loi__' in r or 'loi' in r, str(r)[:120])
        r = await C.goi(S, 'bao_cao_v3', ket_qua_file=str(B34 / 'kiem_thu' / 'du_lieu' / 'v14c_JuiceShop.json'), ra_html=str(KQ / 'y.html'))
        B.kt('H9f tệp truy_vet v1 (không phải v3): báo lỗi rõ, không sập', 'loi' in r or '__loi__' in r, str(r)[:160])
        # ZAP 10038: tên lấy từ tệp thô (thông tin để đính chính)
        m = re.search(r'10038[^<]*<i>\(([^;]*);', H)
        B.kt('Thông tin: tên ZAP 10038 trong tệp quét thô', True, m.group(1) if m else 'không tra được', muc='MEM')
    cung = [d for d in B.ds if d['muc'] == 'CUNG']
    t = {'bo_kiem_thu': B.ten, 'cung_dat': sum(d['ok'] for d in cung), 'cung_tong': len(cung), 'chi_tiet': B.ds}
    json.dump(t, open(KQ / 'ket_qua_test_b35.json', 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print('\n== kiểm tra cứng %d/%d' % (t['cung_dat'], t['cung_tong']))

asyncio.run(main())
