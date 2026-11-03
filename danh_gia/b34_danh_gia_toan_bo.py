"""Bước 34 – chấm G1..G5 của PHIEU_BUOC34.md trên đồ thị v3.0 (kq3/v3_*.json), so với v1.4c và v2.1 (cùng đầu vào, cùng bộ chấm của bước 30/31).
Ngưỡng ĐẠT lấy NGUYÊN VĂN từ phiếu (không chỉnh sau khi chạy). Mọi khoảng tin cậy: Wilson 95%.
G1 cần người kiểm độc lập: script này chỉ (a) kiểm tự động hai lỗi đã biết, (b) rút mẫu 30 cạnh V1 ngẫu nhiên (seed 34) ra kiem/mau_canh_v3.json;
kết luận của người kiểm đọc từ kiem/kiem_doc_lap_v3.json (nếu có). Usage: python b34_danh_gia_toan_bo.py [--in kq3] [--out ket_qua]"""
import json, os, re, sys, math, random, subprocess, collections
B = os.environ.get('B34_DATA', '/home/claude/b34'); sys.path.insert(0, B); from fam2 import family2
KQ3 = os.environ.get('B34_OUT', B + '/kq3'); OUT = os.environ.get('B34_KETQUA', B + '/ket_qua'); os.makedirs(OUT, exist_ok=True); os.makedirs(OUT + '/kiem', exist_ok=True)
X24 = B + '/vao/buoc24_nhieu_ung_dung'; J = B + '/x/buoc31_juiceshop'
APPS4 = {'crAPI': (B + '/x/dap_an_chot.json', B + '/vao/crapi_quet', 'crapi-web'),
         'VAmPI': (X24 + '/dap_an/dap_an_VAmPI.json', X24 + '/quet/VAmPI', 'vampi'),
         'NodeGoat': (X24 + '/dap_an/dap_an_NodeGoat.json', X24 + '/quet/NodeGoat', 'nodegoat'),
         'DVWA': (X24 + '/dap_an/dap_an_DVWA.json', X24 + '/quet/DVWA', 'dvwa')}
def wilson(k, n, z=1.96):
    if n == 0: return None
    p = k / n; d = 1 + z * z / n; c = (p + z * z / (2 * n)) / d; h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [round(max(0, c - h), 3), round(min(1, c + h), 3)]
def rng(s):
    m = re.match(r'(\d+)(?:-(\d+))?', str(s or '')); return (int(m.group(1)), int(m.group(2) or m.group(1))) if m else None
def norm_route(r): return re.sub(r'\{[^}]+\}', '{}', re.sub(r'^[A-Z]+\s+', '', r.split(' (')[0]).rstrip('/'))
def touches(R, G, hieu_dung=False):
    """Luật chạm y hệt b30_cham.py / b24_cham.py (lỏng = vị trí/route; chặt = thêm cùng họ)."""
    T = {}
    for g in G:
        fam_ok = {family2([c]) for c in g['cwe_chap_nhan']}; lo, ch = [], []
        for f in R['phat_hien']:
            a = f['anchors']; hit = False
            if f['phase'] in ('CODE', 'DEPLOY') and a.get('file_path'):
                fp = a['file_path'].replace('\\', '/')
                for tep, dong in g['vi_tri_chap_nhan']:
                    r = rng(dong)
                    if fp.endswith(tep) or tep.endswith(fp.split('services/')[-1]) and 'services/' in fp:
                        if r and a.get('line_start') and not (a['line_end'] + 5 < r[0] or a['line_start'] - 5 > r[1]): hit = True
            elif f['phase'] == 'TEST' and a.get('url_route'):
                hit = any(norm_route(rt) == norm_route(g['route']) for rt in f.get('routes', [])) or norm_route(a['url_route']) == norm_route(g['route'])
            if hit:
                lo.append(f['finding_id'])
                fam_f = f.get('family_hieu_dung', f['family']) if hieu_dung else f['family']
                if fam_f in fam_ok and fam_f != 'khac': ch.append(f['finding_id'])
        T[g['id']] = (lo, ch)
    return T
def cham_app(app, tv, tag):
    gt, quet, web = APPS4[app]; G = [g for g in json.load(open(gt))['thu_thach'] if g['nhom'] == 'chinh']
    outj = f'{OUT}/cham_{tag}_{app}.json'
    subprocess.run(['python3', X24 + '/b24_cham.py', tv, gt, quet, outj, '--lib', B, '--anh-web', web], capture_output=True)
    CH = json.load(open(outj)); R = json.load(open(tv)); F = {f['finding_id']: f for f in R['phat_hien']}
    adj = collections.defaultdict(set)
    for e in R['canh']: adj[e['a']].add(e['b']); adj[e['b']].add(e['a'])
    T = touches(R, G)
    dk = [g for g in G if len({F[i]['phase'] for i in T[g['id']][0]}) >= 2]
    noi = [g['id'] for g in dk if any(F[i]['phase'] != F[j]['phase'] and j in adj[i] for i in T[g['id']][0] for j in T[g['id']][0])]
    cum = [g['id'] for g in dk if any(F[i]['phase'] != F[j]['phase'] and F[i]['cum'] == F[j]['cum'] for i in T[g['id']][0] for j in T[g['id']][0])]
    cg = collections.defaultdict(set)
    for g in G:
        for i in T[g['id']][0]: cg[F[i]['cum']].add(g['id'])
    size = collections.Counter(f['cum'] for f in R['phat_hien']); multi = [c for c, s in cg.items() if len(s) > 1 and size[c] > 1]
    m2 = CH['M2_lien_ket_xuyen_pha_dung']
    return {'M2_cu': [m2['k'], m2['n'], m2['wilson95'], m2['thu_thach']], 'phu_chat': CH['phu_chat']['k'], 'phu_long': CH['phu_long']['k'],
            'M2_dieu_kien_canh': [len(noi), len(dk), wilson(len(noi), len(dk)), noi], 'M2_dieu_kien_cum': [len(cum), len(dk), wilson(len(cum), len(dk)), cum],
            'cum_nhieu_thu_thach': [len(multi), len([c for c, s in cg.items() if size[c] > 1]), {c: sorted(cg[c]) for c in multi}], 'so_canh': R['so_canh'], 'so_cum': R['so_cum'], 'tier': R['tier_theo_phat_hien']}
res = {}
# ======================= G4: 4 ứng dụng của bước 30 =======================
g4 = {}
for app in APPS4:
    g4[app] = {'v21_tai_lap': cham_app(app, f'{B}/kq/v21_{app}.json', 'v21'), 'v21_cong_bo': cham_app(app, f'{B}/ref/v21_{app}.json', 'v21ref'), 'v14': cham_app(app, f'{B}/kq/v14_{app}.json', 'v14'), 'v30': cham_app(app, f'{KQ3}/v3_{app}.json', 'v30')}
def tong(ver, apps): return [sum(g4[a][ver]['M2_cu'][0] for a in apps), sum(g4[a][ver]['M2_cu'][1] for a in apps)]
def tong_dk(ver, apps): return [sum(g4[a][ver]['M2_dieu_kien_canh'][0] for a in apps), sum(g4[a][ver]['M2_dieu_kien_canh'][1] for a in apps)]
app3 = ['VAmPI', 'NodeGoat', 'DVWA']; G4 = {}
for ver in ('v14', 'v21_cong_bo', 'v21_tai_lap', 'v30'):
    t3 = tong(ver, app3); d3 = tong_dk(ver, app3); cr = g4['crAPI'][ver]['M2_cu'][:2]; dcr = g4['crAPI'][ver]['M2_dieu_kien_canh'][:2]
    G4[ver] = {'M2_cu_3app': t3 + [wilson(*t3)], 'M2_cu_crAPI': cr + [wilson(*cr)], 'M2_dieu_kien_canh_3app': d3 + [wilson(*d3)], 'M2_dieu_kien_canh_crAPI': dcr + [wilson(*dcr)],
               'phu_long_3app': sum(g4[a][ver]['phu_long'] for a in app3), 'phu_chat_3app': sum(g4[a][ver]['phu_chat'] for a in app3),
               'cum_nhieu_thu_thach': {a: g4[a][ver]['cum_nhieu_thu_thach'][:2] for a in APPS4}}
# cạnh nối nhầm giữa các microservice (crAPI): cạnh V1 / V1_intra có hai đầu thuộc hai dịch vụ khác nhau
R3 = json.load(open(f'{KQ3}/v3_crAPI.json')); F3 = {f['finding_id']: f for f in R3['phat_hien']}
xs = [l for l in R3['ds_lien_ket_chinh'] if l['svc_code'] and l['svc_ep'] and l['svc_code'] != l['svc_ep']]
xs_intra = [e for e in R3['canh'] if e['luat'] == 'V1_intra' and F3[e['a']]['nut'].get('svc') != F3[e['b']]['nut'].get('svc')]
G4['canh_cheo_microservice'] = {'V1': len(xs), 'V1_intra': len(xs_intra), 'chi_tiet': xs[:5]}
v21c = G4['v21_cong_bo']; v3x = G4['v30']
G4['34B_dat'] = {'M2_cu_3app >= 4/56 (v2.1)': v3x['M2_cu_3app'][0] >= 4, 'M2_dieu_kien_canh_3app >= 5/6': v3x['M2_dieu_kien_canh_3app'][0] >= 5, 'M2_dieu_kien_canh_crAPI >= 3/3': v3x['M2_dieu_kien_canh_crAPI'][0] >= 3,
                 'tong dieu kien >= 8/9': v3x['M2_dieu_kien_canh_3app'][0] + v3x['M2_dieu_kien_canh_crAPI'][0] >= 8, 'cum_nhieu_thu_thach <= 1 (tong 4 app)': sum(v3x['cum_nhieu_thu_thach'][a][0] for a in APPS4) <= 1, '0_canh_cheo': len(xs) + len(xs_intra) == 0,
                 'v21_cum_nhieu_thu_thach_tong': sum(v21c['cum_nhieu_thu_thach'][a][0] for a in APPS4)}
G4['dat_theo_chu_phieu'] = {'3app>=27/56': G4['v30']['M2_cu_3app'][0] >= 27, 'crAPI>=10/15': G4['v30']['M2_cu_crAPI'][0] >= 10, '0_canh_cheo': len(xs) + len(xs_intra) == 0}
res['G4'] = G4
# ======================= Juice Shop: G2, G3 =======================
T = json.load(open(J + '/doi_chieu/canh_bao_tho.json')); REF = json.load(open(J + '/doi_chieu/lien_ket_tham_chieu.json'))
CK = {(c['cong_cu'], c['tep'], c['dong'], c['rule']): c['id'] for c in T['code']}; DK = collections.defaultdict(set)
for d in T['dong']: DK[(d['plugin'], re.sub(r'^https?://[^/]+', '', d['url_vi_du']).split('?')[0])].add(d['id'])
def cid(f):
    a = f['anchors']; return CK.get((f['tool'], re.sub(r'^/?juiceshop/', '', a['file_path'] or ''), a['line_start'], f['raw_rule_id'] if f['tool'] == 'codeql' else f['raw_rule_id'].split('.')[-1]))
ref_loi = {(r['c'], r['d']) for r in REF if r['muc'] == 'cung_loi'}; ref_all = {(r['c'], r['d']) for r in REF}
def g2(path):
    R = json.load(open(path)); F = {f['finding_id']: f for f in R['phat_hien']}; E = set(); EL = set()
    for e in R['canh']:
        if e['luat'] not in ('V1', 'L1'): continue
        a, b = F[e['a']], F[e['b']]
        if a['phase'] == 'TEST': a, b = b, a
        if a['phase'] != 'CODE' or b['tool'] != 'zap': continue
        c = cid(a)
        for d in DK.get((b['raw_rule_id'], b['anchors']['url_route']), ()):
            E.add((c, d))
            if e.get('nhan', 'cung_loi') == 'cung_loi' or e['luat'] == 'L1': EL.add((c, d))
    tp = len(E & ref_all); P = tp / len(E) if E else 0; Rc = tp / len(ref_all); F1 = 2 * P * Rc / (P + Rc) if P + Rc else 0
    return {'canh_C_D': len(E), 'tp': tp, 'precision': [tp, len(E), wilson(tp, len(E))], 'recall': [tp, len(ref_all), wilson(tp, len(ref_all))], 'F1': round(F1, 3),
            'cung_loi': [len(EL & ref_loi), len(ref_loi), wilson(len(EL & ref_loi), len(ref_loi))], 'cung_loi_canh_phat_ra': [len(EL & ref_loi), len(EL)],
            'sot_cung_loi': sorted(ref_loi - EL), 'thua_so_voi_tham_chieu': len(E - ref_all), 'sot': sorted(ref_all - E)}
G2 = {'v14c': g2(B + '/x/buoc31_juiceshop/kq_b31/kq/v14c_JuiceShop.json'), 'v21': g2(B + '/kq/v21_JuiceShop.json'), 'v30': g2(f'{KQ3}/v3_JuiceShop.json')}
v = G2['v30']; G2['dat_theo_chu_phieu'] = {'precision>=0.75': v['tp'] / max(1, v['canh_C_D']) >= .75, 'recall>=0.85 (>=29/34)': v['tp'] >= 29, 'F1>=0.80': v['F1'] >= .80, 'cung_loi>=12/13': v['cung_loi'][0] >= 12}
res['G2'] = G2
GJ = json.load(open(J + '/dap_an_juiceshop.json'))['thu_thach']; five = [205, 209, 211, 212, 220]
def g3(path, vts=five, chat=False, hd=False):
    """chat=True (phiếu 34B 2.1): chỉ xét chạm chặt (cùng họ CWE của thử thách) khi gán cụm và đo độ tinh khiết."""
    R = json.load(open(path)); F = {f['finding_id']: f for f in R['phat_hien']}; Tt = touches(R, GJ, hd); size = collections.Counter(f['cum'] for f in R['phat_hien'])
    out = {}; owner = collections.defaultdict(set)
    for g in GJ:
        for i in Tt[g['id']][1 if chat else 0]: owner[F[i]['cum']].add(g['id'])
    for gid in vts:
        lo, ch = Tt[gid]; cl = collections.defaultdict(list)
        for i in (ch if chat else lo): cl[F[i]['cum']].append(i)
        best = None
        for c, ids in cl.items():
            ph = {F[i]['phase'] for i in ids}
            if len(ph) >= 2: best = (c, ids, sorted(ph)); break
        out[gid] = {'cham_lo': len(lo), 'cham_chat': len(ch), 'cum_tier1': (None if not best else {'cum': best[0], 'kich_thuoc_cum': size[best[0]], 'pha': best[2], 'cham_cac_thu_thach_trong_cum': sorted(owner[best[0]]),
                                                                                                    'tier': F[best[1][0]]['tier']})}
    t1 = [g for g in vts if out[g]['cum_tier1'] and out[g]['cum_tier1']['tier'] == 1]
    tinh_khiet = [g for g in t1 if set(out[g]['cum_tier1']['cham_cac_thu_thach_trong_cum']) & set(vts) == {g}]
    cums = {out[g]['cum_tier1']['cum'] for g in t1}
    return {'chi_tiet': out, 'bat_Tier1': len(t1), 'nhan_vao_cum_rieng_va_tinh_khiet': len(tinh_khiet), 'so_cum_hat_nhan_khac_nhau': len(cums), 'cum_lon_nhat': max(size.values()),
            'cum_cham_nhieu_thu_thach': [c for c, s in owner.items() if len(s) > 1 and size[c] > 1 and len(s & set(vts)) > 1]}
G3 = {'v14c': g3(B + '/x/buoc31_juiceshop/kq_b31/kq/v14c_JuiceShop.json'), 'v21': g3(B + '/kq/v21_JuiceShop.json'), 'v30': g3(f'{KQ3}/v3_JuiceShop.json')}
G3['dat_theo_chu_phieu'] = {'5/5 o Tier 1': G3['v30']['bat_Tier1'] == 5, '5 cum hat nhan doc lap, 100% tinh khiet': G3['v30']['nhan_vao_cum_rieng_va_tinh_khiet'] == 5 and G3['v30']['so_cum_hat_nhan_khac_nhau'] == 5}
# phiếu 34B mục 2.1: 3 vị trí đa pha (205, 209, 211), chạm chặt
three = [205, 209, 211]
G3['34B_3vi_tri_cham_chat'] = {k: g3(pth, three, True) for k, pth in (('v14c', B + '/x/buoc31_juiceshop/kq_b31/kq/v14c_JuiceShop.json'), ('v21', B + '/kq/v21_JuiceShop.json'), ('v30', f'{KQ3}/v3_JuiceShop.json'))}
G3['34B_3vi_tri_cham_chat_ho_hieu_dung'] = {'v30': g3(f'{KQ3}/v3_JuiceShop.json', three, True, True)}   # hậu nghiệm: chạm chặt dùng họ hiệu dụng (1.3) của v3.1
G3['34B_dat_ho_hieu_dung'] = {k: (G3['34B_3vi_tri_cham_chat_ho_hieu_dung']['v30'][kk] ) for k, kk in (('bat_Tier1', 'bat_Tier1'), ('tinh_khiet', 'nhan_vao_cum_rieng_va_tinh_khiet'), ('so_cum_hat_nhan', 'so_cum_hat_nhan_khac_nhau'))}
w = G3['34B_3vi_tri_cham_chat']['v30']; G3['34B_dat'] = {'3/3 o Tier 1': w['bat_Tier1'] == 3, '3 cum hat nhan doc lap, tinh khiet 100%': w['nhan_vao_cum_rieng_va_tinh_khiet'] == 3 and w['so_cum_hat_nhan_khac_nhau'] == 3}
res['G3'] = G3
# ======================= G1: tự động + mẫu cho người kiểm độc lập =======================
RJ = json.load(open(f'{KQ3}/v3_JuiceShop.json')); FJ = {f['finding_id']: f for f in RJ['phat_hien']}
chinh = [e for e in RJ['canh'] if e['luat'] == 'V1']
bad_status = [e for e in chinh if any(re.search(r'\bstatus\(\)', x) and '2fa' in x for x in e['bang_chung'])]
bad_ftp = [e for e in chinh if FJ[e['a']]['phase'] != 'TEST' and any('/ftp/quarantine' in (FJ[x]['anchors']['url_route'] or '') for x in (e['a'], e['b'])) and any('servePublicFiles' in str(y) or 'fileServer.ts' in str(y) for y in e['bang_chung'])]
bad_ftp += [e for e in chinh if any('/ftp/quarantine' in (FJ[x]['anchors']['url_route'] or '') for x in (e['a'], e['b'])) and any('routes/fileServer.ts' in y and 'E1' in y for y in e['bang_chung']) and e not in bad_ftp]
rnd = random.Random(34); samp = rnd.sample(chinh, min(30, len(chinh))); mau = []
for i, e in enumerate(samp, 1):
    a, b = FJ[e['a']], FJ[e['b']]
    if a['phase'] == 'TEST': a, b = b, a
    mau.append({'id': f'V3-V1-{i}', 'repo': B + '/juiceshop', 'canh_bao_A': {'tool': a['tool'], 'rule': a['raw_rule_id'], 'file': a['anchors']['file_path'], 'line': a['anchors']['line_start'], 'url': None},
                'canh_bao_B': {'tool': b['tool'], 'rule': b['raw_rule_id'], 'file': None, 'line': None, 'url': b['anchors']['url_route']}, 'bang_chung': e['bang_chung']})
json.dump({'mau': [['E1_E6_V1', mau]], 'ghi_chu': 'Mẫu ngẫu nhiên (seed 34) 30 cạnh V1 của v3.0 trên Juice Shop; người kiểm độc lập không được đọc mã sinh cạnh.'}, open(OUT + '/kiem/mau_canh_v3.json', 'w'), ensure_ascii=False, indent=1)
kiem_p = OUT + '/kiem/kiem_doc_lap_v3.json'; kd = None
if os.path.exists(kiem_p):
    K = json.load(open(kiem_p)); kd = [sum(1 for k in K if k['ket_luan'] == 'dung'), len(K)]
G1 = {'so_canh_V1': len(chinh), 'canh_sai_do_res_status_tu_dong': len(bad_status), 'canh_sai_do_ftp_quarantine_tu_dong': len(bad_ftp),
      'v21_tham_chieu': '19/30 (63.3%), 11 cạnh sai', 'mau_nguoi_kiem': (kd + [wilson(*kd)]) if kd else 'chưa kiểm'}
if kd: G1['dat_theo_chu_phieu'] = {'>=90%': kd[0] / kd[1] >= 0.9, '0 cạnh sai do res.status/ftp (tự động)': len(bad_status) + len(bad_ftp) == 0}
res['G1'] = G1
# ======================= G5: giá trị khi không có quét động =======================
cf = [f for f in RJ['phat_hien'] if f['phase'] == 'CODE' and 'codefixes' in (f['anchors']['file_path'] or '')]
m4 = [f for f in cf if f['muc_phoi_nhiem_tinh'] == 'M4_UNPACKAGED_DEAD']
m4_all = [f for f in RJ['phat_hien'] if f.get('muc_phoi_nhiem_tinh') == 'M4_UNPACKAGED_DEAD']
RB = json.load(open(f'{KQ3}/v3_AIBook.json')); FBk = {f['finding_id']: f for f in RB['phat_hien']}
cleaned = sorted(f['finding_id'] for f in RB['phat_hien'] if f.get('da_lam_sach'))
exp = sorted(f['finding_id'] for f in RB['phat_hien'] if f['phase'] == 'CODE' and (f['anchors']['file_path'] or '').endswith('server.js') and f['anchors']['line_start'] == 86 and f['family'] == 'path')
G5 = {'codefixes_tong': len(cf), 'codefixes_vao_M4': [len(m4), len(cf), wilson(len(m4), len(cf))], 'M4_tong_JuiceShop': len(m4_all), 'M4_ngoai_codefixes': sorted({(f['anchors']['file_path'], f['ly_do_muc']) for f in m4_all if 'codefixes' not in (f['anchors']['file_path'] or '')})[:10],
      'Bai4_da_lam_sach': cleaned, 'Bai4_ky_vong_path_traversal_server.js:86': exp, 'Bai4_phan_loai_muc': RB['muc_phoi_nhiem_tinh'], 'Bai4_chi tiet': [(f['finding_id'], f['anchors']['line_start'], f['family'], f.get('sanitizer_hint')) for f in RB['phat_hien'] if f.get('da_lam_sach')]}
G5['dat_theo_chu_phieu'] = {'100% codefixes -> M4': len(cf) > 0 and len(m4) == len(cf), 'dung 2 canh bao path traversal server.js:86 duoc gan da_lam_sach': cleaned == exp and len(exp) == 2}
res['G5'] = G5
res['G5']['luu_y_goc'] = 'Nhãn M1/M2 (có/không middleware xác thực) và M3 chưa có đáp án chuẩn; chỉ báo cáo phân bố.'
json.dump(res, open(OUT + '/ket_qua_b34.json', 'w'), ensure_ascii=False, indent=1, default=list)
for k in ('G1', 'G2', 'G3', 'G4', 'G5'): print(k, json.dumps(res[k], ensure_ascii=False, default=list)[:1800]); print()
