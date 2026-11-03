"""Bo chon cong cu – nhanh 1 (thiet ke theo PHIEU_BUOC3.md muc 2).
Dau vao: mo ta du an (dict). Dau ra: bo cong cu + dau vet. Ham chinh: chon(du_an, mo_hinh)."""
import json, os, sys, itertools, collections, math
D = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__))); from fam2 import family2
CAT = json.load(open(f'{D}/catalog.json')); BANG = json.load(open(f'{D}/bang_chuc_nang_ho_loi.json'))
LANGS = ['javascript', 'typescript', 'python', 'java', 'go', 'php']
SAST = ['semgrep', 'codeql', 'bandit', 'njsscan', 'eslint_security', 'eslint_mo_rong']
# --- dieu kien ap dung (thu that o buoc 1, ap_dung.md) ---
AP_LANG = {'semgrep': set(LANGS), 'codeql': {'javascript', 'typescript', 'python', 'java'}, 'bandit': {'python'}, 'njsscan': {'javascript', 'typescript'},
           'eslint_security': {'javascript'}, 'eslint_mo_rong': {'javascript'}}
LOCK_OK = {'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'requirements.txt', 'poetry.lock', 'Pipfile.lock', 'go.mod', 'composer.lock', 'Gemfile.lock', 'pom.xml',
           'gradle.lockfile', 'Cargo.lock', 'packages.lock.json'}
CFG_TYPES = ['dockerfile', 'terraform', 'cloudformation', 'k8s', 'gh_actions']
CFG_COVER = {'trivy': {'dockerfile', 'terraform', 'cloudformation', 'k8s'}, 'checkov': {'dockerfile', 'terraform', 'cloudformation', 'k8s', 'gh_actions'}, 'hadolint': {'dockerfile'}}
SECRET_TOOLS = {'gitleaks', 'trivy'}
# PHIEN BAN 3: do phat hien = HOP THUC NGHIEM tren tung muc cua E4/E5 (buoc 4a), khong gia dinh doc lap.
# Ly do: phien ban 2 (gia dinh doc lap) danh gia qua cao loi ich khi them cong cu thu hai – thuc te cac cong cu bo sot cung loai (vd. mat khau trong URL CSDL).
PH = json.load(open(f'{D}/phat_hien_e4_e5.json'))
N_SECRET = len(PH['tong_bi_mat']); N_CFG = {k: len(v) for k, v in PH['cap_theo_loai'].items()}
def D_phat_hien(S, tep):
    d = len(set().union(*[set(PH['bi_mat'].get(t, [])) for t in S] or [set()])) / N_SECRET
    for k in CFG_TYPES:
        if tep.get(k):
            d += len(set().union(*[set(PH['cau_hinh'].get(t, {}).get(k, [])) for t in S] or [set()])) / N_CFG[k]
    return d
BYTE_PER_LINE = {'javascript': 33.4, 'typescript': 37.1, 'python': 33.8, 'java': 36.7, 'go': 29.4, 'php': 35.2}
CO_VUA_KB = 1000          # gia dinh khi khong biet co ma (phieu 2.5)
GOI_MAC_DINH = 44         # trung vi so goi (syft) tren 27 repo buoc 1, dung khi khong biet
DONG_GOI_Y = {'xac_thuc', 'access_control', 'csrf', 'info_exposure', 'jwt_secret', 'cors', 'open_redirect'}   # ho nen kiem thu dong

class MoHinh:
    """Xac suat p[lang][tool][ho] hoc tu cac ca (Beta-Binomial co ve ty le chung cua cong cu trong ngon ngu, kappa)."""
    def __init__(self, cases, kappa=2.0):
        self.kappa = kappa; self.p = {}; self.prior = {}
        by = collections.defaultdict(list)
        for c in cases: by[c['lang']].append(c)
        for L, cs in by.items():
            fam = [family2(c['cwe']) for c in cs]; cnt = collections.Counter(fam); n = len(cs)
            self.prior[L] = {h: k / n for h, k in cnt.items()}
            self.p[L] = {}
            for t in SAST:
                k = collections.Counter(); m = collections.Counter()
                for c, h in zip(cs, fam):
                    if c['ap'].get(t): m[h] += 1; k[h] += c['y'].get(t, 0)
                K, M = sum(k.values()), sum(m.values())
                if M == 0: continue
                r = (K + .5) / (M + 1)
                self.p[L][t] = {h: (k[h] + kappa * r) / (m[h] + kappa) for h in cnt}
    def pt(self, lang, tool, h):
        L = 'javascript' if lang == 'typescript' else lang
        return self.p.get(L, {}).get(tool, {}).get(h, 0.0)
    def lang_prior(self, lang): return self.prior.get('javascript' if lang == 'typescript' else lang, {})

def du_doan_tg(tool, du_an, an_toan):
    """Thoi gian du doan (giay) x he so an toan; tra (tg, cach_tinh)."""
    c = CAT[tool]['thoi_gian']; hs = c.get('he_so'); p90 = c['khoang_p10_p90_s'][1]
    langs = du_an['ngon_ngu']
    if tool in ('semgrep', 'codeql'):
        s = 0; cach = []
        for L, kb in langs.items():
            if L in AP_LANG[tool]:
                kb = kb if kb is not None else CO_VUA_KB; s += hs['san_theo_ngon_ngu_s'][L] + hs['b'] * kb; cach.append(f'{L}: sàn {hs["san_theo_ngon_ngu_s"][L]:.1f}s + {hs["b"]:.4f}×{kb}KB')
        return s * an_toan, '; '.join(cach)
    if not c.get('dat_T3'):
        k = max(1, sum(1 for L in langs if L in AP_LANG.get(tool, set()))) if tool in SAST else 1
        return p90 * k * an_toan, f'cận trên p90 = {p90}s (mô hình thời gian chưa đạt T3)' + (f' × {k} ngôn ngữ' if k > 1 else '')
    a, b, bien = hs['a'], hs['b'], hs['bien']
    if bien in ('kb_ngon_ngu', 'js_kb'):
        x = sum((kb if kb is not None else CO_VUA_KB) for L, kb in langs.items() if L in AP_LANG[tool])
    elif bien == 'so_goi_syft': x = du_an.get('so_goi') or GOI_MAC_DINH
    elif bien == 'tong_tep':
        if not du_an.get('tong_tep'): return p90 * an_toan, f'cận trên p90 = {p90}s (không biết số tệp)'
        x = du_an['tong_tep']
    elif bien == 'dockerfile': x = du_an['tep'].get('dockerfile', 0)
    else: x = 0
    return (a + b * x) * an_toan, f'{a:.2f} + {b:.5f}×{x} ({bien})'

def ap_dung(tool, du_an):
    """(co ap dung khong, ly do)."""
    if tool == 'zap':
        return (bool(du_an.get('moi_truong_chay')), 'có môi trường chạy thử (URL)' if du_an.get('moi_truong_chay') else 'không có môi trường chạy thử để quét động')
    langs = set(du_an['ngon_ngu']); tep = du_an['tep']
    if tool in SAST:
        ok = langs & AP_LANG[tool]
        return (bool(ok), 'ngôn ngữ: ' + ', '.join(sorted(ok)) if ok else 'không hỗ trợ ngôn ngữ của dự án' + (' (ESLint không quét TypeScript)' if tool.startswith('eslint') and 'typescript' in langs else ''))
    if tool == 'gitleaks': return True, 'mọi repo'
    if tool == 'osv-scanner':
        lk = [x for x in tep.get('lockfile', []) if x in LOCK_OK]
        return (bool(lk), 'đọc được: ' + ', '.join(lk) if lk else 'không có lockfile/manifest có phiên bản')
    if tool in CFG_COVER:
        have = {t for t in CFG_TYPES if tep.get(t)}; cov = have & CFG_COVER[tool]
        if tool == 'trivy': return True, ('cấu hình: ' + ', '.join(sorted(cov)) + '; ' if cov else '') + 'bí mật'
        return (bool(cov), 'cấu hình: ' + ', '.join(sorted(cov)) if cov else 'không có loại tệp cấu hình mà công cụ đọc được')
    if tool == 'syft': return True, 'mọi repo (chỉ liệt kê SBOM)'
    return False, '?'

def trong_so(du_an, mh):
    """w[lang][ho]: theo chuc nang (bang buoc 2) neu co, nguoc lai theo phan bo ho loi cua ngon ngu."""
    f = [x for x in du_an.get('chuc_nang', []) if x in BANG['chuc_nang'] and x != 'thanh_toan']
    if f:
        w = collections.Counter()
        for x in f:
            for r in BANG['chuc_nang'][x]['ho']: w[r['ho']] += r['p']
        s = sum(w.values()); w = {h: v / s for h, v in w.items()}
        return {L: w for L in du_an['ngon_ngu']}, 'theo chức năng: ' + ', '.join(f)
    return {L: mh.lang_prior(L) for L in du_an['ngon_ngu']}, 'theo phân bố họ lỗi của ngôn ngữ (không có mô tả chức năng)'

def cham(S, ctx):
    """Khoa so sanh tu dien (phieu 2.2 + 2.4). Lon hon = tot hon."""
    tep = ctx['du_an']['tep']
    areas = 0
    if ctx['vung']['ma'] and any(t in SAST for t in S): areas += 1
    if any(t in SECRET_TOOLS for t in S): areas += 1
    if ctx['vung']['thu_vien'] and 'osv-scanner' in S: areas += 1
    if ctx['du_an'].get('moi_truong_chay') and 'zap' in S: areas += 1
    have_cfg = {t for t in CFG_TYPES if tep.get(t) and any(t in v for v in CFG_COVER.values())}
    if have_cfg and have_cfg <= set().union(*[CFG_COVER[t] for t in S if t in CFG_COVER] or [set()]): areas += 1
    V = ctx['V'](S); lam = ctx.get('lam', 0.0); fa = sum(ctx['sai'][t] for t in S)
    fa_ma = sum(ctx['sai'][t] for t in S if t in SAST)   # v4: lam chi ap len canh bao sai cua cong cu quet ma nguon (sua 13/10, PHIEU_V4 muc 6)
    diem = round(V, 3) if lam == 0 else round(V - lam * fa_ma, 4)   # lam=0 -> giong v3
    return (areas, diem, round(D_phat_hien(S, tep), 3), -round(fa, 2), -round(sum(ctx['tg'][t] for t in S), 2))

def chon(du_an, mh, an_toan=1.3, rang_buoc_vung=True, lam=0.0):
    du_an = {'ngon_ngu': {}, 'chuc_nang': [], 'tep': {}, 'bat_buoc': [], 'cam': [], **du_an}
    tools = list(CAT)
    trace = {'dau_vao': du_an, 'tham_so': {'lam': lam, 'he_so_an_toan': an_toan, 'kappa': mh.kappa, 'rang_buoc_vung': rang_buoc_vung},
             'phien_ban': 4, 'nguon': {'do_phat_hien_bi_mat_cau_hinh': 'buoc4_kiem_chung/ket_qua_e4_e5.json (bí mật) + buoc4_kiem_chung/e5_nhan/ket_qua_e5_v2.json (cấu hình, chấm chặt)', 'danh_muc': 'buoc1_danh_muc/catalog.json', 'rui_ro': 'buoc2_rui_ro/bang_chuc_nang_ho_loi.json', 'xac_suat': 'học từ nhãn 7003 ca (Beta-Binomial)'},
             'canh_bao': [], 'cong_cu': {}}
    tg, cach_tg, ap, sai = {}, {}, {}, {}
    for t in tools:
        ok, why = ap_dung(t, du_an); ap[t] = (ok, why)
        tg[t], cach_tg[t] = du_doan_tg(t, du_an, an_toan)
        cv = CAT[t]['canh_bao']; prec = cv['ty_le_dung_mau']
        if prec is None: sai[t] = 0.0
        else:
            vol = cv['khoi_luong_trung_vi'] or 0
            if 'dòng' in cv['don_vi']:
                unit = sum((kb if kb is not None else CO_VUA_KB) * 1000 / BYTE_PER_LINE[L] / 1000 for L, kb in du_an['ngon_ngu'].items() if L in AP_LANG.get(t, set()))
            elif 'gói' in cv['don_vi']: unit = du_an.get('so_goi') or GOI_MAC_DINH
            elif 'MB' in cv['don_vi']: unit = max(sum((kb or CO_VUA_KB) for kb in du_an['ngon_ngu'].values()) / 1000, 0.1)
            elif 'Dockerfile' in cv['don_vi']: unit = du_an['tep'].get('dockerfile', 0)
            else: unit = sum(du_an['tep'].get(k, 0) for k in CFG_TYPES if k in CFG_COVER.get(t, set()))
            sai[t] = vol * unit * (1 - prec)
    if 'docker_compose' in du_an['tep'] and du_an['tep']['docker_compose']:
        trace['canh_bao'].append({'ma': 'docker_compose_khong_ho_tro', 'noi_dung': 'Có docker-compose nhưng không công cụ nào trong danh mục quét được (thử thật ở bước 1).'})
    w, nguon_w = trong_so(du_an, mh); trace['trong_so'] = {'cach': nguon_w, 'w': {L: {h: round(v, 3) for h, v in sorted(x.items(), key=lambda z: -z[1])} for L, x in w.items()}}
    tot_kb = {L: (kb if kb is not None else CO_VUA_KB) for L, kb in du_an['ngon_ngu'].items()}
    share = {L: kb / sum(tot_kb.values()) for L, kb in tot_kb.items()} if tot_kb else {}
    def V(S):
        v = 0.0
        for L, wL in w.items():
            for h, wh in wL.items():
                miss = 1.0
                for t in S:
                    if t in SAST and L in AP_LANG[t]: miss *= 1 - mh.pt(L, t, h)
                v += share[L] * wh * (1 - miss)
        return v
    mand = [t for t in du_an['bat_buoc'] if t in CAT]; cam = set(du_an['cam'])
    for t in mand:
        if not ap[t][0]: trace['canh_bao'].append({'ma': 'bat_buoc_khong_co_dau_vao', 'noi_dung': f'{t} bắt buộc nhưng dự án không có đầu vào cho nó ({ap[t][1]}); vẫn chạy theo yêu cầu.'})
        if t in cam: trace['canh_bao'].append({'ma': 'mau_thuan', 'noi_dung': f'{t} vừa bắt buộc vừa bị cấm; ưu tiên bắt buộc.'})
    if sum(tg[t] for t in mand) > du_an['ngan_sach']:
        trace['canh_bao'].append({'ma': 'khong_kha_thi', 'noi_dung': f'Công cụ bắt buộc cần {sum(tg[t] for t in mand):.1f}s (đã × {an_toan}) > ngân sách {du_an["ngan_sach"]}s.',
                                  'chi_tiet': {t: round(tg[t], 1) for t in mand}})
        return {'chon': [], 'khong_kha_thi': True, 'trace': trace}
    cand = [t for t in tools if ap[t][0] and t not in cam and t not in mand and t != 'syft']
    ctx = {'lam': lam, 'du_an': du_an, 'V': V, 'tg': tg, 'sai': sai, 'vung': {'ma': bool(set(du_an['ngon_ngu']) & set(LANGS)), 'thu_vien': ap['osv-scanner'][0]}}
    best = None; best_key = None
    for r in range(len(cand) + 1):
        for extra in itertools.combinations(cand, r):
            S = tuple(mand) + extra
            if sum(tg[t] for t in S) > du_an['ngan_sach'] + 1e-9: continue
            k = cham(S, ctx)
            if not rang_buoc_vung: k = k[1:]
            if best_key is None or k > best_key: best, best_key = S, k
    S = list(best)
    # --- dau vet ---
    cov = {}
    for L, wL in w.items():
        for h, wh in wL.items():
            miss = 1.0
            for t in S:
                if t in SAST and L in AP_LANG[t]: miss *= 1 - mh.pt(L, t, h)
            cov[(L, h)] = (wh, 1 - miss)
    for t in tools:
        rec = {'pha': CAT[t]['pha'], 'ap_dung': ap[t][0], 'ly_do_ap_dung': ap[t][1], 'thoi_gian_du_doan_s': round(tg[t], 1), 'cach_tinh_thoi_gian': cach_tg[t],
               'canh_bao_sai_du_kien': round(sai[t], 1), 'nguon_xac_suat': CAT[t]['nguon_xac_suat_bat_loi']}
        if t in S:
            rest = tuple(x for x in S if x != t); rec['chon'] = True
            rec['dong_gop_V'] = round(V(S) - V(rest), 4); rec['vai_tro'] = ('bắt buộc; ' if t in mand else '') + ', '.join(
                [v for v, c in (('mã nguồn', t in SAST), ('bí mật', t in SECRET_TOOLS), ('thư viện', t == 'osv-scanner'), ('cấu hình', t in CFG_COVER and any(du_an['tep'].get(k) for k in CFG_COVER[t])), ('kiểm thử động', t == 'zap')) if c])
        else:
            rec['chon'] = False
            if not ap[t][0]: rec['ly_do_loai'] = 'không áp dụng: ' + ap[t][1]
            elif t in cam: rec['ly_do_loai'] = 'bị cấm theo yêu cầu'
            elif t == 'syft': rec['ly_do_loai'] = 'chỉ liệt kê SBOM, không phát hiện lỗi – chỉ chạy khi được yêu cầu'
            elif sum(tg[x] for x in S) + tg[t] > du_an['ngan_sach']: rec['ly_do_loai'] = f'thêm vào sẽ vượt ngân sách ({sum(tg[x] for x in S) + tg[t]:.1f}s > {du_an["ngan_sach"]}s)'
            else:
                T2 = tuple(S) + (t,); rec['ly_do_loai'] = f'không cải thiện theo thứ tự ưu tiên (thêm vào: V {V(S):.3f}→{V(T2):.3f}, cảnh báo sai +{sai[t]:.1f})'
        trace['cong_cu'][t] = rec
    if ctx['vung']['ma'] and not any(t in SAST for t in S):
        trace['canh_bao'].append({'ma': 'vung_ma_nguon_bo_ngo', 'noi_dung': 'Không công cụ quét mã nguồn nào vừa ngân sách – tăng ngân sách hoặc chấp nhận bỏ ngỏ.'})
    gaps = collections.defaultdict(float)
    for (L, h), (wh, c) in cov.items(): gaps[h] += share[L] * wh * (1 - c)
    trace['khoang_trong'] = [{'ho': h, 'rui_ro_con_lai': round(v, 3), 'goi_y': 'kiểm thử động (ZAP, bước 4) hoặc review' if h in DONG_GOI_Y else ('review thủ công' if h != 'khac' else 'không phân loại được')}
                             for h, v in sorted(gaps.items(), key=lambda x: -x[1]) if v >= 0.05]
    if 'java' in du_an['ngon_ngu'] and 'codeql' in trace['cong_cu']:
        trace['cong_cu']['codeql']['ghi_chu'] = 'Java không build được: trên OWASP Benchmark chỉ bắt 28% (Youden 0,10) – bước 4a; nếu dự án build được, CodeQL có thể tốt hơn số dùng ở đây.'
    trace['tong'] = {'thoi_gian_du_doan_s': round(sum(tg[t] for t in S), 1), 'ngan_sach_s': du_an['ngan_sach'], 'V': round(V(S), 3), 'D_bi_mat_cau_hinh': round(D_phat_hien(S, du_an['tep']), 3), 'canh_bao_sai_du_kien': round(sum(sai[t] for t in S), 1),
                     'khoa_toi_uu': list(best_key)}
    return {'chon': S, 'khong_kha_thi': False, 'trace': trace}

if __name__ == '__main__':
    mh = MoHinh(json.load(open(f'{D}/table_7003.json')))
    r = chon({'ngon_ngu': {'php': 300}, 'chuc_nang': ['dang_nhap', 'upload', 'csdl', 'html'], 'tep': {'lockfile': ['composer.lock'], 'dockerfile': 1}, 'ngan_sach': 60}, mh)
    print(r['chon']); print(json.dumps(r['trace']['tong'], ensure_ascii=False)); print(r['trace']['khoang_trong'])
    for t, v in r['trace']['cong_cu'].items(): print(t, v.get('chon'), v.get('ly_do_loai', v.get('vai_tro')), v['thoi_gian_du_doan_s'])


# ---- v4: ba muc chiu nhieu (Claude de xuat, PHIEU_V4 muc 3) ----
MUC_NHIEU = {'it_nhieu': 0.002, 'can_bang': 0.0005, 'bao_phu_toi_da': 0.0}
def chon_3_phuong_an(du_an, mh, **kw):
    out = {}
    for ten, lam in MUC_NHIEU.items():
        out[ten] = chon(json.loads(json.dumps(du_an)), mh, lam=lam, **kw)
    return out
