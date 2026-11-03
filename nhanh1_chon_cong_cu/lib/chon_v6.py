# -*- coding: utf-8 -*-
"""v8 (19/10/2026, bước 21): Mở rộng danh mục từ 13 lên 18 công cụ (thêm kics, grype, dockle, docker_bench, nuclei),
bổ sung dữ liệu thực nghiệm tầng 2 + bước 21 (KICS trên E5 + docker-compose; Grype & Dockle trên Release_A/B;
Docker Bench trên container runtime; Nuclei 3 lần chạy trên gr2-vulnapp; OSV-Scanner trên 91 dự án npm),
dùng bảng xác suất table_gop_v7.json (đã sửa 2 ô Go/Semgrep ở bước 19) và đồng nhất làm tròn 4 chữ số thập phân cho V.
Đầu vào: mô tả dự án (dict). Đầu ra: bộ công cụ + dấu vết. Hàm chính: chon(du_an, mo_hinh)."""
import json, os, sys, itertools, collections, math
D = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__))); from fam2 import family2
CAT = json.load(open(f'{D}/catalog.json', encoding='utf-8'))
BANG = json.load(open(f'{D}/bang_chuc_nang_ho_loi.json', encoding='utf-8'))
LANGS = ['javascript', 'typescript', 'python', 'java', 'go', 'php']
SAST = ['semgrep', 'codeql', 'bandit', 'njsscan', 'eslint_security', 'eslint_mo_rong']
# --- điều kiện áp dụng (thử thật ở bước 1 + tầng 2 + bước 21) ---
AP_LANG = {'semgrep': set(LANGS), 'codeql': {'javascript', 'typescript', 'python', 'java'}, 'bandit': {'python'}, 'njsscan': {'javascript', 'typescript'},
           'eslint_security': {'javascript'}, 'eslint_mo_rong': {'javascript'}}
LOCK_OK = {'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'requirements.txt', 'poetry.lock', 'Pipfile.lock', 'go.mod', 'composer.lock', 'Gemfile.lock', 'pom.xml',
           'gradle.lockfile', 'Cargo.lock', 'packages.lock.json'}
CFG_TYPES = ['dockerfile', 'terraform', 'cloudformation', 'k8s', 'gh_actions', 'docker_compose']
CFG_COVER = {
    'trivy': {'dockerfile', 'terraform', 'cloudformation', 'k8s'},
    'checkov': {'dockerfile', 'terraform', 'cloudformation', 'k8s', 'gh_actions'},
    'hadolint': {'dockerfile'},
    'kics': {'dockerfile', 'terraform', 'cloudformation', 'k8s', 'docker_compose'},
    'docker_bench': {'docker_compose'},
}
SECRET_TOOLS = {'gitleaks', 'trivy'}
SCA_TOOLS = {'osv-scanner', 'grype'}
DAST_TOOLS = {'zap', 'nuclei'}
IMAGE_TOOLS = {'grype', 'dockle'}

# Độ phát hiện phi mã nguồn = HỢP THỰC NGHIỆM trên từng mục của E4/E5 + Release_A/B + Deploy + DAST, không giả định độc lập.
PH = json.load(open(f'{D}/phat_hien_e4_e5.json', encoding='utf-8'))
N_SECRET = len(PH['tong_bi_mat'])
N_CFG = {k: len(v) for k, v in PH['cap_theo_loai'].items()}
N_IMG = len(PH.get('tong_container_image', [])) or 1
N_DAST = len(PH.get('tong_kiem_thu_dong', [])) or 1
_BM_SET = {t: frozenset(v) for t, v in PH['bi_mat'].items()}
_CFG_SET = {k: {t: frozenset(PH['cau_hinh'].get(t, {}).get(k, ())) for t in CAT} for k in CFG_TYPES}
_IMG_SET = {t: frozenset(v) for t, v in PH.get('container_image', {}).items()}
_DAST_SET = {t: frozenset(v) for t, v in PH.get('kiem_thu_dong', {}).items()}
_EMPTY = frozenset()

def D_phat_hien(S, tep, moi_truong_chay=False, co_lockfile=False):
    u = _EMPTY.union(*(_BM_SET.get(t, _EMPTY) for t in S)) if S else _EMPTY
    d = len(u) / N_SECRET
    for k in CFG_TYPES:
        if tep.get(k):
            ck = _CFG_SET[k]
            u = _EMPTY.union(*(ck.get(t, _EMPTY) for t in S)) if S else _EMPTY
            d += len(u) / N_CFG[k]
    if tep.get('dockerfile') and _IMG_SET:
        u = _EMPTY.union(*(_IMG_SET.get(t, _EMPTY) for t in S)) if S else _EMPTY
        d += len(u) / N_IMG
    if moi_truong_chay and _DAST_SET:
        u = _EMPTY.union(*(_DAST_SET.get(t, _EMPTY) for t in S)) if S else _EMPTY
        d += len(u) / N_DAST
    if co_lockfile:
        if 'osv-scanner' in S:
            d += 1.0
        elif 'grype' in S or 'trivy' in S:
            d += 472.0 / 473.0
    return d

BYTE_PER_LINE = {'javascript': 33.4, 'typescript': 37.1, 'python': 33.8, 'java': 36.7, 'go': 29.4, 'php': 35.2}
CO_VUA_KB = 1000          # giả định khi không biết cỡ mã (phiếu 2.5)
GOI_MAC_DINH = 44         # trung vị số gói (syft) trên 27 repo bước 1, dùng khi không biết
DONG_GOI_Y = {'xac_thuc', 'access_control', 'csrf', 'info_exposure', 'jwt_secret', 'cors', 'open_redirect'}   # họ nên kiểm thử động

class MoHinh:
    """Xác suất p[lang][tool][ho] học từ các ca (Beta-Binomial co về tỷ lệ chung của công cụ trong ngôn ngữ, kappa)."""
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
    """Thời gian dự đoán (giây) × hệ số an toàn; trả (tg, cach_tinh)."""
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
    base = a + b * x
    desc = f'{a:.2f} + {b:.5f}×{x} ({bien})'
    if tool == 'grype' and du_an['tep'].get('dockerfile'):
        phu = hs.get('phu_phi_image_s', 9.0)
        base += phu
        desc += f' + {phu:.1f}s (quét container image ở pha Release)'
    return base * an_toan, desc

def ap_dung(tool, du_an):
    """(có áp dụng không, lý do)."""
    if tool in DAST_TOOLS:
        return (bool(du_an.get('moi_truong_chay')), 'có môi trường chạy thử (URL)' if du_an.get('moi_truong_chay') else 'không có môi trường chạy thử để quét động')
    langs = set(du_an['ngon_ngu']); tep = du_an['tep']
    if tool in SAST:
        ok = langs & AP_LANG[tool]
        return (bool(ok), 'ngôn ngữ: ' + ', '.join(sorted(ok)) if ok else 'không hỗ trợ ngôn ngữ của dự án' + (' (ESLint không quét TypeScript)' if tool.startswith('eslint') and 'typescript' in langs else ''))
    if tool == 'gitleaks': return True, 'mọi repo'
    if tool == 'osv-scanner':
        lk = [x for x in tep.get('lockfile', []) if x in LOCK_OK]
        return (bool(lk), 'đọc được: ' + ', '.join(lk) if lk else 'không có lockfile/manifest có phiên bản')
    if tool == 'grype':
        lk = [x for x in tep.get('lockfile', []) if x in LOCK_OK]
        has_df = bool(tep.get('dockerfile'))
        parts = []
        if lk: parts.append('lockfile: ' + ', '.join(lk))
        if has_df: parts.append('container image (Dockerfile)')
        return (bool(parts), '; '.join(parts) if parts else 'không có lockfile/manifest có phiên bản hoặc Dockerfile/container image')
    if tool == 'dockle':
        has_df = bool(tep.get('dockerfile'))
        return (has_df, 'container image (build từ Dockerfile)' if has_df else 'không có Dockerfile/container image để kiểm tra tầng image')
    if tool in CFG_COVER:
        have = {t for t in CFG_TYPES if tep.get(t)}; cov = have & CFG_COVER[tool]
        if tool == 'trivy': return True, ('cấu hình: ' + ', '.join(sorted(cov)) + '; ' if cov else '') + 'bí mật'
        return (bool(cov), 'cấu hình: ' + ', '.join(sorted(cov)) if cov else 'không có loại tệp cấu hình mà công cụ đọc được')
    if tool == 'syft': return True, 'mọi repo (chỉ liệt kê SBOM)'
    return False, '?'

def trong_so(du_an, mh):
    """w[lang][ho]: theo chức năng (bảng bước 2) nếu có, ngược lại theo phân bố họ lỗi của ngôn ngữ."""
    f = [x for x in du_an.get('chuc_nang', []) if x in BANG['chuc_nang'] and x != 'thanh_toan']
    if f:
        w = collections.Counter()
        for x in f:
            for r in BANG['chuc_nang'][x]['ho']: w[r['ho']] += r['p']
        s = sum(w.values()); w = {h: v / s for h, v in w.items()}
        return {L: w for L in du_an['ngon_ngu']}, 'theo chức năng: ' + ', '.join(f)
    return {L: mh.lang_prior(L) for L in du_an['ngon_ngu']}, 'theo phân bố họ lỗi của ngôn ngữ (không có mô tả chức năng)'

def cham(S, ctx):
    """Khóa so sánh từ điển (phiếu 2.2 + 2.4). Lớn hơn = tốt hơn."""
    tep = ctx['du_an']['tep']
    mt = bool(ctx['du_an'].get('moi_truong_chay'))
    co_lk = ctx['vung']['thu_vien']
    areas = 0
    if ctx['vung']['ma'] and any(t in SAST for t in S): areas += 1
    if any(t in SECRET_TOOLS for t in S): areas += 1
    if co_lk and any(t in SCA_TOOLS for t in S): areas += 1
    if mt and any(t in DAST_TOOLS for t in S): areas += 1
    have_cfg = {t for t in CFG_TYPES if tep.get(t) and any(t in v for v in CFG_COVER.values())}
    if have_cfg and have_cfg <= set().union(*[CFG_COVER[t] for t in S if t in CFG_COVER] or [set()]): areas += 1
    V = ctx['V'](S); lam = ctx.get('lam', 0.0); fa = sum(ctx['sai'][t] for t in S)
    fa_ma = sum(ctx['sai'][t] for t in S if t in SAST)   # v4: lam chỉ áp lên cảnh báo sai của công cụ quét mã nguồn
    diem = round(V - lam * fa_ma, 4)                     # v8: đồng nhất làm tròn 4 chữ số thập phân (sửa lỗi F2.4 ở lam=0)
    return (areas, diem, round(D_phat_hien(S, tep, mt, co_lk), 3), -round(fa, 2), -round(sum(ctx['tg'][t] for t in S), 2))

def chon(du_an, mh, an_toan=1.3, rang_buoc_vung=True, lam=0.0):
    du_an = {'ngon_ngu': {}, 'chuc_nang': [], 'tep': {}, 'bat_buoc': [], 'cam': [], **du_an}
    tools = list(CAT)
    is_hcl = hasattr(mh, 'sim_matrix')
    ten_mh = 'hcl' if is_hcl else 'bayes'
    mo_ta_xs = (
        'Hierarchical Contrastive Learning (MoHinhHCL, bước 22) trên mặt cầu S^15 với cây phân cấp 3 tầng (6 Pillar × 23 Họ lỗi × 6 công cụ SAST) từ 7003 advisory thư viện + 1152 CVE ứng dụng thật (table_gop_v7.json)'
        if is_hcl else
        'Beta-Binomial (MoHinh Bayes) trên 7003 advisory thư viện + 1152 CVE ứng dụng thật (table_gop_v7.json – đã sửa 2 ô Go/Semgrep bước 19)'
    )
    if getattr(mh, 'ten', None): ten_mh, mo_ta_xs = mh.ten, mh.mo_ta   # v10: mô hình tự khai tên/nguồn (trước đây bảng bước 28/29 bị ghi nhầm là 'bayes')
    trace = {'dau_vao': du_an, 'tham_so': {'lam': lam, 'he_so_an_toan': an_toan, 'kappa': mh.kappa, 'rang_buoc_vung': rang_buoc_vung, 'mo_hinh_xac_suat': ten_mh},
             'phien_ban': 8, 'nguon': {
                 'do_phat_hien_bi_mat_cau_hinh': 'phat_hien_e4_e5.json: E4 (bí mật) + E5_v2 chấm chặt & bước 21 (cấu hình) + tầng 2 Release_A/B (container image) + tầng 2 Deploy (docker-compose/runtime) + tầng 2/bước 21 DAST (gr2-vulnapp)',
                 'danh_muc': 'catalog.json (18 công cụ, 6 pha DevOps: CODE, BUILD, TEST, RELEASE, DEPLOY, OPERATE)',
                 'rui_ro': 'buoc2_rui_ro/bang_chuc_nang_ho_loi.json',
                 'xac_suat': mo_ta_xs
             },
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
            elif 'lần quét' in cv['don_vi']: unit = 1 if du_an.get('moi_truong_chay') else 0
            else: unit = sum(du_an['tep'].get(k, 0) for k in CFG_TYPES if k in CFG_COVER.get(t, set()))
            sai[t] = vol * unit * (1 - prec)
    w, nguon_w = trong_so(du_an, mh); trace['trong_so'] = {'cach': nguon_w, 'w': {L: {h: round(v, 3) for h, v in sorted(x.items(), key=lambda z: -z[1])} for L, x in w.items()}}
    tot_kb = {L: (kb if kb is not None else CO_VUA_KB) for L, kb in du_an['ngon_ngu'].items()}
    share = {L: kb / sum(tot_kb.values()) for L, kb in tot_kb.items()} if tot_kb else {}
    _v_cache = {}
    sast_set = frozenset(SAST)
    def V(S):
        key = tuple(t for t in S if t in sast_set)
        if key in _v_cache: return _v_cache[key]
        v = 0.0
        for L, wL in w.items():
            for h, wh in wL.items():
                miss = 1.0
                for t in key:
                    if L in AP_LANG[t]: miss *= 1 - mh.pt(L, t, h)
                v += share[L] * wh * (1 - miss)
        _v_cache[key] = v
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
    co_lk = ap['osv-scanner'][0]
    mt = bool(du_an.get('moi_truong_chay'))
    ctx = {'lam': lam, 'du_an': du_an, 'V': V, 'tg': tg, 'sai': sai, 'vung': {'ma': bool(set(du_an['ngon_ngu']) & set(LANGS)), 'thu_vien': co_lk}}
    best = None; best_key = None
    for r in range(len(cand) + 1):
        for extra in itertools.combinations(cand, r):
            S = tuple(mand) + extra
            if sum(tg[t] for t in S) > du_an['ngan_sach'] + 1e-9: continue
            k = cham(S, ctx)
            if not rang_buoc_vung: k = k[1:]
            if best_key is None or k > best_key: best, best_key = S, k
    S = list(best)
    # --- dấu vết ---
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
            rec['dong_gop_V'] = round(V(S) - V(rest), 4)
            rec['dong_gop_D'] = round(D_phat_hien(S, du_an['tep'], mt, co_lk) - D_phat_hien(rest, du_an['tep'], mt, co_lk), 3)
            rec['vai_tro'] = ('bắt buộc; ' if t in mand else '') + ', '.join(
                [v for v, c in (
                    ('mã nguồn', t in SAST),
                    ('bí mật', t in SECRET_TOOLS),
                    ('thư viện', t in SCA_TOOLS and co_lk),
                    ('container image', t in IMAGE_TOOLS and bool(du_an['tep'].get('dockerfile'))),
                    ('cấu hình', t in CFG_COVER and t != 'docker_bench' and any(du_an['tep'].get(k) for k in CFG_COVER[t])),
                    ('vận hành container', t == 'docker_bench' and bool(du_an['tep'].get('docker_compose'))),
                    ('kiểm thử động', t in DAST_TOOLS),
                ) if c])
        else:
            rec['chon'] = False
            if not ap[t][0]: rec['ly_do_loai'] = 'không áp dụng: ' + ap[t][1]
            elif t in cam: rec['ly_do_loai'] = 'bị cấm theo yêu cầu'
            elif t == 'syft': rec['ly_do_loai'] = 'chỉ liệt kê SBOM, không phát hiện lỗi – chỉ chạy khi được yêu cầu'
            elif sum(tg[x] for x in S) + tg[t] > du_an['ngan_sach']: rec['ly_do_loai'] = f'thêm vào sẽ vượt ngân sách ({sum(tg[x] for x in S) + tg[t]:.1f}s > {du_an["ngan_sach"]}s)'
            else:
                T2 = tuple(S) + (t,)
                d_cur = D_phat_hien(S, du_an['tep'], mt, co_lk)
                d_new = D_phat_hien(T2, du_an['tep'], mt, co_lk)
                rec['ly_do_loai'] = f'không cải thiện theo thứ tự ưu tiên (thêm vào: V {V(S):.3f}→{V(T2):.3f}, D {d_cur:.3f}→{d_new:.3f}, cảnh báo sai +{sai[t]:.1f})'
        trace['cong_cu'][t] = rec
    if ctx['vung']['ma'] and not any(t in SAST for t in S):
        trace['canh_bao'].append({'ma': 'vung_ma_nguon_bo_ngo', 'noi_dung': 'Không công cụ quét mã nguồn nào vừa ngân sách – tăng ngân sách hoặc chấp nhận bỏ ngỏ.'})
    gaps = collections.defaultdict(float)
    for (L, h), (wh, c) in cov.items(): gaps[h] += share[L] * wh * (1 - c)
    trace['khoang_trong'] = [{'ho': h, 'rui_ro_con_lai': round(v, 3), 'goi_y': 'kiểm thử động (Nuclei/ZAP) hoặc review' if h in DONG_GOI_Y else ('review thủ công' if h != 'khac' else 'không phân loại được')}
                             for h, v in sorted(gaps.items(), key=lambda x: -x[1]) if v >= 0.05]
    if hasattr(mh, 'ngoai_tam_k3'):
        acc = collections.defaultdict(float); wsum = collections.defaultdict(float)
        for (L, h), (wh, c) in cov.items():
            q = mh.ngoai_tam_k3(L, h)
            if q is not None: acc[h] += share[L] * wh * (1 - c) * q; wsum[h] += share[L] * wh * (1 - c)
        for it in trace['khoang_trong']:
            if wsum.get(it['ho']): it['ty_le_ngoai_tam_sast_k3'] = round(acc[it['ho']] / wsum[it['ho']], 3)
    if 'java' in du_an['ngon_ngu'] and 'codeql' in trace['cong_cu']:
        trace['cong_cu']['codeql']['ghi_chu'] = 'Java không build được: trên OWASP Benchmark chỉ bắt 28% (Youden 0,10) – bước 4a; nếu dự án build được, CodeQL có thể tốt hơn số dùng ở đây.'
    trace['tong'] = {'thoi_gian_du_doan_s': round(sum(tg[t] for t in S), 1), 'ngan_sach_s': du_an['ngan_sach'], 'V': round(V(S), 4), 'D_bi_mat_cau_hinh': round(D_phat_hien(S, du_an['tep'], mt, co_lk), 3), 'canh_bao_sai_du_kien': round(sum(sai[t] for t in S), 1),
                     'khoa_toi_uu': list(best_key)}
    return {'chon': S, 'khong_kha_thi': False, 'trace': trace}

# ---- ba mức chịu nhiễu (PHIEU_V4 mục 3) ----
MUC_NHIEU = {'it_nhieu': 0.002, 'can_bang': 0.0005, 'bao_phu_toi_da': 0.0}
def chon_3_phuong_an(du_an, mh, **kw):
    out = {}
    for ten, lam in MUC_NHIEU.items():
        out[ten] = chon(json.loads(json.dumps(du_an)), mh, lam=lam, **kw)
    return out

if __name__ == '__main__':
    mh = MoHinh(json.load(open(f'{D}/table_gop_v7.json', encoding='utf-8')))
    r = chon({'ngon_ngu': {'php': 300}, 'chuc_nang': ['dang_nhap', 'upload', 'csdl', 'html'], 'tep': {'lockfile': ['composer.lock'], 'dockerfile': 1, 'docker_compose': 1}, 'moi_truong_chay': True, 'ngan_sach': 180}, mh)
    print(r['chon']); print(json.dumps(r['trace']['tong'], ensure_ascii=False))
    for t, v in r['trace']['cong_cu'].items(): print(t, v.get('chon'), v.get('ly_do_loai', v.get('vai_tro')), v['thoi_gian_du_doan_s'])
