"""Bước 28 – H4 (bất biến bộ chọn với mô hình mới) và H5 (7 luồng F1–F7) trên bản sao server v9.
H4: lưới 60 kịch bản × 3 mức nhiễu của bước 22.4: B1 (ngân sách + điều kiện áp dụng), F2.4 (V đơn điệu theo λ);
    so với v8: tỷ lệ lượt đổi bộ công cụ (Wilson 95%). B2 (khớp vét cạn) do người kiểm độc lập tự cài lại.
H5: mỗi luồng ≥ 1 ca, so với kỳ vọng ghi trong phiếu mục 6."""
import json, os, sys, itertools, math
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
os.environ['MCP_KHONG_GHI_LOG'] = '1'
HERE = os.path.dirname(os.path.abspath(__file__))
DIR_B33 = os.path.dirname(HERE)
V9 = os.path.join(DIR_B33, 'mcp_chon_cong_cu_v11') if os.path.exists(os.path.join(DIR_B33, 'mcp_chon_cong_cu_v11')) else '/home/claude/b33c/v11c'
OUT_KQ = os.path.join(DIR_B33, 'ket_qua') if os.path.exists(os.path.join(DIR_B33, 'ket_qua')) else '/home/claude/b33c/ket_qua'
sys.path.insert(0, V9); sys.path.insert(0, os.path.join(V9, 'lib'))
import server as S
import chon_v6 as C

def wilson(k, n, z=1.96):
    if n == 0: return [0, 0]
    p = k / n; d = 1 + z * z / n; c = p + z * z / (2 * n); r = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return [round((c - r) / d, 3), round((c + r) / d, 3)]

langs_pool = [{"javascript": 400}, {"typescript": 600}, {"python": 350}, {"java": 800}, {"go": 500}, {"php": 300},
              {"javascript": 300, "python": 300}, {"typescript": 500, "go": 400}, {"python": 250, "java": 500}, {"php": 200, "javascript": 200}]
tep_pool = [{"lockfile": ["package-lock.json"], "dockerfile": 1}, {"lockfile": ["requirements.txt"], "dockerfile": 1, "docker_compose": 1},
            {"lockfile": ["go.mod"], "terraform": 2, "k8s": 1, "gh_actions": 1}, {"lockfile": ["composer.lock"], "docker_compose": 1, "cloudformation": 1},
            {"dockerfile": 1, "docker_compose": 1, "k8s": 1, "terraform": 1, "gh_actions": 1}, {"lockfile": ["pom.xml"]}]
GRID = []
for i, (nn, tp) in enumerate(itertools.product(langs_pool, tep_pool)):
    b = [25, 60, 120, 240, 600, 1500][i % 6]
    cn = ["du_lieu", "phien_token"] if i % 3 == 0 else (["dang_nhap", "api", "csdl"] if i % 3 == 1 else ["upload", "html", "url_ngoai"])
    GRID.append({"ngon_ngu": nn, "chuc_nang": cn, "tep": tp, "moi_truong_chay": i % 2 == 0, "ngan_sach": b, "bat_buoc": [], "cam": []})

b1 = f24 = doi_v8 = doi_bayes = luot = 0; vi_du = []
for d in GRID:
    rs = C.chon_3_phuong_an(json.loads(json.dumps(d)), S.MH_HCL28)
    r8 = C.chon_3_phuong_an(json.loads(json.dumps(d)), S.MH_HCL)
    rb = C.chon_3_phuong_an(json.loads(json.dumps(d)), S.MH_BAYES)
    v = [rs[m]['trace']['tong']['V'] for m in ('it_nhieu', 'can_bang', 'bao_phu_toi_da')]
    if not (v[0] <= v[1] + 1e-9 <= v[2] + 2e-9): f24 += 1
    for m in C.MUC_NHIEU:
        Sx = rs[m]['chon']; luot += 1
        if sum(C.du_doan_tg(t, d, 1.3)[0] for t in Sx) > d['ngan_sach'] + 1e-9: b1 += 1
        b1 += sum(1 for t in Sx if not C.ap_dung(t, d)[0] and t not in d['bat_buoc'])
        if sorted(Sx) != sorted(r8[m]['chon']):
            doi_v8 += 1
            if len(vi_du) < 8: vi_du.append({'muc': m, 'du_an': {k: d[k] for k in ('ngon_ngu', 'chuc_nang', 'ngan_sach')}, 'v8': r8[m]['chon'], 'moi': Sx})
        if sorted(Sx) != sorted(rb[m]['chon']): doi_bayes += 1
H4 = {'so_luot': luot, 'B1_vi_pham': b1, 'F24_vi_pham': f24, 'doi_so_v8': [doi_v8, luot, wilson(doi_v8, luot)],
      'doi_so_bayes': [doi_bayes, luot, wilson(doi_bayes, luot)], 'vi_du_doi_so_v8': vi_du}
print('H4', json.dumps({k: v for k, v in H4.items() if k != 'vi_du_doi_so_v8'}))

# ---------------- H5: 7 luồng ----------------
def goi(**kw): return S.chon_cong_cu(**kw)
H5 = []
def ghi(ma, mo_ta, dat, bang_chung):
    H5.append({'luong': ma, 'mo_ta': mo_ta, 'dat': bool(dat), 'bang_chung': bang_chung}); print(ma, 'DAT' if dat else 'KHONG DAT', bang_chung)

r = goi(ngon_ngu={'python': 300}, chuc_nang=['dang_nhap', 'csdl'], tep={'lockfile': ['requirements.txt'], 'dockerfile': 1}, ngan_sach_giay=180)
ghi('F1', 'luồng chính: đủ trường', r.get('kha_thi') and r['chon'] and 'V=' in r['tom_tat'] and 'cảnh báo sai' in r['tom_tat'] and r['dau_vet'],
    {'chon': r.get('chon'), 'V': r.get('phuong_an', {}).get('can_bang', {}).get('V')})
# F2: tìm một dự án có ô ít mẫu được dùng
f2 = None
for L, kb in (('go', 400), ('java', 600), ('php', 300), ('python', 300), ('javascript', 300)):
    for cn in (['du_lieu'], ['phan_quyen', 'tai_khoan'], ['url_ngoai'], ['upload', 'tep'], ['html', 'csdl']):
        r = goi(ngon_ngu={L: kb}, chuc_nang=cn, ngan_sach_giay=600)
        if r.get('o_it_mau'): f2 = (L, cn, r); break
    if f2: break
if f2:
    L, cn, r = f2; x = r['o_it_mau'][0]
    ghi('F2', 'ô < 5 mẫu', x['so_mau'] < 5 and x['do_tin_cay'] == 'thấp' and x['ho_lang_gieng'] and 'Ô ít mẫu' in r['tom_tat'],
        {'du_an': {L: cn}, 'o': x})
else:
    ghi('F2', 'ô < 5 mẫu', False, 'không tìm được dự án dùng ô ít mẫu')
r = goi(ngon_ngu={'javascript': 300}, ngan_sach_giay=0.5)
ghi('F3', 'ngân sách < công cụ rẻ nhất', ('loi' not in r) and not r.get('chon') and 'KHÔNG chọn được công cụ nào' in (r.get('tom_tat') or ''),
    {'kha_thi': r.get('kha_thi'), 'chon': r.get('chon'), 'tom_tat_dau': (r.get('tom_tat') or str(r.get('loi')))[:160]})
r1 = goi(ngon_ngu={'javascript': 300}, bat_buoc=['zap'], ngan_sach_giay=30, moi_truong_chay=True)
r2 = goi(ngon_ngu={'javascript': 300}, bat_buoc=['semgrep'], cam=['semgrep'], ngan_sach_giay=300)
noi_bo = lambda x: any('lỗi nội bộ' in str(e) for e in x.get('loi', []))
ghi('F4', 'bắt buộc vượt ngân sách / trùng cấm', r1.get('kha_thi') is False and not noi_bo(r1) and 'Xung đột' in r1['tom_tat'] and 'zap' in r1['tom_tat'] and 'loi' in r2 and not noi_bo(r2) and any('vừa bắt buộc vừa cấm' in x and 'semgrep' in x for x in r2['loi']),
    {'vuot': (r1.get('tom_tat') or str(r1.get('loi')))[:160], 'trung': r2.get('loi')})
r1 = goi(ngon_ngu={'rust': 300}, tep={'lockfile': ['Cargo.lock']}, ngan_sach_giay=300)
r2 = goi(ngon_ngu={'go': 300}, ngan_sach_giay=600)
ld = r2['dau_vet']['cong_cu'].get('codeql', {})
ghi('F5', 'ngôn ngữ ngoài phạm vi; Go + CodeQL', 'codeql' not in (r2.get('chon') or []) and bool(ld.get('ly_do_loai')) and any('rust' in x for x in r1.get('canh_bao_dau_vao', [])) and 'rust' in r1['tom_tat'] and not any(t in (r1.get('chon') or []) for t in C.SAST),
    {'rust_canh_bao': r1.get('canh_bao_dau_vao'), 'rust_chon': r1.get('chon'), 'go_chon': r2.get('chon'), 'codeql_ly_do_loai': ld.get('ly_do_loai')})
r = goi(ngon_ngu={'php': 300}, chuc_nang=['thanh_toan', 'csdl'], ngan_sach_giay=300)
ghi('F6', 'chức năng chưa có dữ liệu', r.get('chuc_nang_chua_co_du_lieu') == ['thanh_toan'] and 'chưa có dữ liệu rủi ro nên KHÔNG được tính vào V: thanh_toan' in r['tom_tat'] and 'khoảng trống' in r['tom_tat'],
    {'chuc_nang_chua_co_du_lieu': r.get('chuc_nang_chua_co_du_lieu')})
re_ = goi(ngon_ngu=['python'], ngan_sach_giay=100); rf = goi(ngon_ngu={'python': 300}, chuc_nang='csdl', ngan_sach_giay=100)
ra = goi(ngon_ngu={'python': 'nhieu'}, ngan_sach_giay=100); rb_ = goi(ngon_ngu={'python': 300}, chuc_nang=['bay'], ngan_sach_giay=100)
rc = goi(ngon_ngu={'python': 300}, ngan_sach_giay=100, mo_hinh_xac_suat='abc'); rd = goi(ngon_ngu={'python': 300})
ghi('F7', 'sai kiểu / thiếu trường', all('loi' in x and not noi_bo(x) for x in (ra, rb_, rc, rd, re_, rf)),
    {'kieu': ra.get('loi'), 'chuc_nang': rb_.get('loi'), 'mo_hinh': rc.get('loi'), 'thieu_ngan_sach': rd.get('loi'), 'ngon_ngu_list': re_.get('loi'), 'chuc_nang_chuoi': rf.get('loi')})
json.dump({'H4': H4, 'H5': H5}, open(os.path.join(OUT_KQ, 'h5_b33b.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=1, default=str)
