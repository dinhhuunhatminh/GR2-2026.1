"""Bước 33.2 – dựng đặc trưng x_v, x_t và ba trục nhãn (A, B, C). Xem PHIEU_BUOC33.md và PHU_LUC_QUYET_DINH_TRUOC_KHI_CHAY.md.
Nguyên tắc chống rò rỉ (H1):
  - x_v chỉ gồm: SVD văn bản advisory (đã xóa CWE/CVE/GHSA/URL), SVD mã trước vá (đã xóa CWE/CVE/GHSA), cờ có mã,
    one-hot 5 ngôn ngữ, cờ nguồn, log(1+kb), cờ thiếu kb. KHÔNG có severity, CVSS, CVE, K, n_tep/n_hunk/n_dong, năm, họ lỗi, nhãn y*.
  - TF-IDF/SVD/chuẩn hóa chỉ fit trên tập train của fold (hàm xv_fold).
  - Nhãn chỉ nằm trong các mảng LAB_*, không bao giờ nối vào x."""
import os, re, sys, json, math, collections
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.decomposition import TruncatedSVD

U = os.environ.get('B33_DATA', '/mnt/user-data/uploads/GR2/Dataset')
sys.path.insert(0, '/home/claude/b28/lib')
from fam2 import family2
from hcl import SAST, LANGS

T = json.load(open(U + '/buoc5_mcp/mcp_chon_cong_cu_v8/data/table_gop_v7.json', encoding='utf-8'))
A = json.load(open('/home/claude/b28/d1_advisory.json', encoding='utf-8'))
MA = json.load(open('/home/claude/b28/d1c_ma.json', encoding='utf-8'))
MD = json.load(open(U + '/buoc33_hcl_da_nhan_cong_cu/data/d33_metadata_bo_sung.json', encoding='utf-8'))['du_lieu']
V = json.load(open('/home/claude/b29/viec.json', encoding='utf-8'))
NH = json.load(open(U + '/buoc29_nhan_ham_hcl_mitre/ket_qua/nhan_y_ham_dot3.json', encoding='utf-8'))
CAT = json.load(open(U + '/buoc13_canh_bao/catalog_v6.json', encoding='utf-8'))
n = len(T)
assert len(A) == n == len(MD) == len(V) and all(t['ghsa'] == a['ghsa'] == m['ghsa'] == v['ghsa'] for t, a, m, v in zip(T, A, MD, V))
TOOLS = ['semgrep', 'codeql', 'bandit', 'njsscan', 'eslint_security', 'eslint_mo_rong']
assert set(TOOLS) == set(SAST)
TI = {t: j for j, t in enumerate(TOOLS)}
LI = {l: j for j, l in enumerate(LANGS)}
LANG = np.array([LI[t['lang']] for t in T])

# ---------------- làm sạch văn bản (H1) ----------------
import unicodedata
RE_CWE = re.compile(r'CWE[^.\n]{0,80}', re.I)            # sau H1 lần 1: xóa cả tên loại lỗi đi kèm "CWE"
RE_CVE = re.compile(r'CVE\s*[-_\u2010-\u2015\u2011]\s*\d{4}\S*', re.I)
RE_GHSA = re.compile(r'GHSA(?:\s*[-_\u2010-\u2015\u2011]\s*[a-z0-9]{2,4})+', re.I)
RE_URL = re.compile(r'(?:https?:)?//\S+|www\.\S+', re.I)
RE_CVSS = re.compile(r'CVSS[^\n]{0,60}|\b(?:AV|AC|PR|UI|S|C|I|A):[A-Z]\b|severity\W+\w+', re.I)
RE_SHA = re.compile(r'\b[0-9a-f]{40}\b')


def clean(s):
    s = unicodedata.normalize('NFKC', s or '')
    for r in (RE_URL, RE_CVSS, RE_CWE, RE_CVE, RE_GHSA, RE_SHA):
        s = r.sub(' ', s)
    return s


TXT = [clean(a['summary']) + ' . ' + clean(a['details']) for a in A]
CODE = [clean(MA.get(str(i), '')) for i in range(n)]
META_NAMES = [f'lang_{l}' for l in LANGS] + ['nguon_thu_vien', 'log1p_kb', 'kb_thieu']


def meta():
    rows = []
    for t in T:
        kb = t.get('kb')
        rows.append([1.0 if t['lang'] == l else 0.0 for l in LANGS] + [1.0 if t['nguon'] == 'thu_vien' else 0.0,
                     math.log1p(kb) if kb is not None else 0.0, 0.0 if kb is not None else 1.0])
    return np.array(rows, np.float32)


META = meta()


def xv_fold(tr, n_txt=128, n_code=64):
    """Fit TF-IDF+SVD+chuẩn hóa CHỈ trên chỉ số tr; trả X [n, d] cho mọi ca và tên cột."""
    tr = np.asarray(tr)
    tv = TfidfVectorizer(min_df=3, max_df=0.5, sublinear_tf=True, ngram_range=(1, 2), max_features=40000)
    Ttr = tv.fit_transform([TXT[i] for i in tr]); sv = TruncatedSVD(n_txt, random_state=0); sv.fit(Ttr)
    parts = [sv.transform(tv.transform(TXT))]; names = [f'txt{k}' for k in range(n_txt)]
    cv = TfidfVectorizer(min_df=3, max_df=0.5, sublinear_tf=True, token_pattern=r'[A-Za-z_][A-Za-z0-9_]{2,}', max_features=30000)
    Ctr = cv.fit_transform([CODE[i] for i in tr]); sc = TruncatedSVD(n_code, random_state=0); sc.fit(Ctr)
    parts.append(sc.transform(cv.transform(CODE))); names += [f'ma{k}' for k in range(n_code)]
    parts.append(np.array([[1.0 if c else 0.0] for c in CODE], np.float32)); names.append('co_ma')
    parts.append(META); names += META_NAMES
    X = np.hstack(parts).astype(np.float32); mu, sd = X[tr].mean(0), X[tr].std(0) + 1e-6
    return (X - mu) / sd, names


# ---------------- x_t ----------------
MECH = {'semgrep': 'ast', 'bandit': 'ast', 'eslint_security': 'ast', 'eslint_mo_rong': 'ast', 'codeql': 'taint', 'njsscan': 'pattern'}


def _tg(t):
    he = (CAT[t].get('thoi_gian') or {}).get('he_so') or CAT['eslint_security']['thoi_gian']['he_so']   # eslint_mo_rong không có mô hình riêng: dùng của eslint_security
    if 'san_theo_ngon_ngu_s' in he: return float(np.mean(list(he['san_theo_ngon_ngu_s'].values())))
    return float(he['a'])


def xt_tools():
    rows = []
    for t in TOOLS:
        cb = CAT[t].get('canh_bao') or {}
        rows.append([MECH[t] == 'pattern', MECH[t] == 'ast', MECH[t] == 'taint', t == 'codeql', t in ('semgrep', 'codeql'),
                     cb['ty_le_dung_mau'], math.log1p(cb['khoi_luong_trung_vi']), math.log1p(_tg(t))])
    X = np.array(rows, np.float32); sd = X.std(0); sd[sd == 0] = 1
    return (X - X.mean(0)) / sd


XT_TOOL = xt_tools()           # [6, 8] – hằng số theo công cụ, không phụ thuộc nhãn
XT_NAMES = ['mech_pattern', 'mech_ast', 'mech_taint', 'cross_file', 'multi_lang', 'precision', 'log_mat_do', 'log_tg_nen']


def xt_pair(tool_idx, lang_idx):
    oh = np.zeros((len(tool_idx), len(LANGS)), np.float32); oh[np.arange(len(tool_idx)), lang_idx] = 1
    return np.hstack([XT_TOOL[tool_idx], oh])


# ---------------- nhóm (thành phần liên thông GHSA ∪ commit) ----------------
par = {}


def _f(x):
    while par.get(x, x) != x: x = par[x]
    return x


for v in V:
    ks = ['G:' + v['ghsa']] + ['C:' + c['sha'] for c in v['commits']]
    for k in ks[1:]: par[_f(k)] = _f(ks[0])
GROUPS = np.array([_f('G:' + v['ghsa']) for v in V])

# ---------------- nhãn ----------------
FAM = [family2(t['cwe']) for t in T]
FAM_ID = {h: j for j, h in enumerate(sorted(set(FAM)))}
LAB_FAM = np.array([FAM_ID[h] for h in FAM])
CWE1 = [(sorted(set(t['cwe'])) or ['NONE'])[0] for t in T]


def _ids(keys):
    d = {}
    return np.array([d.setdefault(k, len(d)) for k in keys]), d


# Trục A (chỉ ca có vector CVSS)
VALID_A = np.array([m['has_cvss_vector'] for m in MD], bool)
SEVS = ['LOW', 'MODERATE', 'HIGH', 'CRITICAL']
LAB_K = np.array([['K1', 'K2', 'K3'].index(m['K']) for m in MD])
LAB_SEV = np.array([SEVS.index(m['severity']) for m in MD])
_c2 = [(m['K'], m['cvss']['AV'] == 'N', m['cvss']['AC'], m['cvss']['PR'] == 'N') for m in MD]
_c3 = [c2 + (m['severity'], m['cvss']['CIA_MAX'] == 'H', bool(m['has_cve'])) for c2, m in zip(_c2, MD)]
_t1 = [(m['K'],) for m in MD]
A1, _ = _ids(_t1); A2, _ = _ids(_c2); A3, _ = _ids(_c3)
LAB_A = np.stack([A1, A2, A3, np.arange(n)], 1)          # cột cuối = mẫu; tầng là tiền tố nên so bằng nhau theo từng cột đủ
LAB_C = np.stack([LAB_FAM, _ids([(f, c) for f, c in zip(FAM, CWE1)])[0], np.arange(n)], 1)

# Trục B (theo cặp)
PC, PT = [], []
for i, t in enumerate(T):
    for tl in TOOLS:
        if t['ap'].get(tl): PC.append(i); PT.append(TI[tl])
PC = np.array(PC); PT = np.array(PT); NP = len(PC)
PAIR_OF = collections.defaultdict(list)
for p, i in enumerate(PC): PAIR_OF[i].append(p)
# 1.152 ca "cve_ung_dung" KHÔNG có y_L1/y_L2s (chỉ có y chặt): coi là KHÔNG BIẾT (-1), không phải 0.
Y_L1 = np.array([T[i]['y_L1'].get(TOOLS[tl], 0) if 'y_L1' in T[i] else -1 for i, tl in zip(PC, PT)])
Y_L2S = np.array([T[i]['y_L2s'].get(TOOLS[tl], 0) if 'y_L2s' in T[i] else -1 for i, tl in zip(PC, PT)])
Y_HAM = np.full(NP, -1); Y_HO = np.full(NP, -1)
_pidx = {(int(i), TOOLS[tl]): p for p, (i, tl) in enumerate(zip(PC, PT))}
for key, v in NH.items():
    a, tl = key.split('|'); p = _pidx.get((int(a), tl))
    assert p is not None, key
    Y_HAM[p] = v['y_ham']; Y_HO[p] = v['y_ham_ho']
# y_vung = y_L2s hoặc y_ham_ho dương; âm khi biết chắc không; -1 khi không biết
Y_VUNG = np.full(NP, -1)
Y_VUNG[(Y_L2S == 0) & (Y_HO != 1)] = 0
Y_VUNG[(Y_L2S == 1) | (Y_HO == 1)] = 1
Y_VUNG[(Y_L2S == -1) & (Y_HO == 0)] = 0
_mech = [MECH[TOOLS[tl]] for tl in PT]
_b1 = [(m, int(a)) if a >= 0 else ('unk1', p) for p, (m, a) in enumerate(zip(_mech, Y_L1))]
_b2 = [b1 + (int(v),) if v >= 0 else ('unk2', p) for p, (b1, v) in enumerate(zip(_b1, Y_VUNG))]
_b3 = [b2 + ((int(h),) if h >= 0 else ('unk', p)) for p, (b2, h) in enumerate(zip(_b2, Y_HAM))]
LAB_B = np.stack([_ids(_b1)[0], _ids(_b2)[0], _ids(_b3)[0], np.arange(NP)], 1)
B3_KNOWN = Y_HAM >= 0
XT_PAIR = xt_pair(PT, LANG[PC])

if __name__ == '__main__':
    print('n', n, 'cap', NP, 'cap co y_ham', int(B3_KNOWN.sum()), 'duong y_ham', int((Y_HAM == 1).sum()), 'y_vung biet', int((Y_VUNG>=0).sum()), 'duong y_vung', int((Y_VUNG==1).sum()),
          'duong y_L1', int((Y_L1==1).sum()), 'L1 khong biet', int((Y_L1<0).sum()))
    print('ca co vector (truc A)', int(VALID_A.sum()), 'K', collections.Counter(LAB_K.tolist()), 'so nhom', len(set(GROUPS)))
    print('so lop A t1/t2/t3', [len(set(LAB_A[:, j].tolist())) for j in range(3)], 'B', [len(set(LAB_B[:, j].tolist())) for j in range(3)],
          'C', [len(set(LAB_C[:, j].tolist())) for j in range(2)])
    X, names = xv_fold(np.arange(0, n, 2))
    print('x_v', X.shape, 'x_t', XT_PAIR.shape)
