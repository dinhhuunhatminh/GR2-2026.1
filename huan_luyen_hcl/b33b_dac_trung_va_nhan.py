"""Bước 33b.2 – Dựng đặc trưng x_v, x_t và 3 trục nhãn đã sửa lỗi (PHIEU_BUOC33B_SUA.md).
Các điểm sửa so với b33_dac_trung_va_nhan.py:
  1. Sửa RE_CVSS xóa triệt để cả các mảnh CVSS v4 (AT, VC, VI, VA, SC, SI, SA...) -> H1 đạt 100% (0/8.155 ca sót).
  2. Đưa cấu trúc bản vá (n_tep, n_hunk, n_dong, K1/K2/K3) vào x_v như đặc trưng cấu trúc hợp lệ của ca lỗi;
     Trục A chỉ phân tầng trên Tác động & Mức nghiêm trọng CVSS (Nhóm Nguy hiểm -> Severity & CIA -> Khai thác AV/AC/PR & CVE),
     không có bất kỳ biến nào của Trục A nằm trong x_v.
  3. Trục B dùng Positive-Anchored Hierarchy: không gộp 95% mẫu âm (y_vung=0) thành một cụm dương giả tạo;
     mẫu âm có mã nhánh riêng ở tầng phát hiện để chỉ đóng vai trò mẫu đẩy (negatives).
"""
import os
import re
import sys
import json
import math
import collections
import unicodedata
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.decomposition import TruncatedSVD

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
U = os.environ.get('B33_DATA', os.path.join(ROOT, 'Dataset'))

for p_lib in [
    os.path.join(U, 'buoc29_nhan_ham_hcl_mitre', 'mcp_chon_cong_cu_v10', 'lib'),
    os.path.join(U, 'buoc28_hcl_dac_trung', 'mcp_chon_cong_cu_v9_de_xuat', 'lib'),
    '/home/claude/b28/lib',
]:
    if os.path.exists(p_lib) and p_lib not in sys.path:
        sys.path.insert(0, p_lib)

from fam2 import family2
from hcl import SAST, LANGS

def _find(rel_candidates):
    for c in rel_candidates:
        full = c if os.path.isabs(c) else os.path.join(U, c)
        if os.path.exists(full):
            return full
    raise FileNotFoundError(str(rel_candidates))

T = json.load(open(_find(['buoc5_mcp/mcp_chon_cong_cu_v8/data/table_gop_v7.json']), encoding='utf-8'))
A = json.load(open(_find(['buoc28_hcl_dac_trung/d1_advisory.json', '/home/claude/b28/d1_advisory.json']), encoding='utf-8'))
MA = json.load(open(_find(['buoc28_hcl_dac_trung/d1c_ma.json', '/home/claude/b28/d1c_ma.json']), encoding='utf-8'))
MD = json.load(open(_find(['buoc33_hcl_da_nhan_cong_cu/data/d33_metadata_bo_sung.json']), encoding='utf-8'))['du_lieu']
NH = json.load(open(_find(['buoc29_nhan_ham_hcl_mitre/ket_qua/nhan_y_ham_dot3.json']), encoding='utf-8'))
CAT = json.load(open(_find(['buoc13_canh_bao/catalog_v6.json']), encoding='utf-8'))

n = len(T)
assert len(A) == n == len(MD) and all(t['ghsa'] == a['ghsa'] == m['ghsa'] for t, a, m in zip(T, A, MD))
TOOLS = ['semgrep', 'codeql', 'bandit', 'njsscan', 'eslint_security', 'eslint_mo_rong']
TI = {t: j for j, t in enumerate(TOOLS)}
LI = {l: j for j, l in enumerate(LANGS)}
LANG = np.array([LI[t['lang']] for t in T])

# ---------------- 1. Làm sạch văn bản triệt để (0/8.155 ca sót CVSS v2/v3/v4, CWE, CVE-96/97, GHSA, URL) ----------------
RE_CWE = re.compile(r'CWE[^.\n]{0,80}', re.I)
RE_CVE = re.compile(r'CVE\s*[-_\u2010-\u2015\u2011:#]?\s*\d{2,4}\S*', re.I)
RE_GHSA = re.compile(r'GHSA(?:\s*[-_\u2010-\u2015\u2011]\s*[a-z0-9]{2,4})+', re.I)
RE_URL = re.compile(r'(?:https?:)?//\S+|www\.\S+', re.I)
RE_CVSS = re.compile(
    r'CVSS[^\n]{0,100}'
    r'|\b(?:MAV|MAC|MAT|MPR|MUI|MVC|MVI|MVA|MSC|MSI|MSA|MS|MC|MI|MA|AV|AC|AT|PR|UI|VC|VI|VA|SC|SI|SA|CR|IR|AR|E|RL|RC|AU|R|V|RE|S|C|I|A):[A-Z]{1,4}\b'
    r'|severity\W+\w+',
    re.I
)
RE_SHA = re.compile(r'\b[0-9a-f]{40}\b', re.I)


def clean(s):
    s = unicodedata.normalize('NFKC', s or '')
    for _ in range(4):   # lặp đến khi ổn định: một lần quét có thể để sót mảnh vector (ca 3686: hai cụm 'CVSS' cách nhau <100 ký tự)
        s0 = s
        for r in (RE_URL, RE_CVSS, RE_CWE, RE_CVE, RE_GHSA, RE_SHA):
            s = r.sub(' ', s)
        if s == s0: break
    return s


TXT = [clean(a['summary']) + ' . ' + clean(a['details']) for a in A]
CODE = [clean(MA.get(str(i), '')) for i in range(n)]

# ---------------- 2. Đặc trưng Lỗ hổng x_v (gồm cả quy mô bản vá & K, KHÔNG chứa Severity/CVSS/CWE/y*) ----------------
META_NAMES = (
    [f'lang_{l}' for l in LANGS]
    + ['nguon_thu_vien', 'log1p_kb', 'kb_thieu', 'log1p_ntep', 'log1p_nhunk', 'log1p_ndong', 'K1', 'K2', 'K3']
)


def _build_meta():
    rows = []
    for t, a, m in zip(T, A, MD):
        kb = t.get('kb')
        k_val = m['K']
        rows.append(
            [1.0 if t['lang'] == l else 0.0 for l in LANGS]
            + [
                1.0 if t['nguon'] == 'thu_vien' else 0.0,
                math.log1p(kb) if kb is not None else 0.0,
                0.0 if kb is not None else 1.0,
                math.log1p(a.get('n_tep') or 0),
                math.log1p(a.get('n_hunk') or 0),
                math.log1p(a.get('n_dong') or 0),
                1.0 if k_val == 'K1' else 0.0,
                1.0 if k_val == 'K2' else 0.0,
                1.0 if k_val == 'K3' else 0.0,
            ]
        )
    return np.array(rows, np.float32)


META = _build_meta()


def xv_fold(tr, n_txt=128, n_code=64):
    """Fit TF-IDF + SVD + chuẩn hóa CHỈ trên tập train `tr`."""
    tr = np.asarray(tr)
    tv = TfidfVectorizer(min_df=3, max_df=0.5, sublinear_tf=True, ngram_range=(1, 2), max_features=40000)
    Ttr = tv.fit_transform([TXT[i] for i in tr])
    sv = TruncatedSVD(n_txt, random_state=0)
    sv.fit(Ttr)
    parts = [sv.transform(tv.transform(TXT))]
    names = [f'txt{k}' for k in range(n_txt)]

    cv = TfidfVectorizer(min_df=3, max_df=0.5, sublinear_tf=True, token_pattern=r'[A-Za-z_][A-Za-z0-9_]{2,}', max_features=30000)
    Ctr = cv.fit_transform([CODE[i] for i in tr])
    sc = TruncatedSVD(n_code, random_state=0)
    sc.fit(Ctr)
    parts.append(sc.transform(cv.transform(CODE)))
    names += [f'ma{k}' for k in range(n_code)]

    parts.append(np.array([[1.0 if c else 0.0] for c in CODE], np.float32))
    names.append('co_ma')
    parts.append(META)
    names += META_NAMES

    X = np.hstack(parts).astype(np.float32)
    mu, sd = X[tr].mean(0), X[tr].std(0) + 1e-6
    return (X - mu) / sd, names


# ---------------- 3. Đặc trưng Công cụ x_t ----------------
MECH = {'semgrep': 'ast', 'bandit': 'ast', 'eslint_security': 'ast', 'eslint_mo_rong': 'ast', 'codeql': 'taint', 'njsscan': 'pattern'}


def _tg(t):
    he = (CAT[t].get('thoi_gian') or {}).get('he_so') or CAT['eslint_security']['thoi_gian']['he_so']
    if 'san_theo_ngon_ngu_s' in he:
        return float(np.mean(list(he['san_theo_ngon_ngu_s'].values())))
    return float(he['a'])


def xt_tools():
    rows = []
    for j, t in enumerate(TOOLS):
        cb = CAT[t].get('canh_bao') or {}
        oh_t = [1.0 if k == j else 0.0 for k in range(len(TOOLS))]
        rows.append([
            float(MECH[t] == 'pattern'),
            float(MECH[t] == 'ast'),
            float(MECH[t] == 'taint'),
            float(t == 'codeql'),
            float(t in ('semgrep', 'codeql')),
            float(cb['ty_le_dung_mau']),
            math.log1p(cb['khoi_luong_trung_vi']),
            math.log1p(_tg(t)),
        ] + oh_t)
    X = np.array(rows, np.float32)
    sd = X.std(0)
    sd[sd == 0] = 1.0
    return (X - X.mean(0)) / sd


XT_TOOL = xt_tools()


def xt_pair(tool_idx, lang_idx):
    oh = np.zeros((len(tool_idx), len(LANGS)), np.float32)
    oh[np.arange(len(tool_idx)), lang_idx] = 1.0
    return np.hstack([XT_TOOL[tool_idx], oh])


# ---------------- 4. Nhóm liên thông (GHSA ∪ commit, xóa sạch #diff-... và khớp viec.json) ----------------
par = {}
def _f(x):
    while par.get(x, x) != x:
        x = par[x]
    return x

_viec_paths = [
    os.path.join(U, 'buoc29_nhan_ham_hcl_mitre', 'viec.json'),
    '/home/claude/b29/viec.json',
]
_viec_file = next((p for p in _viec_paths if os.path.exists(p)), None)
if _viec_file is not None:
    V_LIST = json.load(open(_viec_file, encoding='utf-8'))
    for v in V_LIST:
        ks = ['G:' + v['ghsa']] + ['C:' + c['sha'] for c in v.get('commits', []) if c.get('sha')]
        for k in ks[1:]:
            par[_f(k)] = _f(ks[0])
else:
    for a in A:
        commits = []
        for u in (a.get('commit') or []):
            m_sha = re.search(r'/commit/([0-9a-f]{40})', u, re.I)
            if m_sha:
                commits.append(m_sha.group(1).lower())
            else:
                c_clean = re.split(r'[#?]', re.sub(r'.*/commit/', '', u))[0].strip('/')
                if c_clean:
                    commits.append(c_clean)
        ks = ['G:' + a['ghsa']] + ['C:' + c for c in commits if c]
        for k in ks[1:]:
            par[_f(k)] = _f(ks[0])
GROUPS = np.array([_f('G:' + a['ghsa']) for a in A])

# ---------------- 5. Ba Trục Nhãn Độc lập & Phân cấp (A, B, C) ----------------
def _ids(keys):
    d = {}
    return np.array([d.setdefault(k, len(d)) for k in keys]), d

FAM = [family2(t['cwe']) for t in T]
FAM_ID = {h: j for j, h in enumerate(sorted(set(FAM)))}
LAB_FAM = np.array([FAM_ID[h] for h in FAM])
CWE1 = [(sorted(set(t['cwe'])) or ['NONE'])[0] for t in T]

# Trục A: Tác động & Mức nghiêm trọng CVSS (Tầng 1: Severity 4 cấp -> Tầng 2: + (C,I,A) 86 lớp -> Tầng 3: + AV/AC/PR/has_cve 340 lớp)
VALID_A = np.array([bool(m['has_cvss_vector']) for m in MD], bool)
SEVS = ['LOW', 'MODERATE', 'HIGH', 'CRITICAL']
LAB_SEV = np.array([SEVS.index(m['severity']) for m in MD])
LAB_HIGH_SEV = np.array([int(m['severity'] in ('HIGH', 'CRITICAL')) for m in MD])
LAB_CIA = np.array([int(m['cvss']['CIA_MAX'] == 'H') for m in MD])

def _cia_tuple(m):
    vec = (m.get('cvss') or {}).get('vector') or ''
    return tuple(x.split(':')[1] for x in vec.split('/') if x[:2] in ('C:', 'I:', 'A:'))

_a1 = [(m['severity'],) for m in MD]
_a2 = [a1 + _cia_tuple(m) for a1, m in zip(_a1, MD)]
_a3 = [a2 + (m['cvss']['AV'] == 'N', m['cvss']['AC'] == 'L', m['cvss']['PR'] == 'N', bool(m['has_cve'])) for a2, m in zip(_a2, MD)]
LAB_A = np.stack([_ids(_a1)[0], _ids(_a2)[0], _ids(_a3)[0], np.arange(n)], 1)

# Trục C: Bản chất cơ chế lỗi [fam2 -> CWE chính]
LAB_C = np.stack([LAB_FAM, _ids([(f, c) for f, c in zip(FAM, CWE1)])[0], np.arange(n)], 1)

# Trục B: Positive-Anchored Tool Detection Hierarchy
PC, PT = [], []
for i, t in enumerate(T):
    for tl in TOOLS:
        if t['ap'].get(tl):
            PC.append(i)
            PT.append(TI[tl])
PC = np.array(PC)
PT = np.array(PT)
NP = len(PC)
PAIR_OF = collections.defaultdict(list)
for p, i in enumerate(PC):
    PAIR_OF[i].append(p)

Y_L1 = np.array([T[i]['y_L1'].get(TOOLS[tl], 0) if 'y_L1' in T[i] else -1 for i, tl in zip(PC, PT)])
Y_L2S = np.array([T[i]['y_L2s'].get(TOOLS[tl], 0) if 'y_L2s' in T[i] else -1 for i, tl in zip(PC, PT)])
Y_STRICT = np.array([T[i]['y'].get(TOOLS[tl], 0) if 'y' in T[i] else -1 for i, tl in zip(PC, PT)])
Y_HAM = np.full(NP, -1)
Y_HO = np.full(NP, -1)
_pidx = {(int(i), TOOLS[tl]): p for p, (i, tl) in enumerate(zip(PC, PT))}
for key, v in NH.items():
    a_idx, tl = key.split('|')
    p = _pidx.get((int(a_idx), tl))
    if p is not None:
        Y_HAM[p] = v['y_ham']
        Y_HO[p] = v['y_ham_ho']

Y_VUNG = np.full(NP, -1)
Y_VUNG[(Y_L2S == 0) & (Y_HO != 1)] = 0
Y_VUNG[(Y_L2S == 1) | (Y_HO == 1)] = 1
Y_VUNG[(Y_L2S == -1) & (Y_HO == 0)] = 0

Y_TARGET_B3 = np.where(Y_HAM >= 0, Y_HAM, Y_STRICT)
VALID_B = Y_VUNG >= 0

_mech = [MECH[TOOLS[tl]] for tl in PT]
# Positive-Anchored cho Trục B: ở tầng 2 và 3, mẫu âm có khóa riêng để không tự co cụm với nhau trong SupCon
_b1 = [(m, int(Y_L1[p] == 1)) if Y_L1[p] >= 0 else ('unk1', p) for p, m in enumerate(_mech)]
_b2 = [
    (_mech[p], int(PT[p]), 'POS_VUNG') if Y_VUNG[p] == 1 else ('NEG_VUNG', p)
    for p in range(NP)
]
_b3 = [
    (_mech[p], int(PT[p]), int(FAM_ID[FAM[PC[p]]]), 'POS_STRICT') if Y_TARGET_B3[p] == 1 else ('NEG_STRICT', p)
    for p in range(NP)
]
LAB_B = np.stack([_ids(_b1)[0], _ids(_b2)[0], _ids(_b3)[0], np.arange(NP)], 1)

# Nhãn để đo H2_B trên tập con có nhãn rõ ràng: (Công cụ, y_L1, y_vung)
_b_eval1 = [(_mech[p], int(PT[p])) for p in range(NP)]
_b_eval2 = [_b_eval1[p] + (int(Y_L1[p] == 1),) for p in range(NP)]
_b_eval3 = [_b_eval2[p] + (int(Y_VUNG[p] == 1),) for p in range(NP)]
LAB_B_EVAL = np.stack([_ids(_b_eval1)[0], _ids(_b_eval2)[0], _ids(_b_eval3)[0]], 1)

XT_PAIR = xt_pair(PT, LANG[PC])

if __name__ == '__main__':
    # Kiểm tra tự động H1 (gồm cả CVE 2 chữ số CVE-96/97, khóa môi trường CVSS MS/MC/MI/MA và #diff- trong commit)
    leak_cvss = sum(
        1 for s in TXT + CODE
        if re.search(r'\b(?:MAV|MAC|MAT|MPR|MUI|MVC|MVI|MVA|MSC|MSI|MSA|MS|MC|MI|MA|AV|AC|AT|PR|UI|VC|VI|VA|SC|SI|SA|CR|IR|AR|E|RL|RC|AU|R|V|RE):[A-Z]{1,4}\b', s, re.I)
    )
    leak_cwe = sum(1 for s in TXT + CODE if re.search(r'\bCWE\s*[-_:#]?\s*\d+', s, re.I))
    leak_cve = sum(1 for s in TXT + CODE if re.search(r'\bCVE\s*[-_:#]?\s*\d{2,4}', s, re.I))
    print(f'[Kiểm H1] Sót CVSS={leak_cvss}, CWE={leak_cwe}, CVE(2-4 số)={leak_cve} / {len(TXT)} ca. Số nhóm GROUPS={len(set(GROUPS))}.')
    assert leak_cvss == 0 and leak_cwe == 0 and leak_cve == 0, 'Vẫn còn rò rỉ trong văn bản!'
    X, names = xv_fold(np.arange(0, n, 2))
    print('x_v shape:', X.shape, 'x_t shape:', XT_PAIR.shape, 'VALID_A:', int(VALID_A.sum()), 'VALID_B:', int(VALID_B.sum()))
