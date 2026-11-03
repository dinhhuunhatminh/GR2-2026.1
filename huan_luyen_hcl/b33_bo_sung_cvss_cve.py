"""Bước 33 (GĐ0) – Trích xuất và bổ sung đầy đủ CVE ID, CVSS v3 Vector / Base Score (8 thành phần),
nhãn phạm vi định vị cấu trúc (K1/K2/K3) và nhãn phản hồi công cụ đa tầng cho toàn bộ 8.155 ca lỗ hổng.

Cách hoạt động:
1. Đọc 8.155 ca từ Dataset/buoc28_hcl_dac_trung/d1_advisory.json và table_gop_v7.json.
2. Quét toàn bộ các file OSV/GHSA JSON đã có sẵn trên đĩa (Dataset/tang2_build/du_lieu/osv_*/GHSA-*.json).
3. Với các mã GHSA chưa có file OSV trên đĩa, tự động gọi đa luồng API công khai của OSV.dev
   (https://api.osv.dev/v1/vulns/<GHSA_ID>) có lưu cache từng đợt để có thể dừng và chạy tiếp bất cứ lúc nào.
4. Tính điểm CVSS v3.0/v3.1 Base Score chính xác theo công thức chuẩn FIRST.org và tách 8 thành phần
   (AV, AC, PR, UI, S, C, I, A).
5. Gán nhãn phạm vi định vị K1/K2/K3 và tổng hợp nhãn công cụ đa tầng (y_L1, y_L2s, y_cu, y_ham_ho, y_ham).
6. Xuất ra Dataset/buoc33_hcl_da_nhan_cong_cu/data/d33_metadata_bo_sung.json (KHÔNG sửa bất kỳ file cũ nào).
"""
import os
import re
import sys
import json
import math
import glob
import time
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
DIR_B33 = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DATA_DIR = os.path.join(DIR_B33, 'data')
CACHE_FILE = os.path.join(DATA_DIR, 'osv_api_cache.json')
OUT_FILE = os.path.join(DATA_DIR, 'd33_metadata_bo_sung.json')

PATH_A = os.path.join(ROOT, 'Dataset', 'buoc28_hcl_dac_trung', 'd1_advisory.json')
PATH_T = os.path.join(ROOT, 'Dataset', 'buoc5_mcp', 'mcp_chon_cong_cu_v8', 'data', 'table_gop_v7.json')
PATH_YHAM = os.path.join(ROOT, 'Dataset', 'buoc29_nhan_ham_hcl_mitre', 'ket_qua', 'nhan_y_ham_dot3.json')

# ---------------- Công thức chuẩn CVSS v3.0 / v3.1 ----------------
_W_AV = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.20}
_W_AC = {'L': 0.77, 'H': 0.44}
_W_PR_U = {'N': 0.85, 'L': 0.62, 'H': 0.27}
_W_PR_C = {'N': 0.85, 'L': 0.68, 'H': 0.50}
_W_UI = {'N': 0.85, 'R': 0.62}
_W_CIA = {'H': 0.56, 'L': 0.22, 'N': 0.0}


def _roundup(val):
    int_input = round(val * 100000)
    if (int_input % 10000) == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def parse_cvss_v3(vector_str):
    """Phân tích chuỗi CVSS:3.x/AV:.../AC:... thành dict 8 thành phần + base_score + exploitability + impact."""
    if not vector_str or not isinstance(vector_str, str) or 'CVSS:3' not in vector_str:
        return None
    parts = {}
    for token in vector_str.strip().split('/')[1:]:
        if ':' in token:
            k, v = token.split(':', 1)
            parts[k.upper()] = v.upper()
    req = ('AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A')
    if not all(k in parts for k in req):
        return None
    try:
        av = _W_AV[parts['AV']]
        ac = _W_AC[parts['AC']]
        s_changed = (parts['S'] == 'C')
        pr = (_W_PR_C if s_changed else _W_PR_U)[parts['PR']]
        ui = _W_UI[parts['UI']]
        c, i, a = _W_CIA[parts['C']], _W_CIA[parts['I']], _W_CIA[parts['A']]

        isc_base = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
        if not s_changed:
            impact = 6.42 * isc_base
        else:
            impact = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)

        exploitability = 8.22 * av * ac * pr * ui
        if impact <= 0:
            base_score = 0.0
        elif not s_changed:
            base_score = _roundup(min(impact + exploitability, 10.0))
        else:
            base_score = _roundup(min(1.08 * (impact + exploitability), 10.0))

        return {
            'vector': vector_str,
            'AV': parts['AV'],
            'AC': parts['AC'],
            'PR': parts['PR'],
            'UI': parts['UI'],
            'S': parts['S'],
            'C': parts['C'],
            'I': parts['I'],
            'A': parts['A'],
            'base_score': round(base_score, 1),
            'exploitability': round(exploitability, 2),
            'impact': round(max(impact, 0.0), 2),
        }
    except Exception:
        return None


def extract_osv_info(osv_obj):
    """Rút trích CVE aliases, CVSS v3 vector và ngày công bố từ một JSON OSV."""
    aliases = osv_obj.get('aliases') or []
    cves = sorted({x for x in aliases if isinstance(x, str) and x.upper().startswith('CVE-')})
    cvss_vec = None
    for sev in (osv_obj.get('severity') or []):
        if isinstance(sev, dict) and 'CVSS:3' in str(sev.get('score', '')):
            cvss_vec = sev['score']
            break
    db_spec = osv_obj.get('database_specific') or {}
    if not cvss_vec and isinstance(db_spec.get('cvss'), dict):
        cvss_vec = db_spec['cvss'].get('vector_string')
    return {
        'cves': cves,
        'cvss_raw': cvss_vec,
        'github_reviewed': bool(db_spec.get('github_reviewed', True)),
        'nvd_published_at': db_spec.get('nvd_published_at'),
    }


def fetch_single_osv(ghsa_id, retries=3):
    url = f'https://api.osv.dev/v1/vulns/{ghsa_id}'
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'GR2-VSecOps-Research/1.0'})
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode('utf-8'))
                    return ghsa_id, extract_osv_info(data)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return ghsa_id, {'cves': [], 'cvss_raw': None, 'not_found': True}
            time.sleep(0.5 * (attempt + 1))
        except Exception:
            time.sleep(0.5 * (attempt + 1))
    return ghsa_id, None


def infer_k_scope(a_row, k_b29=None):
    """Gán nhãn phạm vi cấu trúc K1 (cục bộ), K2 (xuyên hàm/tệp vừa), K3 (thiết kế/kiến trúc).
    Nếu ca đã có nhãn K từ tree-sitter ở Bước 29 thì giữ nguyên; nếu chưa thì suy từ cấu trúc diff.
    """
    if k_b29 in ('K1', 'K2', 'K3'):
        return k_b29, 'tree_sitter_b29'
    n_tep = int(a_row.get('n_tep') or 0)
    n_hunk = int(a_row.get('n_hunk') or 0)
    n_dong = int(a_row.get('n_dong') or 0)
    if n_tep >= 4 or n_dong > 80:
        return 'K3', 'quy_tac_diff'
    if n_tep == 1 and n_hunk <= 1 and n_dong <= 20:
        return 'K1', 'quy_tac_diff'
    return 'K2', 'quy_tac_diff'


def main():
    os.makedirs(DATA_DIR, exist_ok=True)
    print(f'[1/5] Đang đọc dữ liệu gốc từ:\n  - {PATH_A}\n  - {PATH_T}')
    A = json.load(open(PATH_A, encoding='utf-8'))
    T = json.load(open(PATH_T, encoding='utf-8'))
    assert len(A) == len(T), f'Lệch kích thước: A={len(A)} vs T={len(T)}'

    yham_map = {}
    k_b29_map = {}
    if os.path.exists(PATH_YHAM):
        nh = json.load(open(PATH_YHAM, encoding='utf-8'))
        for key, val in nh.items():
            idx_str, tool = key.split('|')
            idx = int(idx_str)
            yham_map.setdefault(idx, {})[tool] = val
            if 'K' in val:
                k_b29_map[idx] = val['K']
        print(f'  -> Đã nạp {len(nh)} cặp quét toàn repo từ Bước 29 ({len(k_b29_map)} ca có nhãn K tree-sitter).')

    # 2. Đọc cache & quét các file OSV có sẵn trên đĩa
    cache = {}
    if os.path.exists(CACHE_FILE):
        try:
            cache = json.load(open(CACHE_FILE, encoding='utf-8'))
            print(f'  -> Đã nạp {len(cache)} GHSA từ cache: {CACHE_FILE}')
        except Exception:
            cache = {}

    local_pattern = os.path.join(ROOT, 'Dataset', 'tang2_build', 'du_lieu', 'osv_*', 'GHSA-*.json')
    local_files = glob.glob(local_pattern)
    print(f'[2/5] Đang đọc {len(local_files)} file OSV có sẵn trên ổ cứng...')
    for fp in local_files:
        gid = os.path.splitext(os.path.basename(fp))[0]
        if gid not in cache:
            try:
                obj = json.load(open(fp, encoding='utf-8'))
                cache[gid] = extract_osv_info(obj)
            except Exception:
                pass

    unique_ghsas = sorted({row['ghsa'] for row in A})
    missing = [g for g in unique_ghsas if g not in cache]
    print(f'  -> Đã có trên đĩa/cache: {len(unique_ghsas) - len(missing)} / {len(unique_ghsas)} mã GHSA.')

    # 3. Tải bổ sung các mã GHSA còn thiếu từ API OSV.dev
    if missing and '--no-network' not in sys.argv:
        print(f'[3/5] Đang tải bổ sung {len(missing)} mã GHSA từ api.osv.dev (24 luồng)...')
        done = 0
        t0 = time.time()
        with ThreadPoolExecutor(max_workers=24) as ex:
            futs = {ex.submit(fetch_single_osv, gid): gid for gid in missing}
            for fut in as_completed(futs):
                gid, info = fut.result()
                if info is not None:
                    cache[gid] = info
                done += 1
                if done % 250 == 0 or done == len(missing):
                    el = time.time() - t0
                    print(f'  ... Đã tải {done}/{len(missing)} ({el:.1f}s)', flush=True)
                    json.dump(cache, open(CACHE_FILE, 'w', encoding='utf-8'), ensure_ascii=False)
        json.dump(cache, open(CACHE_FILE, 'w', encoding='utf-8'), ensure_ascii=False)
    else:
        print('[3/5] Bỏ qua bước gọi mạng (hoặc đã đủ 100% trong cache).')

    # 4. Tổng hợp dữ liệu đa nhãn cho 8.155 ca
    print('[4/5] Đang tính toán CVSS v3.1, K1/K2/K3 và nhãn công cụ đa tầng cho 8.155 ca...')
    SEV_DEFAULT_SCORE = {'LOW': 3.1, 'MODERATE': 5.5, 'HIGH': 7.5, 'CRITICAL': 9.1}
    rows_out = []
    stats = {'has_cve': 0, 'has_cvss_vec': 0, 'K': {'K1': 0, 'K2': 0, 'K3': 0}, 'tool_profile': {'T_AST': 0, 'T_DEEP_ONLY': 0, 'T_FILE_WEAK': 0, 'T_NONE': 0}}

    AST_TOOLS = ('semgrep', 'bandit', 'eslint_security', 'eslint_mo_rong', 'njsscan')
    for idx, (t_row, a_row) in enumerate(zip(T, A)):
        ghsa = a_row['ghsa']
        osv_info = cache.get(ghsa) or {}
        cves = osv_info.get('cves') or []
        cvss_parsed = parse_cvss_v3(osv_info.get('cvss_raw'))
        sev = a_row.get('severity') or 'MODERATE'

        if cves:
            stats['has_cve'] += 1
        if cvss_parsed:
            stats['has_cvss_vec'] += 1
            cvss_score = cvss_parsed['base_score']
            av, ac, pr, ui, scope = cvss_parsed['AV'], cvss_parsed['AC'], cvss_parsed['PR'], cvss_parsed['UI'], cvss_parsed['S']
            cia_max = 'H' if 'H' in (cvss_parsed['C'], cvss_parsed['I'], cvss_parsed['A']) else ('L' if 'L' in (cvss_parsed['C'], cvss_parsed['I'], cvss_parsed['A']) else 'N')
        else:
            cvss_score = SEV_DEFAULT_SCORE.get(sev, 5.5)
            av, ac, pr, ui, scope = 'N', ('L' if sev in ('CRITICAL', 'HIGH') else 'H'), ('N' if sev == 'CRITICAL' else 'L'), 'N', 'U'
            cia_max = 'H' if sev in ('CRITICAL', 'HIGH') else 'L'

        k_val, k_src = infer_k_scope(a_row, k_b29_map.get(idx))
        stats['K'][k_val] += 1

        # Tổng hợp hồ sơ phản ứng công cụ (Tool Response Profile)
        y_strict = t_row.get('y') or {}
        y_l2s = t_row.get('y_L2s') or {}
        y_l1 = t_row.get('y_L1') or {}
        yh_case = yham_map.get(idx, {})

        ast_caught = any(y_l2s.get(tl, 0) == 1 or y_strict.get(tl, 0) == 1 or yh_case.get(tl, {}).get('y_ham', 0) == 1 for tl in AST_TOOLS)
        deep_caught = (y_l2s.get('codeql', 0) == 1 or y_strict.get('codeql', 0) == 1 or yh_case.get('codeql', {}).get('y_ham', 0) == 1)
        any_file_alert = any(v == 1 for v in y_l1.values())

        if ast_caught:
            tool_prof = 'T_AST'
        elif deep_caught:
            tool_prof = 'T_DEEP_ONLY'
        elif any_file_alert:
            tool_prof = 'T_FILE_WEAK'
        else:
            tool_prof = 'T_NONE'
        stats['tool_profile'][tool_prof] += 1

        rows_out.append({
            'i': idx,
            'ghsa': ghsa,
            'cves': cves,
            'has_cve': int(bool(cves)),
            'severity': sev,
            'has_cvss_vector': int(cvss_parsed is not None),
            'cvss_score': cvss_score,
            'cvss': {
                'AV': av, 'AC': ac, 'PR': pr, 'UI': ui, 'S': scope, 'CIA_MAX': cia_max,
                'vector': cvss_parsed['vector'] if cvss_parsed else None
            },
            'K': k_val,
            'K_nguon': k_src,
            'tool_profile': tool_prof,
            'y_toan_repo': yh_case if yh_case else None
        })

    out_payload = {
        'so_ca': len(rows_out),
        'thong_ke': stats,
        'du_lieu': rows_out
    }
    json.dump(out_payload, open(OUT_FILE, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print(f'[5/5] Hoàn tất! Đã lưu vào: {OUT_FILE}')
    print('Thống kê tổng hợp:', json.dumps(stats, ensure_ascii=False))


if __name__ == '__main__':
    main()
