"""Bước 33 (Tùy chọn) – Lọc danh sách các ca lỗ hổng ứng viên sáng giá nhất trong 7.161 ca chưa quét toàn repo
(ưu tiên các ca nằm ở ô ít mẫu m < 10 nhưng đã có tín hiệu dương ở mức tệp y_L2s = 1 hoặc y_L1 = 1).
Dùng khi người dùng/AI thực thi muốn quét bổ sung thêm khoảng 100-150 commit để tăng số cặp dương y_ham.
"""
import os
import sys
import json
import collections

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
PATH_T = os.path.join(ROOT, 'Dataset', 'buoc5_mcp', 'mcp_chon_cong_cu_v8', 'data', 'table_gop_v7.json')
PATH_A = os.path.join(ROOT, 'Dataset', 'buoc28_hcl_dac_trung', 'd1_advisory.json')
PATH_YHAM = os.path.join(ROOT, 'Dataset', 'buoc29_nhan_ham_hcl_mitre', 'ket_qua', 'nhan_y_ham_dot3.json')
OUT_CAND = os.path.join(ROOT, 'Dataset', 'buoc33_hcl_da_nhan_cong_cu', 'data', 'ung_vien_quet_bo_sung.json')

sys.path.insert(0, os.path.join(ROOT, 'Dataset', 'buoc29_nhan_ham_hcl_mitre', 'mcp_chon_cong_cu_v10', 'lib'))
from fam2 import family2


def main():
    os.makedirs(os.path.dirname(OUT_CAND), exist_ok=True)
    T = json.load(open(PATH_T, encoding='utf-8'))
    A = json.load(open(PATH_A, encoding='utf-8'))
    nh = json.load(open(PATH_YHAM, encoding='utf-8')) if os.path.exists(PATH_YHAM) else {}

    scanned_cases = {int(k.split('|')[0]) for k in nh.keys()}
    cell_counts = collections.Counter()
    cell_pos = collections.Counter()
    for k, v in nh.items():
        idx, tool = int(k.split('|')[0]), k.split('|')[1]
        fam = family2(T[idx]['cwe'])
        lang = T[idx]['lang']
        cell_counts[(lang, tool, fam)] += 1
        cell_pos[(lang, tool, fam)] += int(v.get('y_ham', 0))

    candidates = []
    for idx, (t_row, a_row) in enumerate(zip(T, A)):
        if idx in scanned_cases:
            continue
        fam = family2(t_row['cwe'])
        lang = t_row['lang']
        y_l2s = t_row.get('y_L2s') or {}
        y_strict = t_row.get('y') or {}
        pos_tools = [tl for tl, val in y_l2s.items() if val == 1 or y_strict.get(tl, 0) == 1]
        if not pos_tools:
            continue
        sparse_tools = [tl for tl in pos_tools if cell_counts[(lang, tl, fam)] < 10 or cell_pos[(lang, tl, fam)] < 2]
        if sparse_tools and (a_row.get('n_tep') or 1) <= 3:
            candidates.append({
                'i': idx,
                'ghsa': a_row['ghsa'],
                'lang': lang,
                'fam': fam,
                'repo': t_row.get('repo'),
                'commit': a_row.get('commit'),
                'n_tep': a_row.get('n_tep'),
                'cong_cu_co_tin_hieu': sparse_tools
            })

    json.dump({'so_ung_vien': len(candidates), 'ung_vien': candidates[:200]}, open(OUT_CAND, 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
    print(f'Đã tìm thấy {len(candidates)} ca ứng viên tiềm năng (lưu top 200 tại {OUT_CAND}).')


if __name__ == '__main__':
    main()
