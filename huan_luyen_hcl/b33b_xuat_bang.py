"""Bước 33b.4 – Xuất bảng xác suất bang_hcl_b33b.json cho mcp_chon_cong_cu_v11.
Quy tắc đặt trước (PHIEU_BUOC33B_SUA.md):
  - Nếu cận trên khoảng tin cậy bootstrap 95% của (Brier A1_b33b − Brier A0) <= 0:
    dùng A1_b33b (Two-Stage Calibrated Joint HMLC) làm mức nền mu(L, t, h).
  - Ngược lại: fallback về A0.
  - Bổ sung trường ngoai_tam_sast = P(K3 | L, h) và tích hợp vào mcp_chon_cong_cu_v11.
"""
import os
import sys
import json
import collections
import numpy as np
from sklearn.linear_model import LogisticRegression

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import b33b_dac_trung_va_nhan as D
import b33b_joint_hmlc as J

ROOT = os.path.abspath(os.path.join(HERE, '..', '..', '..'))
DIR_B33 = os.path.dirname(HERE)
OUT_DIR = os.path.join(DIR_B33, 'ket_qua')
V11_DATA = os.path.join(DIR_B33, 'mcp_chon_cong_cu_v11', 'data')


def main():
    h4_path = os.path.join(OUT_DIR, 'b33b_h4.json')
    h4 = json.load(open(h4_path, encoding='utf-8'))
    ci_brier = h4['hieu_so_voi_A0']['A1_b33b|brier']
    dung_a1 = ci_brier[2] <= 0.0
    mode = 'A1_b33b' if dung_a1 else 'A0'
    print(f'[Bước 33b.4] Hiệu Brier A1_b33b - A0 = {ci_brier[0]:.5f} (CI 95%: [{ci_brier[1]:.5f}, {ci_brier[2]:.5f}]) -> Chọn: {mode}')

    old_path = os.path.join(V11_DATA, 'bang_hcl_b28.json')
    old = json.load(open(old_path, encoding='utf-8'))
    kap = old['kappa']

    NHP = np.where(D.Y_HAM >= 0)[0]
    pairs = [(int(D.PC[p]), D.TOOLS[D.PT[p]], int(D.Y_HAM[p])) for p in NHP]
    lang = [t['lang'] for t in D.T]
    S = collections.defaultdict(lambda: [0, 0])
    rate = collections.defaultdict(lambda: [0, 0])
    for i, t, y in pairs:
        S[(lang[i], t, D.FAM[i])][0] += y
        S[(lang[i], t, D.FAM[i])][1] += 1
        rate[t][0] += y
        rate[t][1] += 1

    CELL = collections.defaultdict(list)
    FAMC = collections.defaultdict(list)
    for i in range(D.n):
        CELL[(lang[i], D.FAM[i])].append(i)
        FAMC[D.FAM[i]].append(i)

    if dung_a1:
        print('  -> Đang huấn luyện Two-Stage Calibrated Joint HMLC trên 100% dữ liệu để xuất bảng...')
        all_idx = np.arange(D.n)
        X, _ = D.xv_fold(all_idx)
        p_net, _ = J.train(X, all_idx, J.CFG)
        emb = J.embed_all(p_net, X)
        c_idx = np.array([i for i, _, _ in pairs])
        t_idx = np.array([D.TI[t] for _, t, _ in pairs])
        y_all = np.array([y for _, _, y in pairs])
        U_all = J.pair_features_any(p_net, emb, c_idx, t_idx)
        head = LogisticRegression(C=0.05, max_iter=3000, random_state=0).fit(U_all, y_all)

    KAPPA_MU = 10.0
    for L, d in old['p'].items():
        for t, d2 in d.items():
            r0_t = rate[t][0] / max(rate[t][1], 1)
            for h in list(d2.keys()):
                k, m = S.get((L, t, h), (0, 0))
                if dung_a1:
                    ii = CELL.get((L, h))
                    n_cell = len(ii) if ii else 0
                    lg = None
                    if not ii:
                        ii = FAMC[h]
                        lg = D.LI[L]
                    U_cell = J.pair_features_any(p_net, emb, ii, np.full(len(ii), D.TI[t]), lg)
                    mu_raw = float(head.predict_proba(U_cell)[:, 1].mean())
                    # Co cụm Bayes Phân cấp 2 tầng chống quá tự tin ở các ô ít mẫu (m=1..5)
                    mu = (n_cell * mu_raw + KAPPA_MU * r0_t) / (n_cell + KAPPA_MU)
                    nguon = 'hcl_b33b_cung_o' if n_cell > 0 else 'hcl_b33b_muon_ngon_ngu'
                else:
                    mu_raw = r0_t
                    mu = r0_t
                    n_cell = len(CELL.get((L, h), []))
                    nguon = 'ty_le_cong_cu_A0'
                p_val = round((k + kap * mu) / (m + kap), 6)
                d2[h] = p_val
                if f'{L}|{t}|{h}' in old.get('thong_tin_o', {}):
                    old['thong_tin_o'][f'{L}|{t}|{h}']['mu'] = round(mu, 6)
                    old['thong_tin_o'][f'{L}|{t}|{h}']['mu_hcl_raw'] = round(mu_raw, 6)
                    old['thong_tin_o'][f'{L}|{t}|{h}']['n_ca_o'] = int(n_cell)
                    old['thong_tin_o'][f'{L}|{t}|{h}']['nguon'] = nguon

    K3 = [m['K'] == 'K3' for m in D.MD]
    lr = {}
    cell_k3 = collections.defaultdict(list)
    for i in range(D.n):
        cell_k3[(lang[i], D.FAM[i])].append(K3[i])
    for L in D.LANGS:
        lr[L] = sum(K3[i] for i in range(D.n) if lang[i] == L) / sum(1 for i in range(D.n) if lang[i] == L)
    nt = {}
    for (L, h), v in cell_k3.items():
        nt.setdefault(L, {})[h] = {'p': round((sum(v) + 10 * lr[L]) / (len(v) + 10), 4), 'n': len(v)}

    old['ngoai_tam_sast'] = {
        'dinh_nghia': 'P(K3 | ngon ngu, ho loi): ty le ban va cham >=4 tep hoac thiet ke (nhan K3), co ve ty le K3 cua ngon ngu, kappa=10.',
        'bang': nt,
    }
    old['phien_ban'] = f'hcl_b33b_{mode}'
    old['danh_gia_h4_b33b'] = h4

    for out_p in [
        os.path.join(OUT_DIR, 'bang_hcl_b33b.json'),
        os.path.join(OUT_DIR, 'bang_hcl_b33.json'),
        os.path.join(V11_DATA, 'bang_hcl_b33.json'),
    ]:
        json.dump(old, open(out_p, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
        print('  -> Đã ghi:', out_p)


if __name__ == '__main__':
    main()
