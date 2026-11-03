# -*- coding: utf-8 -*-
"""
Bước 22: Mô hình Hierarchical Contrastive Learning (MoHinhHCL) cho ước lượng xác suất phát hiện lỗi mã nguồn.
Thiết kế:
  1. Cây phân cấp 3 tầng (3-Level Vulnerability Taxonomy):
     - Tầng 1 (Pillar - Cơ chế gốc): 6 nhóm cơ chế AST/Dataflow/Serialization/Crypto/Boundary/Logic.
     - Tầng 2 (Family - Họ lỗ hổng): 23 họ lỗi family2(cwe).
     - Tầng 3 (Cell & Multi-granularity Signature): Tổ hợp (Ngôn ngữ L, Họ lỗi h) kèm tín hiệu đa mức độ (y_L1, y_L2, y_R, y_L10, y).
  2. Mạng nhúng tương phản phân cấp (Multi-level Hierarchical Supervised Contrastive Network):
     - Ánh xạ mỗi nút u = (L, h) lên mặt cầu đơn vị S^(d-1) (d = 16).
     - Tối ưu hóa hàm mất mát phân cấp L_HCL = sum_{l=1..3} alpha_l * L_SupCon^(l)(Z; tau_l) bằng giải tích gradient + Adam (numpy thuần).
  3. Ước lượng hậu nghiệm co phân cấp bằng nhân tương phản (Contrastive Kernel Hierarchical Shrinkage):
     - Thay vì co phẳng về trung bình ngôn ngữ r_{L,t} như Bayes Beta-Binomial, HCL co về tiên nghiệm tương phản phân cấp mu_HCL(L, t, h)
       với hệ số co thích nghi theo cỡ mẫu ô kappa_eff(m) = kappa * (15 / (m + 15)), giúp:
         + Ở các ô thưa (m < 15, chiếm 40% số ô): tận dụng tối đa tri thức phân cấp trên mặt cầu S^(d-1).
         + Ở các ô giàu dữ liệu (m >= 30): hội tụ nhanh về tỷ lệ thực nghiệm không chệch k/m.
  4. Tương thích 100% giao diện với MoHinh Bayes trong chon_v6.py: .pt(lang, tool, h), .lang_prior(lang), .kappa.
"""
import collections, math
import numpy as np
from fam2 import family2

SAST = ['semgrep', 'codeql', 'bandit', 'njsscan', 'eslint_security', 'eslint_mo_rong']
LANGS = ['javascript', 'python', 'java', 'go', 'php']

PILLAR_MAP = {
    # Pillar 1: Thực thi lệnh & mã động (Command / Dynamic Code Execution Sink)
    'cmd': 'P1_code_cmd_eval',
    'eval': 'P1_code_cmd_eval',
    # Pillar 2: Luồng dữ liệu đầu vào Web & Biểu thức chính quy (Taint Dataflow & Regex)
    'xss': 'P2_web_taint_flow',
    'path': 'P2_web_taint_flow',
    'sqli': 'P2_web_taint_flow',
    'open_redirect': 'P2_web_taint_flow',
    'prototype': 'P2_web_taint_flow',
    'regex': 'P2_web_taint_flow',
    # Pillar 3: Giải tuần tự hóa & Thực thể XML ngoài (Serialization & XXE Parser)
    'deserialization': 'P3_serialization_xml',
    'xxe': 'P3_serialization_xml',
    # Pillar 4: Thuật toán băm & Sinh số ngẫu nhiên yếu (Cryptographic / PRNG AST Pattern)
    'weak_hash': 'P4_crypto_random',
    'insecure_random': 'P4_crypto_random',
    # Pillar 5: Ranh giới mạng & Kiểm tra đầu vào chung (Network Boundary / Validation / CORS)
    'ssrf': 'P5_boundary_net_val',
    'validation': 'P5_boundary_net_val',
    'cors': 'P5_boundary_net_val',
    # Pillar 6: Xác thực, Phân quyền, Phiên/Token, Logic nghiệp vụ & Khác
    'access_control': 'P6_auth_access_other',
    'xac_thuc': 'P6_auth_access_other',
    'csrf': 'P6_auth_access_other',
    'jwt_secret': 'P6_auth_access_other',
    'info_exposure': 'P6_auth_access_other',
    'bo_nho': 'P6_auth_access_other',
    'ma_doc': 'P6_auth_access_other',
    'khac': 'P6_auth_access_other',
}
PILLARS = sorted(set(PILLAR_MAP.values()))


class MoHinhHCL:
    """Mô hình Hierarchical Contrastive Learning (HCL) ước lượng xác suất p[lang][tool][ho]."""
    def __init__(self, cases, kappa=2.0, kappa_pillar=3.5, dim=16, epochs=120, lr=0.03,
                 tau_levels=(0.35, 0.22, 0.12), alpha_levels=(0.25, 0.35, 0.40),
                 tau_kernel=0.12, seed=42):
        self.kappa = kappa
        self.kappa_pillar = kappa_pillar
        self.dim = dim
        self.tau_levels = tau_levels
        self.alpha_levels = alpha_levels
        self.tau_kernel = tau_kernel
        self.p = {}
        self.prior = {}
        self.loss_history = []
        self._fit(cases, epochs=epochs, lr=lr, seed=seed)

    def _fit(self, cases, epochs, lr, seed):
        by_lang = collections.defaultdict(list)
        all_fams_set = set(PILLAR_MAP.keys())
        for c in cases:
            by_lang[c['lang']].append(c)
            all_fams_set.add(family2(c['cwe']))
        self.fams = sorted(all_fams_set)
        self.langs = sorted(by_lang.keys())

        k_cell = collections.defaultdict(float)
        k_l10_cell = collections.defaultdict(float)
        k_l1_cell = collections.defaultdict(float)
        m_cell = collections.defaultdict(float)

        k_pil = collections.defaultdict(float)
        m_pil = collections.defaultdict(float)

        k_lang = collections.defaultdict(float)
        m_lang = collections.defaultdict(float)

        k_fam_global = collections.defaultdict(float)
        m_fam_global = collections.defaultdict(float)

        for L, cs in by_lang.items():
            fams_L = [family2(c['cwe']) for c in cs]
            cnt = collections.Counter(fams_L)
            n_L = len(cs)
            self.prior[L] = {h: cnt[h] / n_L for h in cnt}
            for c, h in zip(cs, fams_L):
                P = PILLAR_MAP.get(h, 'P6_auth_access_other')
                y_dict = c.get('y', {})
                y_l10 = c.get('y_L10', y_dict)
                y_l1 = c.get('y_L1', y_dict)
                for t in SAST:
                    if c['ap'].get(t):
                        yv = float(y_dict.get(t, 0))
                        l10v = float(y_l10.get(t, yv))
                        l1v = float(y_l1.get(t, yv))
                        k_cell[(L, t, h)] += yv
                        k_l10_cell[(L, t, h)] += l10v
                        k_l1_cell[(L, t, h)] += l1v
                        m_cell[(L, t, h)] += 1.0

                        k_pil[(L, t, P)] += yv
                        m_pil[(L, t, P)] += 1.0

                        k_lang[(L, t)] += yv
                        m_lang[(L, t)] += 1.0

                        k_fam_global[(t, h)] += yv
                        m_fam_global[(t, h)] += 1.0

        # 2. Xây dựng ma trận đặc trưng phân cấp X cho các nút u = (L, h)
        nodes = [(L, h) for L in self.langs for h in self.fams]
        self.nodes = nodes
        node_idx = {u: i for i, u in enumerate(nodes)}
        N = len(nodes)

        feat_list = []
        for (L, h) in nodes:
            P = PILLAR_MAP.get(h, 'P6_auth_access_other')
            v_pil = [1.2 if p == P else 0.0 for p in PILLARS]
            v_fam = [1.0 if f == h else 0.0 for f in self.fams]
            v_lng = [0.5 if l == L else 0.0 for l in self.langs]
            v_beh = []
            for t in SAST:
                m_lt = m_lang[(L, t)]
                r_lt = (k_lang[(L, t)] + 0.5) / (m_lt + 1.0) if m_lt > 0 else 0.0
                m_lp = m_pil[(L, t, P)]
                r_lp = (k_pil[(L, t, P)] + 2.0 * r_lt) / (m_lp + 2.0) if m_lt > 0 else 0.0
                m_fg = m_fam_global[(t, h)]
                r_fg = (k_fam_global[(t, h)] + 2.0 * r_lp) / (m_fg + 2.0) if m_fg > 0 else r_lp
                m_c = m_cell[(L, t, h)]
                r_strict = (k_cell[(L, t, h)] + 2.0 * r_fg) / (m_c + 2.0) if m_lt > 0 else 0.0
                r_l10 = (k_l10_cell[(L, t, h)] + 2.0 * r_fg) / (m_c + 2.0) if m_lt > 0 else 0.0
                r_l1 = (k_l1_cell[(L, t, h)] + 2.0 * r_lp) / (m_c + 2.0) if m_lt > 0 else 0.0
                v_beh.extend([
                    1.5 * math.sqrt(max(0.0, r_strict)),
                    1.2 * math.sqrt(max(0.0, r_l10)),
                    0.8 * math.sqrt(max(0.0, r_l1)),
                ])
            feat_list.append(v_pil + v_fam + v_lng + v_beh)

        X = np.array(feat_list, dtype=np.float64)
        X_norm = np.linalg.norm(X, axis=1, keepdims=True)
        X = X / np.maximum(X_norm, 1e-8)
        D_in = X.shape[1]

        # 3. Mặt nạ dương phân cấp 3 tầng cho Hierarchical SupCon Loss
        M1 = np.zeros((N, N), dtype=np.float64)
        M2 = np.zeros((N, N), dtype=np.float64)
        M3 = np.zeros((N, N), dtype=np.float64)
        for i, (Li, hi) in enumerate(nodes):
            Pi = PILLAR_MAP.get(hi, 'P6_auth_access_other')
            for j, (Lj, hj) in enumerate(nodes):
                if i == j:
                    continue
                Pj = PILLAR_MAP.get(hj, 'P6_auth_access_other')
                if Pi == Pj:
                    M1[i, j] = 1.0
                if (Li == Lj and Pi == Pj) or (hi == hj):
                    M2[i, j] = 1.0
                if hi == hj:
                    M3[i, j] = 1.0

        def norm_mask(M):
            row_sum = M.sum(axis=1, keepdims=True)
            valid = (row_sum.squeeze() > 0)
            M_norm = np.divide(M, np.maximum(row_sum, 1e-12))
            return M_norm, valid

        M1_n, val1 = norm_mask(M1)
        M2_n, val2 = norm_mask(M2)
        M3_n, val3 = norm_mask(M3)
        masks = [(M1_n, val1, self.tau_levels[0], self.alpha_levels[0]),
                 (M2_n, val2, self.tau_levels[1], self.alpha_levels[1]),
                 (M3_n, val3, self.tau_levels[2], self.alpha_levels[2])]

        # 4. Khởi tạo SVD + Huấn luyện mạng nhúng tương phản phân cấp trên S^(d-1)
        u_svd, s_svd, vt_svd = np.linalg.svd(X, full_matrices=False)
        W0 = vt_svd[:self.dim].T.copy()
        if W0.shape[1] < self.dim:
            rng = np.random.default_rng(seed)
            pad = rng.normal(0, 0.1, size=(D_in, self.dim - W0.shape[1]))
            W0 = np.concatenate([W0, pad], axis=1)
        W = W0.copy()

        m_adam = np.zeros_like(W)
        v_adam = np.zeros_like(W)
        beta1, beta2, eps_adam = 0.9, 0.999, 1e-8
        diag_mask = np.eye(N, dtype=bool)

        for ep in range(1, epochs + 1):
            H = X @ W
            norms = np.maximum(np.linalg.norm(H, axis=1, keepdims=True), 1e-8)
            Z = H / norms
            sim = Z @ Z.T

            total_loss = 0.0
            G_Z = np.zeros_like(Z)

            for M_norm, valid, tau, alpha in masks:
                logits = sim / tau
                logits_max = np.max(np.where(diag_mask, -1e9, logits), axis=1, keepdims=True)
                exp_logits = np.exp(logits - logits_max)
                exp_logits = np.where(diag_mask, 0.0, exp_logits)
                denom = np.maximum(np.sum(exp_logits, axis=1, keepdims=True), 1e-12)
                Q = exp_logits / denom

                log_prob = (logits - logits_max) - np.log(denom)
                n_val = max(1, int(np.sum(valid)))
                loss_l = -np.sum(M_norm[valid] * log_prob[valid]) / n_val
                total_loss += alpha * loss_l

                diff = (Q - M_norm) * valid[:, None]
                G_S = (alpha / (tau * n_val)) * (diff + diff.T)
                G_Z += G_S @ Z

            proj = np.sum(G_Z * Z, axis=1, keepdims=True)
            G_H = (G_Z - proj * Z) / norms
            reg_lambda = 0.02
            total_loss += 0.5 * reg_lambda * np.sum((W - W0) ** 2)
            G_W = X.T @ G_H + reg_lambda * (W - W0)

            self.loss_history.append(float(total_loss))

            m_adam = beta1 * m_adam + (1.0 - beta1) * G_W
            v_adam = beta2 * v_adam + (1.0 - beta2) * (G_W ** 2)
            m_hat = m_adam / (1.0 - beta1 ** ep)
            v_hat = v_adam / (1.0 - beta2 ** ep)
            W -= lr * m_hat / (np.sqrt(v_hat) + eps_adam)

        H_final = X @ W
        Z_final = H_final / np.maximum(np.linalg.norm(H_final, axis=1, keepdims=True), 1e-8)
        self.embeddings = {u: Z_final[i] for i, u in enumerate(nodes)}
        self.sim_matrix = Z_final @ Z_final.T

        # 5. Tính xác suất hậu nghiệm p[L][t][h] bằng Contrastive Kernel Hierarchical Shrinkage
        for L in self.langs:
            self.p[L] = {}
            for t in SAST:
                M_lt = m_lang[(L, t)]
                if M_lt == 0:
                    continue
                K_lt = k_lang[(L, t)]
                r_lang = (K_lt + 0.5) / (M_lt + 1.0)

                self.p[L][t] = {}
                for h in self.fams:
                    P = PILLAR_MAP.get(h, 'P6_auth_access_other')
                    u_idx = node_idx[(L, h)]

                    # Tầng 1: Tỷ lệ Pillar P trong ngôn ngữ L (loại trừ chính ô (L, t, h))
                    kp_excl = max(0.0, k_pil[(L, t, P)] - k_cell[(L, t, h)])
                    mp_excl = max(0.0, m_pil[(L, t, P)] - m_cell[(L, t, h)])
                    r_pil_h = (kp_excl + self.kappa_pillar * r_lang) / (mp_excl + self.kappa_pillar)

                    # Tầng 2a: Lân cận tương phản cùng ngôn ngữ L và cùng Pillar P(h) trên S^(d-1)
                    num_same_l, den_same_l = 0.0, 0.0
                    for h2 in self.fams:
                        if h2 == h or PILLAR_MAP.get(h2, 'P6_auth_access_other') != P:
                            continue
                        m2 = m_cell[(L, t, h2)]
                        if m2 <= 0:
                            continue
                        v_idx = node_idx[(L, h2)]
                        cos_sim = float(self.sim_matrix[u_idx, v_idx])
                        w_kern = math.exp((cos_sim - 1.0) / self.tau_kernel)
                        # Giới hạn cỡ mẫu đóng góp của một họ đơn lẻ để 1 họ lớn (vd xss) không lấn át toàn bộ lân cận
                        eff_m2 = min(m2, 30.0) * w_kern
                        r_h2 = k_cell[(L, t, h2)] / m2
                        num_same_l += eff_m2 * r_h2
                        den_same_l += eff_m2
                    r_nei_same = (num_same_l + 2.5 * r_pil_h) / (den_same_l + 2.5)

                    # Tầng 2b: Chuyển giao xuyên ngôn ngữ (Cross-language Contrastive Transfer) cho cùng họ lỗi h
                    num_xlang, den_xlang = 0.0, 0.0
                    for L2 in self.langs:
                        if L2 == L or m_lang[(L2, t)] == 0:
                            continue
                        m2 = m_cell[(L2, t, h)]
                        if m2 <= 0:
                            continue
                        v_idx = node_idx[(L2, h)]
                        cos_sim = float(self.sim_matrix[u_idx, v_idx])
                        w_kern = math.exp((cos_sim - 1.0) / self.tau_kernel)
                        r_l2_lang = (k_lang[(L2, t)] + 0.5) / (m_lang[(L2, t)] + 1.0)
                        r_l2_pil = (k_pil[(L2, t, P)] + self.kappa_pillar * r_l2_lang) / (m_pil[(L2, t, P)] + self.kappa_pillar)
                        scale = min(max(r_pil_h / max(r_l2_pil, 1e-4), 0.25), 3.0)
                        r_cell_l2 = k_cell[(L2, t, h)] / m2
                        scaled_rate = min(max(r_cell_l2 * scale, 0.0), 0.85)
                        eff_n = min(m2, 20.0) * w_kern
                        num_xlang += eff_n * scaled_rate
                        den_xlang += eff_n
                    r_xlang = (num_xlang + 2.5 * r_pil_h) / (den_xlang + 2.5)

                    # Tiên nghiệm tương phản phân cấp mu_HCL(L, t, h)
                    mu_hcl = 0.40 * r_pil_h + 0.35 * r_nei_same + 0.25 * r_xlang

                    # Hệ số co thích nghi: ở ô thưa (mc < 15), dùng tiên nghiệm phân cấp mu_HCL mạnh;
                    # ở ô giàu dữ liệu (mc lớn), pha mượt về r_lang để giữ nguyên tính không chệch tối ưu trên mẫu lớn
                    kc = k_cell[(L, t, h)]
                    mc = m_cell[(L, t, h)]
                    alpha_sparse = 12.0 / (mc + 12.0)
                    prior_blend = alpha_sparse * mu_hcl + (1.0 - alpha_sparse) * r_lang
                    self.p[L][t][h] = float((kc + self.kappa * prior_blend) / (mc + self.kappa))

    def pt(self, lang, tool, h):
        L = 'javascript' if lang == 'typescript' else lang
        return self.p.get(L, {}).get(tool, {}).get(h, 0.0)

    def lang_prior(self, lang):
        return self.prior.get('javascript' if lang == 'typescript' else lang, {})
