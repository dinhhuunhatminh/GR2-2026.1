"""Bước 33.3 – đánh giá 5-fold: H2 (thứ bậc cosine), H3 (kNN đa trục), H4 (xác suất p(L,t,h)). Giao thức: PHU_LUC_QUYET_DINH_TRUOC_KHI_CHAY.md.
Chạy một lần, cấu hình mặc định (không dò lưới)."""
import sys, os, json, time, math, collections
import numpy as np
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.metrics import roc_auc_score
sys.path.insert(0, '/home/claude/b33/ma')
import b33_dac_trung_va_nhan as D
import b33_joint_hmlc as J

OUT = '/home/claude/b33/ket_qua'; os.makedirs(OUT, exist_ok=True)
LOG = open(OUT + '/log_cv.txt', 'a')
def log(*a):
    s = ' '.join(map(str, a)); print(s, flush=True); LOG.write(s + '\n'); LOG.flush()

def wilson(k, n, z=1.96):
    if n == 0: return [0.0, 0.0]
    p = k / n; d = 1 + z * z / n; c = p + z * z / (2 * n); r = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)); return [round((c - r) / d, 3), round((c + r) / d, 3)]

# ---------------- H2: thứ bậc cosine ----------------
def cos_levels(Z, tiers, rng, B=200, ns=800):
    m = len(Z); s = rng.choice(m, min(ns, m), replace=False); Zs = Z[s]; T_ = tiers[s]; k = T_.shape[1]
    S = Zs @ Zs.T; eq = [T_[:, None, j] == T_[None, :, j] for j in range(k)]
    cats = [eq[k - 1]] + [eq[j] & ~eq[j + 1] for j in range(k - 2, -1, -1)] + [~eq[0]]
    def stat(ix):
        sub = S[np.ix_(ix, ix)]; ok = ix[:, None] != ix[None, :]; iu = np.triu(np.ones_like(ok), 1) & ok
        out = []
        for c in cats:
            mk = iu & c[np.ix_(ix, ix)]; out.append(sub[mk].mean() if mk.sum() > 0 else np.nan)
        return out
    base = stat(np.arange(len(s))); cnt = [int((np.triu(np.ones_like(c), 1) & c).sum()) for c in cats]
    bs = np.array([stat(rng.choice(len(s), len(s))) for _ in range(B)])
    return {'mean': [float(x) for x in base], 'lo': np.nanpercentile(bs, 2.5, 0).tolist(), 'hi': np.nanpercentile(bs, 97.5, 0).tolist(), 'so_cap': cnt}

def thu_bac(r):
    m = r['mean']; ok = all(not np.isnan(x) for x in m) and all(m[i] > m[i + 1] for i in range(len(m) - 1))
    tach = [bool(r['lo'][i] > r['hi'][i + 1]) for i in range(len(m) - 1)]
    return {'dung_thu_tu': bool(ok), 'cap_lien_ke_tach': tach}

# ---------------- H3: kNN ----------------
def knn_scores(Zte, Ztr, ytr, k=10, nclass=None):
    out_votes = []
    for s in range(0, len(Zte), 800):
        S = Zte[s:s + 800] @ Ztr.T; nn = np.argpartition(-S, k, axis=1)[:, :k]; out_votes.append(ytr[nn])
    return np.concatenate(out_votes, 0)          # [m, k] nhãn láng giềng

def acc_major(votes, y):
    pred = np.array([collections.Counter(v.tolist()).most_common(1)[0][0] for v in votes]); return float((pred == y).mean())

def nrm(X): return X / (np.linalg.norm(X, axis=1, keepdims=True) + 1e-8)

def balanced_acc(pred, y):
    return float(np.mean([(pred[y == c] == c).mean() for c in (0, 1) if (y == c).sum() > 0]))

def raw_pair(X, pairs):
    oh = np.zeros((len(pairs), 6), np.float32); oh[np.arange(len(pairs)), D.PT[pairs]] = 1
    return np.hstack([nrm(X[D.PC[pairs]]), oh])

def h2h3(fo, tr, te, X, emb, rng):
    r = {'fold': fo, 'n_tr': int(len(tr)), 'n_te': int(len(te))}
    trA, teA = tr[D.VALID_A[tr]], te[D.VALID_A[te]]
    # --- H2 ---
    r['H2_A'] = cos_levels(emb['zA'][teA], D.LAB_A[teA][:, :3], rng); r['H2_A'].update(thu_bac(r['H2_A']))
    kn = lambda pairs: pairs[(D.Y_L1[pairs] >= 0) & (D.Y_VUNG[pairs] >= 0)]
    tep = np.concatenate([D.PAIR_OF[i] for i in te]); tep = kn(tep)
    r['H2_B_T12'] = cos_levels(emb['zB'][tep], D.LAB_B[tep][:, :2], rng); r['H2_B_T12'].update(thu_bac(r['H2_B_T12']))
    t3 = tep[D.Y_HAM[tep] >= 0]
    if len(t3) > 0:
        r['H2_B_T123'] = cos_levels(emb['zB'][t3], D.LAB_B[t3][:, :3], rng); r['H2_B_T123'].update(thu_bac(r['H2_B_T123']))
        r['H2_B_T123']['du_mau'] = bool(min(r['H2_B_T123']['so_cap']) >= 30)
    r['H2_C'] = cos_levels(emb['zC'][te], D.LAB_C[te][:, :2], rng); r['H2_C'].update(thu_bac(r['H2_C']))
    # --- H3 ---
    Xn = nrm(X)
    vA = knn_scores(emb['zA'][teA], emb['zA'][trA], D.LAB_K[trA]); vAx = knn_scores(Xn[teA], Xn[trA], D.LAB_K[trA])
    sA = knn_scores(emb['zA'][teA], emb['zA'][trA], D.LAB_SEV[trA]); sAx = knn_scores(Xn[teA], Xn[trA], D.LAB_SEV[trA])
    r['H3_A_K'] = {'z': acc_major(vA, D.LAB_K[teA]), 'x': acc_major(vAx, D.LAB_K[teA]), 'da_so': float(np.bincount(D.LAB_K[teA]).max() / len(teA))}
    r['H3_A_SEV'] = {'z': acc_major(sA, D.LAB_SEV[teA]), 'x': acc_major(sAx, D.LAB_SEV[teA]), 'da_so': float(np.bincount(D.LAB_SEV[teA]).max() / len(teA))}
    vC = knn_scores(emb['zC'][te], emb['zC'][tr], D.LAB_FAM[tr]); vCx = knn_scores(Xn[te], Xn[tr], D.LAB_FAM[tr])
    r['H3_C_FAM'] = {'z': acc_major(vC, D.LAB_FAM[te]), 'x': acc_major(vCx, D.LAB_FAM[te]), 'da_so': float(np.bincount(D.LAB_FAM[te]).max() / len(te))}
    trp = np.concatenate([D.PAIR_OF[i] for i in tr]); trp = trp[D.Y_VUNG[trp] >= 0]; tep2 = np.concatenate([D.PAIR_OF[i] for i in te]); tep2 = tep2[D.Y_VUNG[tep2] >= 0]
    ytr, yte = D.Y_VUNG[trp], D.Y_VUNG[tep2]
    vB = knn_scores(emb['zB'][tep2], emb['zB'][trp], ytr); vBx = knn_scores(raw_pair(X, tep2), raw_pair(X, trp), ytr)
    out = {}
    for nm, v in (('z', vB), ('x', vBx)):
        sc = v.mean(1); pred = (sc > 0.5).astype(int)
        out[nm] = {'auc': float(roc_auc_score(yte, sc)), 'bal_acc': balanced_acc(pred, yte), 'acc': float((pred == yte).mean())}
    out['ty_le_duong_test'] = float(yte.mean()); out['n_te'] = int(len(yte)); r['H3_B_VUNG'] = out
    return r

# ---------------- H4 (giao thức GD6 của Bước 29) ----------------
KAPPAS = [1, 3, 10, 30]
def brier(p, y): return float(np.mean((p - y) ** 2))
def logloss(p, y):
    p = np.clip(p, 1e-4, 1 - 1e-4); return float(-np.mean(y * np.log(p) + (1 - y) * np.log(1 - p)))

def run_h4(rng):
    NHP = np.where(D.Y_HAM >= 0)[0]
    pairs = [(int(D.PC[p]), D.TOOLS[D.PT[p]], int(D.Y_HAM[p])) for p in NHP]
    cases = sorted({i for i, _, _ in pairs}); pos_case = {i: int(any(y for j, _, y in pairs if j == i)) for i in cases}
    g = np.array([D.GROUPS[i] for i in cases]); s_ = np.array([pos_case[i] for i in cases])
    lang = [D.T[i]['lang'] for i in range(D.n)]; fam = D.FAM
    CELL = collections.defaultdict(list)
    for i in range(D.n): CELL[(lang[i], fam[i])].append(i)
    FAMC = collections.defaultdict(list)
    for i in range(D.n): FAMC[fam[i]].append(i)
    def cell_stats(pp):
        s = collections.defaultdict(lambda: [0, 0])
        for i, t, y in pp: s[(lang[i], t, fam[i])][0] += y; s[(lang[i], t, fam[i])][1] += 1
        return s
    def predict0(pp_tr, pp_te, kappa):
        S = cell_stats(pp_tr); rate = collections.defaultdict(lambda: [0, 0])
        for i, t, y in pp_tr: rate[t][0] += y; rate[t][1] += 1
        return np.array([(S.get((lang[i], t, fam[i]), (0, 0))[0] + kappa * rate[t][0] / max(rate[t][1], 1)) / (S.get((lang[i], t, fam[i]), (0, 0))[1] + kappa) for i, t, y in pp_te])
    def predict1(pp_tr, pp_te, kappa, mu_of):
        S = cell_stats(pp_tr); out = []
        for i, t, y in pp_te:
            k, m = S.get((lang[i], t, fam[i]), (0, 0)); out.append((k + kappa * mu_of(lang[i], t, fam[i])) / (m + kappa))
        return np.array(out)
    skf = StratifiedGroupKFold(5, shuffle=True, random_state=0); rec = []; kap = []
    for fo, (tr, te) in enumerate(skf.split(np.zeros(len(cases)), s_, g)):
        t0 = time.time(); trc = {cases[j] for j in tr}; tec = {cases[j] for j in te}
        ptr = [p for p in pairs if p[0] in trc]; pte = [p for p in pairs if p[0] in tec]
        inner = StratifiedGroupKFold(5, shuffle=True, random_state=1); trl = sorted(trc)
        a, b = next(inner.split(np.zeros(len(trl)), [pos_case[i] for i in trl], [D.GROUPS[i] for i in trl]))
        itr = {trl[j] for j in a}; iva = {trl[j] for j in b}
        pitr = [p for p in ptr if p[0] in itr]; piva = [p for p in ptr if p[0] in iva]; yv = np.array([p[2] for p in piva])
        k0 = min(KAPPAS, key=lambda kk: logloss(predict0(pitr, piva, kk), yv)); kap.append(k0)
        tgroups = {D.GROUPS[i] for i in tec}; train_all = np.array([i for i in range(D.n) if D.GROUPS[i] not in tgroups])
        X, _ = D.xv_fold(train_all); p, hist = J.train(X, train_all, J.CFG); emb = J.embed_all(p, X)
        cache = {}
        def mu_of(L, t, h):
            if (L, t, h) not in cache:
                ii = CELL.get((L, h)); lg = None
                if not ii: ii = FAMC[h]; lg = D.LI[L]
                cache[(L, t, h)] = float(J.p_any(p, emb, ii, np.full(len(ii), D.TI[t]), lg).mean())
            return cache[(L, t, h)]
        yt = np.array([q[2] for q in pte])
        p0 = predict0(ptr, pte, k0); p1 = predict1(ptr, pte, k0, mu_of)
        p1k = {kk: predict1(ptr, pte, kk, mu_of) for kk in KAPPAS}
        pmap = {(int(D.PC[q]), D.TOOLS[D.PT[q]]): q for q in NHP}
        p2 = np.array([emb['p_main'][pmap[(i, t)]] for i, t, _ in pte])
        for j, (i, t, y) in enumerate(pte): rec.append((fo, i, t, y, p0[j], p1[j], p2[j], *[p1k[kk][j] for kk in KAPPAS]))
        log(f'H4 fold {fo}: n_tr_model={len(train_all)} kappa_A0={k0} Brier A0/A1/A2 = {brier(p0, yt):.5f} {brier(p1, yt):.5f} {brier(p2, yt):.5f} ({time.time() - t0:.0f}s) loss_cuoi={hist[-1][0]:.3f}')
    R = np.array([r[3:] for r in rec], float); y = R[:, 0]; ci = np.array([r[1] for r in rec]); uc = np.unique(ci); idx = {c: np.where(ci == c)[0] for c in uc}
    names = ['A0', 'A1_b33', 'A2_dau_truc_tiep'] + [f'A1_b33_k{kk}' for kk in KAPPAS]
    res = {'so_cap': len(rec), 'so_duong': int(y.sum()), 'kappa_A0_theo_fold': kap}
    for j, nm in enumerate(names, 1): res[nm] = {'brier': brier(R[:, j], y), 'logloss': logloss(R[:, j], y), 'auc': float(roc_auc_score(y, R[:, j]))}
    rng2 = np.random.default_rng(0); bs = collections.defaultdict(list)
    for _ in range(1000):
        s = np.concatenate([idx[c] for c in rng2.choice(uc, len(uc))]); yy = y[s]
        if yy.sum() == 0: continue
        for j, nm in ((2, 'A1_b33'), (3, 'A2_dau_truc_tiep')):
            bs[nm + '|brier'].append(brier(R[s, j], yy) - brier(R[s, 1], yy)); bs[nm + '|logloss'].append(logloss(R[s, j], yy) - logloss(R[s, 1], yy))
            bs[nm + '|auc'].append(roc_auc_score(yy, R[s, j]) - roc_auc_score(yy, R[s, 1]))
    res['hieu_so_voi_A0'] = {k: [res[k.split('|')[0]][k.split('|')[1]] - res['A0'][k.split('|')[1]], float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5))] for k, v in bs.items()}
    res['A1_b29_da_cong_bo'] = json.load(open('/mnt/user-data/uploads/GR2/Dataset/buoc29_nhan_ham_hcl_mitre/ket_qua/gd6_danh_gia.json'))['A1']
    res['A0_b29_da_cong_bo'] = json.load(open('/mnt/user-data/uploads/GR2/Dataset/buoc29_nhan_ham_hcl_mitre/ket_qua/gd6_danh_gia.json'))['A0']
    json.dump(res, open(OUT + '/b33_h4.json', 'w'), ensure_ascii=False, indent=1)
    np.save(OUT + '/b33_h4_du_doan.npy', np.array(rec, dtype=object), allow_pickle=True)
    return res

if __name__ == '__main__':
    rng = np.random.default_rng(0); which = sys.argv[1] if len(sys.argv) > 1 else 'all'
    log('=== Bước 33 CV', time.strftime('%d/%m/%Y %H:%M:%S'), 'cấu hình', json.dumps({k: v for k, v in J.CFG.items()}), 'phần', which)
    if which in ('all', 'h23'):
        skf = StratifiedGroupKFold(5, shuffle=True, random_state=0); R = {'cfg': J.CFG, 'fold': []}
        for fo, (tr, te) in enumerate(skf.split(np.zeros(D.n), D.LAB_FAM, D.GROUPS)):
            t0 = time.time(); X, names = D.xv_fold(tr); p, hist = J.train(X, tr, J.CFG, log); emb = J.embed_all(p, X)
            r = h2h3(fo, tr, te, X, emb, rng); r['giay'] = round(time.time() - t0); r['loss'] = [hist[0][0], hist[-1][0]]
            R['fold'].append(r); log(json.dumps(r, ensure_ascii=False)); json.dump(R, open(OUT + '/b33_cv_results.json', 'w'), ensure_ascii=False, indent=1)
    if which in ('all', 'h4'):
        res = run_h4(rng); log('H4', json.dumps(res, ensure_ascii=False))
