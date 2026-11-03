# Mô hình xác suất bắt lỗi: P(công cụ X bắt được lỗi thuộc họ Y), ước lượng Bayes Beta-Binomial.
# Tiên nghiệm: dataset tự cài (ma_tran.json, trọng số omega); bằng chứng: 200 lỗi thật (nhan.csv).
# Siêu tham số (omega, kappa) chọn bằng kiểm tra chéo bỏ-một-repo (mỗi ca là một repo riêng).
import csv, json, os, math, collections, itertools
import numpy as np
H = os.path.dirname(os.path.abspath(__file__))
CWE2FAM = {'sqli': ['CWE-89'], 'cmd': ['CWE-77', 'CWE-78', 'CWE-88', 'CWE-74'], 'xss': ['CWE-79', 'CWE-80', 'CWE-116', 'CWE-184'],
 'path': ['CWE-22', 'CWE-23', 'CWE-73'], 'ssrf': ['CWE-918'], 'eval': ['CWE-94', 'CWE-95'], 'weak_hash': ['CWE-327', 'CWE-328', 'CWE-916'],
 'insecure_random': ['CWE-330', 'CWE-338', 'CWE-331'], 'open_redirect': ['CWE-601'], 'jwt_secret': ['CWE-347', 'CWE-345', 'CWE-798', 'CWE-259', 'CWE-321'],
 'cors': ['CWE-346', 'CWE-942'], 'regex': ['CWE-1333', 'CWE-400', 'CWE-185', 'CWE-770'], 'prototype': ['CWE-1321', 'CWE-471', 'CWE-915'],
 'validation': ['CWE-20', 'CWE-1286'], 'info_exposure': ['CWE-200', 'CWE-209', 'CWE-532', 'CWE-522'], 'access_control': ['CWE-862', 'CWE-863', 'CWE-284', 'CWE-285', 'CWE-306', 'CWE-639']}
C2F = {c: f for f, cs in CWE2FAM.items() for c in cs}
def family(cwes):
    for c in cwes:
        if c in C2F: return C2F[c]
    return 'khac'
TOOLS = {'semgrep': 'semgrep@CODE_A', 'eslint_security': 'eslint@CODE_A', 'njsscan': None, 'eslint_mo_rong': None}

def load_real():
    rows = list(csv.DictReader(open(H + '/du_lieu/nhan.csv', encoding='utf-8-sig')))
    by = collections.defaultdict(dict)
    for r in rows:
        if r['ap_dung'] != 'co': continue
        d = by[(r['ghsa'], r['cong_cu'])]
        d['cwe'] = [c for c in r['cwe'].split(';') if c]; d['y'] = d.get('y', 0) + int(r['khop_trong_tep'])
    obs = []
    for (g, t), d in by.items(): obs.append({'case': g, 'tool': t, 'fam': family(d['cwe']), 'y': 1 if d['y'] > 0 else 0})
    return obs

def load_planted():
    ma = json.load(open(os.path.normpath(H + '/../tang3_chon/ma_tran.json'), encoding='utf-8'))
    pri = {}   # (tool, fam) -> (k, n); n=2 ca mỗi lớp
    for c in ma['CODE_A']['cands']:
        t = [k for k, v in TOOLS.items() if v == c['id']]
        if not t: continue
        for fam, p in c['p'].items(): pri[(t[0], fam)] = (2 * p, 2)
    return pri

def posterior(tool, fam, real_counts, tool_rate, pri, omega, kappa, exclude=None):
    k = n = 0
    for (t, f), (kk, nn) in real_counts.items():
        if t == tool and f == fam: k += kk; n += nn
    if exclude is not None and exclude['tool'] == tool and exclude['fam'] == fam: k -= exclude['y']; n -= 1
    kp, np_ = pri.get((tool, fam), (0, 0))
    a = kappa * tool_rate + k + omega * kp
    b = kappa * (1 - tool_rate) + (n - k) + omega * (np_ - kp)
    return a, b

def fit_all(obs, pri, omega, kappa, loo=False):
    rc = collections.defaultdict(lambda: [0, 0]); tc = collections.defaultdict(lambda: [0, 0])
    for o in obs: rc[(o['tool'], o['fam'])][0] += o['y']; rc[(o['tool'], o['fam'])][1] += 1; tc[o['tool']][0] += o['y']; tc[o['tool']][1] += 1
    return {k: tuple(v) for k, v in rc.items()}, {k: tuple(v) for k, v in tc.items()}

def cv(obs, pri, omega, kappa):
    rc, tc = fit_all(obs, pri, omega, kappa); ll = br = 0
    for o in obs:
        k_t, n_t = tc[o['tool']]; k_t -= o['y']; n_t -= 1; rate = (k_t + 0.5) / (n_t + 1)
        a, b = posterior(o['tool'], o['fam'], rc, rate, pri, omega, kappa, exclude=o)
        p = min(max(a / (a + b), 1e-3), 1 - 1e-3)
        ll += -(o['y'] * math.log(p) + (1 - o['y']) * math.log(1 - p)); br += (p - o['y']) ** 2
    return ll / len(obs), br / len(obs)

if __name__ == '__main__':
    obs = load_real(); pri = load_planted()
    print('so quan sat:', len(obs), '| ty le duong:', round(sum(o['y'] for o in obs) / len(obs), 3))
    # đường cơ sở: chỉ tỉ lệ theo công cụ (kappa rất lớn), chỉ tiên nghiệm tự cài (omega lớn, bằng chứng thật bỏ qua không làm được -> dùng kappa=0.01, omega=1 so sánh)
    base = cv(obs, pri, 0, 1e6)
    print('co so 1 - chi ty le theo cong cu: logloss %.4f brier %.4f' % base)
    res = []
    for omega in (0, 0.05, 0.1, 0.25, 0.5, 1.0):
        for kappa in (1, 2, 5, 10, 20, 50):
            ll, br = cv(obs, pri, omega, kappa); res.append((ll, br, omega, kappa))
    res.sort(); best = res[0]
    print('tot nhat: omega=%s kappa=%s logloss %.4f brier %.4f' % (best[2], best[3], best[0], best[1]))
    for r in res[:5]: print('  ', r)
    ll0, br0 = cv(obs, pri, 0, 5); print('chi bang chung that (omega=0, kappa=5): logloss %.4f brier %.4f' % (ll0, br0))
    omega, kappa = best[2], best[3]
    rc, tc = fit_all(obs, pri, omega, kappa); out = {'omega': omega, 'kappa': kappa, 'cv': {'logloss': best[0], 'brier': best[1], 'co_so_theo_cong_cu_logloss': base[0], 'co_so_theo_cong_cu_brier': base[1]}, 'cong_cu': {}}
    rng = np.random.default_rng(0)
    for tool in TOOLS:
        if tool not in tc: continue
        rate = (tc[tool][0] + 0.5) / (tc[tool][1] + 1); out['cong_cu'][tool] = {'ty_le_chung': round(rate, 3), 'k': tc[tool][0], 'n': tc[tool][1], 'ho': {}}
        for fam in sorted({o['fam'] for o in obs} | {f for (t, f) in pri if t == tool}):
            a, b = posterior(tool, fam, rc, rate, pri, omega, kappa)
            s = rng.beta(a, b, 4000); k, n = rc.get((tool, fam), (0, 0))
            out['cong_cu'][tool]['ho'][fam] = {'p': round(a / (a + b), 3), 'p05': round(float(np.quantile(s, .05)), 3), 'p95': round(float(np.quantile(s, .95)), 3), 'k_that': k, 'n_that': n, 'k_tu_cai': pri.get((tool, fam), (None, 0))[0], 'a': a, 'b': b}
    json.dump(out, open(H + '/xac_suat_mo_hinh.json', 'w'), ensure_ascii=False, indent=1)
    for tool, v in out['cong_cu'].items():
        print('\n', tool, 'ty le chung', v['ty_le_chung'], f"({v['k']}/{v['n']})")
        for fam, x in sorted(v['ho'].items(), key=lambda kv: -kv[1]['p'])[:8]:
            print('   %-15s p=%.2f [%.2f-%.2f]  that %s/%s  tu cai %s' % (fam, x['p'], x['p05'], x['p95'], x['k_that'], x['n_that'], x['k_tu_cai']))
