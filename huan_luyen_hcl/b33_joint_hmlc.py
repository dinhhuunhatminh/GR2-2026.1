"""Bước 33.3 – Multi-Faceted Joint HMLC (PHIEU_BUOC33.md mục 5). JAX, tái dùng `supcon` của Bước 29 (hmce).
Cấu hình đặt trước, không dò lưới."""
import sys, time
import numpy as np, jax, jax.numpy as jnp, optax
sys.path.insert(0, '/mnt/user-data/uploads/GR2/Dataset/buoc29_nhan_ham_hcl_mitre/ma')
import b29_hmlc as HM
import b33_dac_trung_va_nhan as D

CFG = dict(temp=0.07, base_temp=0.07, dropout=0.1, lam=(0.35, 0.35, 0.30), alpha=0.25, epochs=100, batch=512, lr=1e-3, wd=1e-4, seed=0,
           h_v=(256, 128), h_t=32, d_vt=128, d_z=128)


def lin(key, a, b):
    return (jax.random.normal(key, (a, b)) * jnp.sqrt(2.0 / a), jnp.zeros(b))


def init(key, d_v, d_t, c=CFG):
    ks = iter(jax.random.split(key, 16)); p = {}
    p['v'] = [lin(next(ks), d_v, c['h_v'][0]), lin(next(ks), c['h_v'][0], c['h_v'][1])]
    p['t'] = lin(next(ks), d_t, c['h_t'])
    p['Wv'] = lin(next(ks), c['h_v'][1], c['h_t'])[0]
    p['vt'] = lin(next(ks), c['h_v'][1] + 2 * c['h_t'], c['d_vt'])
    p['ZA'] = lin(next(ks), c['h_v'][1], c['d_z'])[0]
    p['ZB'] = lin(next(ks), c['d_vt'], c['d_z'])[0]
    p['ZC'] = lin(next(ks), c['h_v'][1], c['d_z'])[0]
    df = c['d_vt'] + 3 * c['d_z']
    p['hd'] = (jax.random.normal(next(ks), (df,)) * 0.01, jnp.zeros(()))
    p['ax'] = (jax.random.normal(next(ks), (df,)) * 0.01, jnp.zeros(()))
    return p


def _drop(h, key, rate):
    if key is None or rate <= 0: return h
    keep = jax.random.bernoulli(key, 1 - rate, h.shape); return jnp.where(keep, h / (1 - rate), 0.0)


def _nrm(u): return u / (jnp.linalg.norm(u, axis=1, keepdims=True) + 1e-8)


def encode_v(p, xv, key=None, rate=0.0):
    h = xv
    for i, (W, b) in enumerate(p['v']):
        h = jax.nn.relu(h @ W + b)
        if key is not None:
            key, k = jax.random.split(key); h = _drop(h, k, rate)
    return h


def pair_part(p, hv, xt):
    ht = jax.nn.relu(xt @ p['t'][0] + p['t'][1])
    inter = (hv @ p['Wv']) * ht
    hvt = jax.nn.relu(jnp.concatenate([hv, ht, inter], 1) @ p['vt'][0] + p['vt'][1])
    return hvt


def forward(p, xv, xt, key=None, rate=0.0):
    hv = encode_v(p, xv, key, rate)
    hvt = pair_part(p, hv, xt)
    zA, zB, zC = _nrm(hv @ p['ZA']), _nrm(hvt @ p['ZB']), _nrm(hv @ p['ZC'])
    return hv, hvt, zA, zB, zC


def heads(p, hvt, zA, zB, zC):
    f = jnp.concatenate([hvt, zA, zB, zC], 1)
    return f @ p['hd'][0] + p['hd'][1], f @ p['ax'][0] + p['ax'][1]


def layers(labels, valid):
    """Như HM.mat_na_tang nhưng mẫu không hợp lệ không bao giờ hoạt động."""
    B, nc = labels.shape; out = []; act = valid.copy()
    for l in range(1, nc):
        ll = labels[:, :nc - l]
        M = np.all(ll[:, None, :] == ll[None, :, :], axis=2).astype(np.float32)
        out.append((M, act.astype(np.float32).copy()))
        seen = set(); new = np.zeros(B, bool)
        for i in range(B):
            if act[i]:
                k = tuple(ll[i])
                if k not in seen: seen.add(k); new[i] = True
        act = new
    return np.stack([m for m, _ in out]), np.stack([a for _, a in out])


def axis_loss(z1, z2, Ms, acts, c):
    f2 = jnp.concatenate([z1, z2], 0); n_cot = Ms.shape[0] + 1; cum = 0.0; mx = -jnp.inf
    for l in range(1, n_cot):
        ll = HM.supcon(f2, Ms[l - 1], acts[l - 1], c['temp'], c['base_temp']); ll = jnp.maximum(mx, ll)
        cum = cum + jnp.power(2.0, 1.0 / l) * ll; mx = jnp.maximum(mx, ll)
    return cum / n_cot


def make_loss(c):
    lam = c['lam']

    def loss(p, xv, xt, MA, aA, MB, aB, MC, aC, y_main, m_main, y_aux, m_aux, key):
        k1, k2 = jax.random.split(key)
        o1 = forward(p, xv, xt, k1, c['dropout']); o2 = forward(p, xv, xt, k2, c['dropout'])
        LA = axis_loss(o1[2], o2[2], MA, aA, c); LB = axis_loss(o1[3], o2[3], MB, aB, c); LC = axis_loss(o1[4], o2[4], MC, aC, c)
        _, hvt, zA, zB, zC = forward(p, xv, xt)
        lg, lx = heads(p, hvt, zA, zB, zC)
        bce = lambda z, y: jnp.maximum(z, 0) - z * y + jnp.log1p(jnp.exp(-jnp.abs(z)))
        Lm = (bce(lg, y_main) * m_main).sum() / jnp.maximum(m_main.sum(), 1.0)
        La = (bce(lx, y_aux) * m_aux).sum() / jnp.maximum(m_aux.sum(), 1.0)
        tot = lam[0] * LA + lam[1] * LB + lam[2] * LC + Lm + c['alpha'] * La
        return tot, jnp.stack([LA, LB, LC, Lm, La])
    return loss


def train(X, train_cases, c=CFG, log=None):
    """X: [n, d_v] đã chuẩn hóa (fit chỉ trên train). train_cases: chỉ số ca huấn luyện."""
    rng = np.random.default_rng(c['seed']); key = jax.random.PRNGKey(c['seed'])
    p = init(key, X.shape[1], D.XT_PAIR.shape[1], c)
    opt = optax.adamw(c['lr'], weight_decay=c['wd']); st = opt.init(p); lossf = make_loss(c)

    @jax.jit
    def step(p, st, *a):
        (l, aux), g = jax.value_and_grad(lossf, has_aux=True)(p, *a)
        up, st = opt.update(g, st, p); return optax.apply_updates(p, up), st, l, aux
    tc = np.asarray(train_cases); hist = []; t0 = time.time()
    for ep in range(c['epochs']):
        perm = rng.permutation(tc); tot = 0.0; nb = 0; auxs = np.zeros(5)
        for s in range(0, len(perm) - c['batch'] + 1, c['batch']):
            ci = perm[s:s + c['batch']]
            pi = np.array([D.PAIR_OF[i][rng.integers(len(D.PAIR_OF[i]))] for i in ci])   # một công cụ áp dụng ngẫu nhiên cho mỗi ca
            MA, aA = layers(D.LAB_A[ci], D.VALID_A[ci]); MB, aB = layers(D.LAB_B[pi], np.ones(len(pi), bool)); MC, aC = layers(D.LAB_C[ci], np.ones(len(ci), bool))
            ym = D.Y_HAM[pi]; ya = D.Y_VUNG[pi]
            key, k = jax.random.split(key)
            p, st, l, aux = step(p, st, jnp.asarray(X[ci]), jnp.asarray(D.XT_PAIR[pi]), jnp.asarray(MA), jnp.asarray(aA), jnp.asarray(MB), jnp.asarray(aB),
                                 jnp.asarray(MC), jnp.asarray(aC), jnp.asarray(np.maximum(ym, 0), jnp.float32), jnp.asarray(ym >= 0, jnp.float32),
                                 jnp.asarray(np.maximum(ya, 0), jnp.float32), jnp.asarray(ya >= 0, jnp.float32), k)
            tot += float(l); nb += 1; auxs += np.asarray(aux)
        hist.append((tot / max(nb, 1), (auxs / max(nb, 1)).tolist()))
        if log and (ep % 20 == 0 or ep == c['epochs'] - 1): log(f'  epoch {ep}: loss {hist[-1][0]:.4f} [A,B,C,bce,aux]={np.round(hist[-1][1], 4).tolist()} ({time.time() - t0:.0f}s)')
    return p, hist


def embed_all(p, X):
    """Trả zA, zC theo ca; zB và p̂ (chính, phụ) theo cặp thực; và hàm p̂ cho cặp (ca, công cụ) bất kỳ."""
    hv = encode_v(p, jnp.asarray(X)); zA = _nrm(hv @ p['ZA']); zC = _nrm(hv @ p['ZC'])
    hvt = pair_part(p, hv[D.PC], jnp.asarray(D.XT_PAIR)); zB = _nrm(hvt @ p['ZB'])
    lg, lx = heads(p, hvt, zA[D.PC], zB, zC[D.PC])
    return dict(zA=np.asarray(zA), zC=np.asarray(zC), zB=np.asarray(zB), p_main=np.asarray(jax.nn.sigmoid(lg)), p_aux=np.asarray(jax.nn.sigmoid(lx)),
                hv=hv, zA_j=zA, zC_j=zC)


def p_any(p, emb, cases, tool_idx, lang=None):
    """p̂(i, t) cho ca i, công cụ t bất kỳ (kể cả công cụ không áp dụng cho ca, đổi cột công cụ như b29_gd6.mu_hcl)."""
    cases = np.asarray(cases); tool_idx = np.asarray(tool_idx)
    xt = jnp.asarray(D.xt_pair(tool_idx, D.LANG[cases] if lang is None else np.full(len(cases), lang)))
    hv = emb['hv'][cases]; hvt = pair_part(p, hv, xt); zB = _nrm(hvt @ p['ZB'])
    lg, _ = heads(p, hvt, emb['zA_j'][cases], zB, emb['zC_j'][cases])
    return np.asarray(jax.nn.sigmoid(lg))
