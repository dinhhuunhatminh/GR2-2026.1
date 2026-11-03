"""Bước 33b.3 – Kiến trúc Two-Stage Calibrated Joint HMLC (PHIEU_BUOC33B_SUA.md mục 2.4).
Điểm nâng cấp chính:
  1. Residual Projection: z_A, z_B, z_C có kết nối tắt (skip-connection) từ x_v và [x_v, x_t]
     giúp không gian nhúng bảo toàn thông tin tuyến tính của đặc trưng gốc và luôn thắng kNN thô (H3).
  2. Giai đoạn 1 (Representation Learning): Chỉ học HMLC 3 trục + đầu phụ y_vung (1.099 mẫu dương),
     KHÔNG ép học trực tiếp y_ham (87 mẫu dương) bằng BCE trong 100 epoch để tránh overfit loss=0.001.
  3. Giai đoạn 2 (Calibrated Probe ở b33b_danh_gia_cv.py): Đóng băng biểu diễn và dùng L2-regularized
     LogisticRegression (như Bước 29) để ước lượng xác suất y_ham được hiệu chuẩn tốt (giảm cả Brier và Log-loss).
"""
import os
import sys
import time
import numpy as np
import jax
import jax.numpy as jnp
import optax

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
for p_ma in [
    os.path.join(ROOT, 'Dataset', 'buoc29_nhan_ham_hcl_mitre', 'ma'),
    '/mnt/user-data/uploads/GR2/Dataset/buoc29_nhan_ham_hcl_mitre/ma',
    '/home/claude/b29/ma',
]:
    if os.path.exists(p_ma) and p_ma not in sys.path:
        sys.path.insert(0, p_ma)

import b29_hmlc as HM
import b33b_dac_trung_va_nhan as D

CFG = dict(
    temp=0.07,
    base_temp=0.07,
    dropout=0.1,
    lam=(0.35, 0.35, 0.30),
    alpha=0.30,
    epochs=80,
    batch=512,
    lr=1e-3,
    wd=1e-4,
    seed=0,
    h_v=(256, 128),
    h_t=32,
    d_vt=128,
    d_z=128,
)


def lin(key, a, b, scale=2.0):
    return (jax.random.normal(key, (a, b)) * jnp.sqrt(scale / a), jnp.zeros(b))


def init(key, d_v, d_t, c=CFG):
    ks = iter(jax.random.split(key, 20))
    p = {}
    p['v'] = [lin(next(ks), d_v, c['h_v'][0]), lin(next(ks), c['h_v'][0], c['h_v'][1])]
    p['t'] = lin(next(ks), d_t, c['h_t'])
    p['Wv'] = lin(next(ks), c['h_v'][1], c['h_t'])[0]
    p['vt'] = lin(next(ks), c['h_v'][1] + 2 * c['h_t'], c['d_vt'])

    # Projection heads + Residual skip-connections (VA, VB, VC)
    p['ZA'] = lin(next(ks), c['h_v'][1], c['d_z'])[0]
    p['VA'] = lin(next(ks), d_v, c['d_z'], scale=0.5)[0]

    p['ZB'] = lin(next(ks), c['d_vt'], c['d_z'])[0]
    p['VB'] = lin(next(ks), d_v + d_t, c['d_z'], scale=0.5)[0]

    p['ZC'] = lin(next(ks), c['h_v'][1], c['d_z'])[0]
    p['VC'] = lin(next(ks), d_v, c['d_z'], scale=0.5)[0]

    df = c['d_vt'] + 3 * c['d_z']
    p['ax'] = (jax.random.normal(next(ks), (df,)) * 0.01, jnp.zeros(()))
    return p


def _drop(h, key, rate):
    if key is None or rate <= 0:
        return h
    keep = jax.random.bernoulli(key, 1.0 - rate, h.shape)
    return jnp.where(keep, h / (1.0 - rate), 0.0)


def _nrm(u):
    return u / (jnp.linalg.norm(u, axis=1, keepdims=True) + 1e-8)


def encode_v(p, xv, key=None, rate=0.0):
    h = xv
    for W, b in p['v']:
        h = jax.nn.relu(h @ W + b)
        if key is not None:
            key, k = jax.random.split(key)
            h = _drop(h, k, rate)
    return h


def pair_part(p, hv, xt):
    ht = jax.nn.relu(xt @ p['t'][0] + p['t'][1])
    inter = (hv @ p['Wv']) * ht
    hvt = jax.nn.relu(jnp.concatenate([hv, ht, inter], 1) @ p['vt'][0] + p['vt'][1])
    return hvt


def forward(p, xv, xt, key=None, rate=0.0):
    hv = encode_v(p, xv, key, rate)
    hvt = pair_part(p, hv, xt)
    xvt = jnp.concatenate([xv, xt], 1)
    zA = _nrm(hv @ p['ZA'] + xv @ p['VA'])
    zB = _nrm(hvt @ p['ZB'] + xvt @ p['VB'])
    zC = _nrm(hv @ p['ZC'] + xv @ p['VC'])
    return hv, hvt, zA, zB, zC


def aux_head(p, hvt, zA, zB, zC):
    f = jnp.concatenate([hvt, zA, zB, zC], 1)
    return f @ p['ax'][0] + p['ax'][1]


def layers(labels, valid):
    B, nc = labels.shape
    out = []
    act = valid.copy()
    for l in range(1, nc):
        ll = labels[:, :nc - l]
        M = np.all(ll[:, None, :] == ll[None, :, :], axis=2).astype(np.float32)
        out.append((M, act.astype(np.float32).copy()))
        seen = set()
        new = np.zeros(B, bool)
        for i in range(B):
            if act[i]:
                k = tuple(ll[i])
                if k not in seen:
                    seen.add(k)
                    new[i] = True
        act = new
    return np.stack([m for m, _ in out]), np.stack([a for _, a in out])


def axis_loss(z1, z2, Ms, acts, c):
    f2 = jnp.concatenate([z1, z2], 0)
    n_cot = Ms.shape[0] + 1
    cum = 0.0
    mx = -jnp.inf
    for l in range(1, n_cot):
        ll = HM.supcon(f2, Ms[l - 1], acts[l - 1], c['temp'], c['base_temp'])
        ll = jnp.maximum(mx, ll)
        cum = cum + jnp.power(2.0, 1.0 / l) * ll
        mx = jnp.maximum(mx, ll)
    return cum / n_cot


def make_loss(c):
    lam = c['lam']

    def loss(p, xv, xt, MA, aA, MB, aB, MC, aC, y_aux, m_aux, key):
        k1, k2 = jax.random.split(key)
        o1 = forward(p, xv, xt, k1, c['dropout'])
        o2 = forward(p, xv, xt, k2, c['dropout'])
        LA = axis_loss(o1[2], o2[2], MA, aA, c)
        LB = axis_loss(o1[3], o2[3], MB, aB, c)
        LC = axis_loss(o1[4], o2[4], MC, aC, c)
        _, hvt, zA, zB, zC = forward(p, xv, xt)
        lx = aux_head(p, hvt, zA, zB, zC)
        bce = lambda z, y: jnp.maximum(z, 0) - z * y + jnp.log1p(jnp.exp(-jnp.abs(z)))
        La = (bce(lx, y_aux) * m_aux).sum() / jnp.maximum(m_aux.sum(), 1.0)
        tot = lam[0] * LA + lam[1] * LB + lam[2] * LC + c['alpha'] * La
        return tot, jnp.stack([LA, LB, LC, La])

    return loss


def train(X, train_cases, c=CFG, log=None):
    rng = np.random.default_rng(c['seed'])
    key = jax.random.PRNGKey(c['seed'])
    p = init(key, X.shape[1], D.XT_PAIR.shape[1], c)
    opt = optax.adamw(c['lr'], weight_decay=c['wd'])
    st = opt.init(p)
    lossf = make_loss(c)

    @jax.jit
    def step(p, st, *a):
        (l, aux), g = jax.value_and_grad(lossf, has_aux=True)(p, *a)
        up, st = opt.update(g, st, p)
        return optax.apply_updates(p, up), st, l, aux

    tc = np.asarray(train_cases)
    hist = []
    t0 = time.time()
    for ep in range(c['epochs']):
        perm = rng.permutation(tc)
        tot = 0.0
        nb = 0
        auxs = np.zeros(4)
        for s in range(0, len(perm) - c['batch'] + 1, c['batch']):
            ci = perm[s:s + c['batch']]
            pi = np.array([D.PAIR_OF[i][rng.integers(len(D.PAIR_OF[i]))] for i in ci])
            MA, aA = layers(D.LAB_A[ci], D.VALID_A[ci])
            MB, aB = layers(D.LAB_B[pi], D.VALID_B[pi])
            MC, aC = layers(D.LAB_C[ci], np.ones(len(ci), bool))
            ya = D.Y_VUNG[pi]
            key, k = jax.random.split(key)
            p, st, l, aux = step(
                p, st,
                jnp.asarray(X[ci]),
                jnp.asarray(D.XT_PAIR[pi]),
                jnp.asarray(MA), jnp.asarray(aA),
                jnp.asarray(MB), jnp.asarray(aB),
                jnp.asarray(MC), jnp.asarray(aC),
                jnp.asarray(np.maximum(ya, 0), jnp.float32),
                jnp.asarray(ya >= 0, jnp.float32),
                k,
            )
            tot += float(l)
            nb += 1
            auxs += np.asarray(aux)
        hist.append((tot / max(nb, 1), (auxs / max(nb, 1)).tolist()))
        if log and (ep % 20 == 0 or ep == c['epochs'] - 1):
            log(f'  epoch {ep}: loss {hist[-1][0]:.4f} [A,B,C,aux]={np.round(hist[-1][1], 4).tolist()} ({time.time() - t0:.0f}s)')
    return p, hist


def embed_all(p, X):
    Xj = jnp.asarray(X)
    hv = encode_v(p, Xj)
    zA = _nrm(hv @ p['ZA'] + Xj @ p['VA'])
    zC = _nrm(hv @ p['ZC'] + Xj @ p['VC'])

    xv_pair = Xj[D.PC]
    xt_pair = jnp.asarray(D.XT_PAIR)
    hvt = pair_part(p, hv[D.PC], xt_pair)
    xvt = jnp.concatenate([xv_pair, xt_pair], 1)
    zB = _nrm(hvt @ p['ZB'] + xvt @ p['VB'])
    lx = aux_head(p, hvt, zA[D.PC], zB, zC[D.PC])
    return dict(
        zA=np.asarray(zA),
        zC=np.asarray(zC),
        zB=np.asarray(zB),
        logit_aux=np.asarray(lx),
        p_aux=np.asarray(jax.nn.sigmoid(lx)),
        hv=hv,
        Xj=Xj,
        zA_j=zA,
        zC_j=zC,
    )


def pair_features_any(p, emb, cases, tool_idx, lang=None):
    """Trích xuất đặc trưng đã đóng băng cho cặp (ca, công cụ) bất kỳ để đưa vào Calibrated LogisticRegression."""
    cases = np.asarray(cases)
    tool_idx = np.asarray(tool_idx)
    lang_arr = D.LANG[cases] if lang is None else np.full(len(cases), lang)
    xt = jnp.asarray(D.xt_pair(tool_idx, lang_arr))
    xv = emb['Xj'][cases]
    hv = emb['hv'][cases]
    hvt = pair_part(p, hv, xt)
    xvt = jnp.concatenate([xv, xt], 1)
    zA = emb['zA_j'][cases]
    zC = emb['zC_j'][cases]
    zB = _nrm(hvt @ p['ZB'] + xvt @ p['VB'])
    lx = aux_head(p, hvt, zA, zB, zC)

    oh_t = np.zeros((len(cases), len(D.TOOLS)), np.float32)
    oh_t[np.arange(len(cases)), tool_idx] = 1.0
    oh_l = np.zeros((len(cases), len(D.LANGS)), np.float32)
    oh_l[np.arange(len(cases)), lang_arr] = 1.0

    return np.hstack([
        np.asarray(zA),
        np.asarray(zB),
        np.asarray(zC),
        np.asarray(lx)[:, None],
        oh_t,
        oh_l,
    ])
