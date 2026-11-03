"""Bước 29 – HMLC (Zhang và cs., 'Use All The Labels', arXiv 2204.13207), cài lại bằng JAX bám sát
salesforce/hierarchicalContrastiveLearning/losses/losses.py (lớp HMLC + SupConLoss), loss_type='hmce':
  for l in 1..n_cot-1: che l cột cuối của nhãn -> mask_labels[i,j] = (mọi cột còn lại trùng)
      layer_loss = SupCon(features 2 góc nhìn, mask_labels)          (contrast_mode='all', loss nhân tau/base_tau)
      layer_loss = max(max_loss_lower_layer, layer_loss)              (HiConE: tầng thô >= loss lớn nhất các tầng mịn hơn)
      cumulative += 2^(1/l) * layer_loss                              (layer_penalty mặc định pow_2)
      giữ một đại diện (lần xuất hiện đầu) cho mỗi nhãn tầng l; max_loss_lower_layer = max(., layer_loss)
  return cumulative / n_cot
Khác biệt bắt buộc (ghi rõ): đặc trưng dạng bảng -> bộ mã hóa MLP; 2 góc nhìn = dropout (kiểu SimCSE) thay biến đổi ảnh;
việc 'giữ đại diện' cài bằng mặt nạ hoạt động (tương đương phép cắt mảng của mã gốc, để jit được)."""
import numpy as np, jax, jax.numpy as jnp, optax

CFG = dict(temp=0.07, base_temp=0.07, dropout=0.1, hidden=(256, 128), dim=128, epochs=100, batch=512, lr=1e-3, wd=1e-4, seed=0)


def init(key, d_in, cfg):
    sizes = [d_in, *cfg['hidden'], cfg['dim']]; ps = []
    for a, b in zip(sizes[:-1], sizes[1:]):
        key, k = jax.random.split(key); ps.append((jax.random.normal(k, (a, b)) * jnp.sqrt(2.0 / a), jnp.zeros(b)))
    return ps


def encode(ps, x, key=None, rate=0.0):
    h = x
    for i, (W, b) in enumerate(ps[:-1]):
        h = jax.nn.relu(h @ W + b)
        if key is not None and rate > 0:
            key, k = jax.random.split(key); keep = jax.random.bernoulli(k, 1 - rate, h.shape); h = jnp.where(keep, h / (1 - rate), 0.0)
    W, b = ps[-1]; u = h @ W + b
    return u / (jnp.linalg.norm(u, axis=1, keepdims=True) + 1e-8)


def supcon(f2, M, act, temp, base_temp):
    """f2: [2B, d] (góc nhìn 1 rồi góc nhìn 2); M: [B,B] mặt nạ dương (gồm đường chéo); act: [B] mẫu đang hoạt động."""
    B = M.shape[0]
    Mt = jnp.tile(M, (2, 2)); a2 = jnp.tile(act, 2)
    logits = f2 @ f2.T / temp
    logits = logits - jax.lax.stop_gradient(jnp.max(jnp.where(a2[None, :] > 0, logits, -1e9), axis=1, keepdims=True))
    lm = (1.0 - jnp.eye(2 * B)) * a2[None, :]               # bỏ chính nó và mẫu không hoạt động
    mask = Mt * lm
    exp = jnp.exp(logits) * lm
    logp = logits - jnp.log(exp.sum(1, keepdims=True) + 1e-12)
    mlpp = (mask * logp).sum(1) / jnp.maximum(mask.sum(1), 1.0)
    loss = -(temp / base_temp) * mlpp
    return (loss * a2).sum() / jnp.maximum(a2.sum(), 1.0)


def mat_na_tang(labels):
    """labels: [B, n_cot] số nguyên. Trả list theo l=1..n_cot-1 của (M_l [B,B], act_l [B]) theo đúng thứ tự cắt của mã gốc."""
    B, nc = labels.shape; out = []; act = np.ones(B, dtype=bool)
    for l in range(1, nc):
        ll = labels[:, :nc - l]
        M = np.all(ll[:, None, :] == ll[None, :, :], axis=2).astype(np.float32)
        out.append((M, act.astype(np.float32).copy()))
        seen = set(); new = np.zeros(B, dtype=bool)
        for i in range(B):                                  # giữ lần xuất hiện đầu của mỗi nhãn tầng l trong các mẫu đang hoạt động
            if act[i]:
                k = tuple(ll[i])
                if k not in seen: seen.add(k); new[i] = True
        act = new
    return out


def make_loss(cfg, n_cot):
    def loss(ps, x, Ms, acts, key):
        k1, k2 = jax.random.split(key)
        f2 = jnp.concatenate([encode(ps, x, k1, cfg['dropout']), encode(ps, x, k2, cfg['dropout'])], 0)
        cum = 0.0; mx = -jnp.inf; ls = []
        for l in range(1, n_cot):
            ll = supcon(f2, Ms[l - 1], acts[l - 1], cfg['temp'], cfg['base_temp'])
            ll = jnp.maximum(mx, ll)                         # hmce
            cum = cum + jnp.power(2.0, 1.0 / l) * ll
            mx = jnp.maximum(mx, ll); ls.append(ll)
        return cum / n_cot, jnp.stack(ls)
    return loss


def train(X, labels, cfg=CFG, log=None):
    n_cot = labels.shape[1]
    key = jax.random.PRNGKey(cfg['seed']); rng = np.random.default_rng(cfg['seed'])
    ps = init(key, X.shape[1], cfg); opt = optax.adamw(cfg['lr'], weight_decay=cfg['wd']); st = opt.init(ps)
    lossf = make_loss(cfg, n_cot)

    @jax.jit
    def step(ps, st, x, Ms, acts, key):
        (l, aux), g = jax.value_and_grad(lossf, has_aux=True)(ps, x, Ms, acts, key)
        up, st = opt.update(g, st, ps); return optax.apply_updates(ps, up), st, l, aux
    hist = []; n = len(X)
    for ep in range(cfg['epochs']):
        perm = rng.permutation(n); tot = 0; nb = 0
        for s in range(0, n - cfg['batch'] + 1, cfg['batch']):
            idx = perm[s:s + cfg['batch']]; mt = mat_na_tang(labels[idx])
            Ms = jnp.stack([m for m, _ in mt]); acts = jnp.stack([a for _, a in mt])
            key, k = jax.random.split(key)
            ps, st, l, aux = step(ps, st, jnp.asarray(X[idx]), Ms, acts, k); tot += float(l); nb += 1
        hist.append(tot / max(nb, 1))
        if log and (ep % 20 == 0 or ep == cfg['epochs'] - 1): log(f'  epoch {ep}: {hist[-1]:.4f}')
    return ps, hist


def embed(ps, X):
    return np.asarray(encode(ps, jnp.asarray(X)))
