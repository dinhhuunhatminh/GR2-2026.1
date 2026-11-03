# -*- coding: utf-8 -*-
"""Lõi truy vết v2.3-poc (MCP nhánh 2, 29/10/2026): đồ thị tài sản có nguồn gốc – các mối quan hệ lấy TỪ REPO, không phụ thuộc công cụ.
Gốc: b31_do_thi.py (v2.1 đã chấm ở bước 30–31). Khác v2.1 (hậu nghiệm, ghi rõ): (a) bỏ lời gọi phương thức trên đối tượng req/res/next/request/response
(lỗi 'res.status' do kiểm độc lập bước 31 tìm ra); (b) bỏ thư mục 'codefixes' (mã sửa mẫu không chạy); (c) đọc tham số dòng lệnh thay cho bảng APPS cố định.
Đầu vào: kết quả lõi v1 (cùng tập phát hiện) + repo + route map + thư mục quét thô. Đầu ra: cùng định dạng v1 + 'nhan' và 'bang_chung' cho từng cặp ghép.
Usage: python truy_vet_v2.py --v1 kq_v1.json --repo REPO --quet QUET --route-map RM.json --ra OUT.json [--mot-dich-vu ten] [--compose rel ...] [--deploy file] [--cum chat|rong]"""
import json, os, re, sys, glob, collections, argparse
def _relp(*a): return os.path.relpath(*a).replace('\\', '/')   # v1.6: Windows -> dấu '/'
from tree_sitter_language_pack import get_parser
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fam2 import family2
ap = argparse.ArgumentParser()
ap.add_argument('--v1', required=True); ap.add_argument('--repo', required=True); ap.add_argument('--quet', required=True); ap.add_argument('--route-map', required=True)
ap.add_argument('--ra', required=True); ap.add_argument('--mot-dich-vu'); ap.add_argument('--compose', nargs='*', default=None); ap.add_argument('--deploy'); ap.add_argument('--cum', default='chat', choices=['chat', 'rong'])
A_ = ap.parse_args()
REPO = os.path.realpath(A_.repo)
MULTI = (not A_.mot_dich_vu) and os.path.isdir(os.path.join(REPO, 'services'))
SVC1 = A_.mot_dich_vu or os.path.basename(REPO).lower()
COMPOSE = A_.compose if A_.compose is not None else [c for c in ('docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml', 'deploy/docker/docker-compose.yml') if os.path.exists(os.path.join(REPO, c))]
C = {'quet': A_.quet, 'multi': MULTI, 'svc': SVC1, 'compose': COMPOSE, 'deploy': A_.deploy}
R = json.load(open(A_.v1, encoding='utf-8')); F = R['phat_hien']; FB = {f['finding_id']: f for f in F}
RM = json.load(open(A_.route_map, encoding='utf-8'))
_REL = {}
def rel(p):
    """Chuẩn hoá đường dẫn trong cảnh báo về tương đối gốc repo (bỏ tiền tố /src/, ../../src/, tên thư mục repo...)."""
    if not p: return None
    if p in _REL: return _REL[p]
    q = p.replace('\\', '/'); q = re.sub(r'^(?:\.\./)*/?src/', '', q).lstrip('/')
    parts = q.split('/'); out = q
    for k in range(len(parts)):
        cand = '/'.join(parts[k:])
        if os.path.exists(os.path.join(REPO, cand)): out = cand; break
    _REL[p] = out; return out
# ======================= dịch vụ (E4, E5) =======================
SVCS = sorted(d for d in os.listdir(REPO + '/services') if os.path.isdir(REPO + '/services/' + d)) if C['multi'] else [C['svc']]
SVC_BY_LEN = sorted(SVCS, key=len, reverse=True)
def svc_of_path(p):
    p = rel(p) or ''
    if C['multi']:
        m = re.match(r'services/([^/]+)/', p); return m.group(1) if m else None
    return C['svc']
def svc_of_image_file(fn):
    b = os.path.basename(fn or '')
    if C['multi']:
        return next((s for s in SVC_BY_LEN if s in b), None)
    return C['svc'] if re.match(r'^(?:grype_image|dockle)_', b) else None   # một dịch vụ: mọi image quét được coi là image dựng từ repo
# container -> dịch vụ, từ compose (image + container_name)
CONT = {}; COMPOSE_BLOCKS = []   # (tệp, dòng đầu, dòng cuối, dịch vụ)
def parse_compose(path, relname):
    if not os.path.exists(path): return
    L = open(path, encoding='utf-8').read().split('\n'); blocks = []; cur = None; insvc = False
    for i, ln in enumerate(L, 1):
        if re.match(r'^services:\s*$', ln): insvc = True; continue
        if insvc and re.match(r'^\S', ln): insvc = False
        m = re.match(r'^  ([\w.\-]+):\s*$', ln)
        if insvc and m:
            if cur: blocks.append(cur)
            cur = {'name': m.group(1), 'a': i, 'b': i, 'image': None, 'cont': None, 'build': None}
        elif cur:
            cur['b'] = i if ln.strip() else cur['b']
            mi = re.match(r'^\s+image:\s*[\'"]?([^\'"\s]+)', ln); mc = re.match(r'^\s+container_name:\s*(\S+)', ln); mb = re.match(r'^\s+build:\s*(\S+)', ln)
            if mi: cur['image'] = mi.group(1)
            if mc: cur['cont'] = mc.group(1)
            if mb: cur['build'] = mb.group(1)
    if cur: blocks.append(cur)
    for bl in blocks:
        s = None
        if C['multi']:
            s = next((x for x in SVC_BY_LEN if x in (bl['image'] or '') or x == bl['name'] or (bl['build'] or '').rstrip('/').endswith(x)), None)
        else:
            if bl['build'] is not None or C['svc'] in (bl['image'] or '') or C['svc'] in bl['name']: s = C['svc']
        if s:
            if bl['cont']: CONT[bl['cont']] = s
            COMPOSE_BLOCKS.append((relname, bl['a'], bl['b'], s, bl['name']))
for c in C['compose']: parse_compose(os.path.join(REPO, c), c)
if C.get('deploy'): parse_compose(C['deploy'], 'deploy:' + os.path.basename(C['deploy']))
def svc_of_iac(f):
    p = rel(f['anchors']['file_path']) or ''; ln = f['anchors']['line_start'] or 0
    if os.path.basename(p).lower().startswith('dockerfile'): return svc_of_path(p), 'Dockerfile thuộc thư mục dịch vụ'
    for (fn, a, b, s, nm) in COMPOSE_BLOCKS:
        if p.endswith(fn) and a <= ln <= b: return s, f'{fn}:{a}-{b} khối service "{nm}"'
    if C['multi'] and re.match(r'deploy/(?:k8s|helm)/', p):
        s = next((x for x in SVC_BY_LEN if re.search(r'(^|[/\-_.])' + re.escape(x) + r'([/.\-_]|$)', p)), None)
        if s: return s, 'tệp k8s/helm mang tên dịch vụ'
    return None, None
def svc_of_containers(txt):
    out = set()
    for tok in re.split(r'[,\s]+', txt or ''):
        tok = tok.split(':')[0]
        if tok in CONT: out.add(CONT[tok])
    return out

# ======================= hàm và lời gọi (E1, E6) =======================
EXT = {'.js': 'javascript', '.ts': 'typescript', '.py': 'python', '.java': 'java', '.go': 'go', '.php': 'php'}
FN_T = {'function_declaration', 'function_definition', 'method_declaration', 'method_definition', 'constructor_declaration', 'function_expression', 'arrow_function', 'func_literal'}
STOP = {'get', 'set', 'save', 'find', 'update', 'delete', 'create', 'load', 'init', 'run', 'main', 'tostring', 'equals', 'hashcode', 'valueof', 'build', 'of', 'add', 'put',
        'remove', 'contains', 'size', 'isempty', 'format', 'parse', 'error', 'info', 'debug', 'warn', 'log', 'print', 'println', 'append', 'close', 'open', 'read', 'write',
        'send', 'json', 'render', 'response', 'request', 'next', 'then', 'catch', 'filter', 'map', 'join', 'split', 'replace', 'length', 'push', 'call', 'apply', 'bind'}
_P = {}
def parser(lang):
    if lang not in _P: _P[lang] = get_parser(lang)
    return _P[lang]
FUNCS = collections.defaultdict(list)   # (svc, tên) -> [(tệp, a, b)]
CALLS = {}                              # (tệp, a, b) -> {tên được gọi}
FILE_FUNCS = collections.defaultdict(list)
def fname(n, src):
    nm = n.child_by_field_name('name')
    if nm is not None: return src[nm.start_byte:nm.end_byte].decode('utf-8', 'replace')
    p = n.parent   # hàm ẩn danh gán vào biến/thuộc tính
    if p is not None and p.type in ('variable_declarator', 'pair', 'assignment_expression'):
        k = p.child_by_field_name('name') or p.child_by_field_name('key') or p.child_by_field_name('left')
        if k is not None: return src[k.start_byte:k.end_byte].decode('utf-8', 'replace').split('.')[-1]
    return None
def callee(n, src):
    f = n.child_by_field_name('function') or n.child_by_field_name('name')
    if f is None: return None
    t = src[f.start_byte:f.end_byte].decode('utf-8', 'replace')
    parts = re.split(r'[.\->:]+', t)
    if len(parts) > 1 and parts[-2].strip('()').lower() in BO_DOI_TUONG: return None   # v2.3: res.status(), req.get()... là của thư viện web, không phải hàm dự án
    return parts[-1].strip('()') or None
BO_DOI_TUONG = {'req', 'res', 'next', 'request', 'response', 'resp', 'ctx', 'reply', 'w', 'r', 'c', 'http', 'console', 'json', 'math', 'object', 'array', 'string', 'promise', 'this'}
CALL_T = {'call_expression', 'call', 'method_invocation', 'function_call_expression', 'member_call_expression', 'scoped_call_expression'}
def index_repo():
    for dp, dn, fs in os.walk(REPO):
        dn[:] = [d for d in dn if d not in ('.git', 'node_modules', 'vendor', 'test', 'tests', 'external', 'migrations')]
        dn[:] = [d for d in dn if d not in ('codefixes',)]   # v2.3: mã sửa mẫu (Juice Shop) không chạy
        for fn in fs:
            ext = os.path.splitext(fn)[1]
            if ext not in EXT: continue
            p = os.path.join(dp, fn); r = _relp(p, REPO); s = svc_of_path(r)
            if not s: continue
            try: src = open(p, 'rb').read()
            except Exception: continue
            if len(src) > 2_000_000: continue
            tr = parser(EXT[ext]).parse(src); st = [tr.root_node]
            while st:
                n = st.pop(); st.extend(n.children)
                if n.type in FN_T:
                    nm = fname(n, src); key = (r, n.start_point[0] + 1, n.end_point[0] + 1)
                    if nm: FUNCS[(s, nm.lower())].append(key)
                    FILE_FUNCS[r].append(key)
                    cs = set(); q = [n]
                    while q:
                        x = q.pop(); q.extend(x.children)
                        if x.type in CALL_T:
                            c = callee(x, src)
                            if c and len(c) >= 4 and c.lower() not in STOP: cs.add(c.lower())
                    CALLS[key] = cs
index_repo()
def reach(svc, fileh, a, b, depth=2):
    """Hàm handler (tệp, a, b) -> {hàm đích: chuỗi bằng chứng}, qua lời gọi theo tên trong cùng dịch vụ, tên định nghĩa <= 2 lần."""
    start = [k for k in FILE_FUNCS.get(fileh, []) if k[1] <= a <= k[2] or a <= k[1] <= b]
    start = [k for k in start if k[1] >= a - 2 and k[2] <= b + 2] or [(fileh, a, b)]
    out = {k: [] for k in start}; fr = list(start)
    for _ in range(depth):
        nx = []
        for k in fr:
            for c in CALLS.get(k, ()):
                defs = FUNCS.get((svc, c), [])
                if not defs or len(defs) > 2: continue
                for d in defs:
                    if d not in out: out[d] = out[k] + [f'{k[0]}:{k[1]} gọi {c}() -> {d[0]}:{d[1]}-{d[2]}']; nx.append(d)
        fr = nx
    return out
UUIDL = re.compile(r'\{[^}]+\}')
V21 = True   # phương thức HTTP, regex Django, dấu '/' cuối (v2.1)
def pat(r, rx=None):
    if V21 and rx: return re.compile(rx)
    if V21: return re.compile('^' + re.sub(r'\\\{[^}]+\\\}', r'[^/]+', re.escape(r)) + ('?$' if r.endswith('/') else '$'))
    return re.compile('^' + re.sub(r'\\\{[^}]+\\\}', r'[^/]+', re.escape(r.rstrip('/'))) + '/?$')
URLM = collections.defaultdict(set)   # url_route -> phương thức HTTP quan sát được trong tệp quét động thô
for p in glob.glob(os.path.join(C['quet'], 'nuclei*.jsonl')):
    for ln in open(p, encoding='utf-8'):
        if ln.strip():
            r_ = json.loads(ln); u = re.sub(r'^https?://[^/]+', '', r_.get('matched-at', r_.get('host', ''))).split('?')[0]
            m_ = re.search(r"curl -X '(\w+)'", r_.get('curl-command', '') or ''); URLM[u].add(m_.group(1) if m_ else 'GET')
for p in glob.glob(os.path.join(C['quet'], 'zap*.json')):
    for s_ in json.load(open(p)).get('site', []):
        for a_ in s_.get('alerts', []):
            for i_ in a_.get('instances', []): URLM[re.sub(r'^https?://[^/]+', '', i_.get('uri', '')).split('?')[0]].add(i_.get('method', 'GET'))
ENDP = []   # (method, route, svc, pattern, {hàm đích: chuỗi}, nguồn)
for r in RM:
    s = r.get('service') if C['multi'] else C['svc']
    s = {'gateway-service': 'gateway-service'}.get(s, s)
    ENDP.append((r['method'], r['route'], s, (re.compile('^' + re.sub(r'\\\{[^}]+\\\}', r'[^/]+', re.escape(r['route'].rstrip('/'))) + '(/.*)?$') if r['method'] == 'ALL' else pat(r['route'], r.get('regex'))),   # app.use: khớp tiền tố
                  reach(s, r['file'], r['line_start'], r['line_end']), f"{r['file']}:{r['line_start']}-{r['line_end']}"))

# ======================= gắn phát hiện vào nút =======================
def endpoints_of_code(f):
    p = rel(f['anchors']['file_path']); ln = f['anchors']['line_start']
    if not p or not ln: return []
    out = []
    for (m, rt, s, _, fx, src) in ENDP:
        for (fp, a, b), chain in fx.items():
            if (p == fp or p.endswith('/' + fp) or fp.endswith('/' + p)) and a <= ln <= b:
                out.append(((m, rt), [f'E1 route_map: {m} {rt} -> {src}'] + [f'E6 {c}' for c in chain])); break
    return out
def endpoints_of_test(f):
    u = f['anchors']['url_route']
    if not u: return []
    out = [((m, rt), [f'E1 route_map: URL {u} khớp mẫu {m} {rt}']) for (m, rt, s, pt, _, _) in ENDP if pt.match(u) and (not V21 or not URLM.get(u) or m in URLM[u] or m == 'ALL')]
    if V21 and C['multi']:   # Django khớp route theo thứ tự đầu tiên: chỉ giữ mẫu đầu tiên khớp trong cùng dịch vụ workshop
        firsts = {}
        for (m, rt, s, pt, _, _) in ENDP:
            if pt.match(u) and s == 'workshop': firsts.setdefault(m, rt)
        out = [x for x in out if not any(x[0][1] != firsts.get(x[0][0], x[0][1]) for _ in [0])]
    return out
for f in F:
    f['nut'] = {}
    t = f['tool']
    if f['phase'] == 'CODE': f['nut']['endpoint'] = endpoints_of_code(f); f['nut']['svc'] = svc_of_path(f['anchors']['file_path'])
    elif f['phase'] == 'TEST': f['nut']['endpoint'] = endpoints_of_test(f)
    if t in ('osv-scanner',) or (t == 'grype' and f['anchors']['container_target'] == 'dir'): f['nut']['svc'] = svc_of_path(f['anchors']['file_path']) or (f['svc'][0] if f['svc'] else None)
    if t == 'grype' and f['anchors']['container_target'] == 'image': f['nut']['svc'] = f['svc'][0] if f['svc'] else None
    if t == 'dockle': f['nut']['svc'] = svc_of_image_file(f['anchors']['container_target'])
    if t == 'kics': f['nut']['svc'], f['nut']['svc_nguon'] = svc_of_iac(f)
    if t == 'docker_bench': f['nut']['svcs'] = sorted(svc_of_containers(f['anchors']['container_target']))

# ======================= E2: tệp repo -> tệp trong image (Dockerfile COPY/ADD) =======================
import fnmatch, posixpath
def stages(svc):
    """Dockerfile của dịch vụ -> danh sách giai đoạn [(tên, [(loại, nguồn[], đích, from, bằng chứng)])]; mở rộng ENV/ARG/WORKDIR."""
    d = os.path.join(REPO, 'services', svc) if C['multi'] else REPO
    df = os.path.join(d, 'Dockerfile'); st = []
    if not os.path.exists(df): return st, d
    env = {}; wd = '/'
    raw = open(df, encoding='utf-8', errors='ignore').read().split('\n'); lines = []; buf = ''; start = 0
    for i, ln in enumerate(raw, 1):
        if not buf: start = i
        if ln.rstrip().endswith('\\'): buf += ln.rstrip()[:-1] + ' '; continue
        lines.append((start, buf + ln)); buf = ''
    def ex(x): return re.sub(r'\$\{?(\w+)\}?', lambda m: env.get(m.group(1), m.group(0)), x)
    for i, ln in lines:
        m = re.match(r'^\s*(\w+)\s+(.*)$', ln)
        if not m: continue
        k, v = m.group(1).upper(), m.group(2).strip()
        if k == 'FROM':
            nm = re.search(r'\s+as\s+(\S+)', v, re.I); st.append((nm.group(1) if nm else str(len(st)), [])); wd = '/'
        elif k in ('ENV', 'ARG'):
            mm = re.match(r'(\w+)(?:\s*=\s*|\s+)(\S+)', v)
            if mm: env[mm.group(1)] = mm.group(2).strip('"')
        elif k == 'WORKDIR':
            w = ex(v); wd = w if w.startswith('/') else posixpath.join(wd, w)
        elif k in ('COPY', 'ADD') and st:
            parts = v.split(); fr = None; pp = []
            for x in parts:
                if x.startswith('--from='): fr = x.split('=', 1)[1]
                elif not x.startswith('--'): pp.append(ex(x))
            if len(pp) < 2: continue
            dest = pp[-1]; dest_abs = dest if dest.startswith('/') else posixpath.join(wd, dest)
            st[-1][1].append((pp[:-1], dest_abs, dest.endswith('/') or dest in ('.', './') or len(pp) > 2, fr, f'{_relp(df, REPO)}:{i} {k} {v}'))
    return st, d
def paths_in(st, idx, r, depth=0):
    """Đường dẫn của tệp context r trong giai đoạn idx -> [(đường dẫn, [bằng chứng])]."""
    out = []
    if depth > 5: return out
    for srcs, dest, isdir, fr, ev in st[idx][1]:
        for s_ in srcs:
            if fr is None:
                s0 = s_.lstrip('./') if s_ not in ('.', './') else ''
                if s0 == '' or r == s0 or r.startswith(s0.rstrip('/') + '/') or fnmatch.fnmatch(r, s0):
                    if s0 == '' or r.startswith(s0.rstrip('/') + '/'): q = posixpath.join(dest, r[len(s0):].lstrip('/') if s0 else r)
                    else: q = posixpath.join(dest, posixpath.basename(r)) if isdir else dest
                    out.append((posixpath.normpath(q), [ev]))
            else:
                j = next((k for k, (nm, _) in enumerate(st) if nm == fr), None)
                if j is None or j >= idx: continue
                for (q0, ev0) in paths_in(st, j, r, depth + 1):
                    s1 = s_.rstrip('/')
                    if q0 == s1 or q0.startswith(s1 + '/'):
                        rest = q0[len(s1):].lstrip('/')
                        q = posixpath.join(dest, rest) if rest else (posixpath.join(dest, posixpath.basename(q0)) if isdir else dest)
                        out.append((posixpath.normpath(q), ev0 + [ev]))
    return out
def image_path(svc, repo_file):
    st, ctx = stages(svc)
    if not st: return []
    r = _relp(os.path.join(REPO, repo_file), ctx)
    if r.startswith('..'): return []
    di = os.path.join(ctx, '.dockerignore')   # tệp bị .dockerignore loại thì không vào image
    if os.path.exists(di):
        for pt in (x.strip() for x in open(di, encoding='utf-8', errors='ignore')):
            if not pt or pt.startswith('#') or pt.startswith('!'): continue
            p0 = pt[3:] if pt.startswith('**/') else pt.lstrip('/')
            if fnmatch.fnmatch(r, p0) or fnmatch.fnmatch(os.path.basename(r), p0) or r.startswith(p0.rstrip('/') + '/'): return []
    return [(q.lstrip('/'), ' => '.join(ev)) for q, ev in paths_in(st, len(st) - 1, r)]   # chỉ giai đoạn cuối = image chạy thật
def dockle_paths(f):
    p = f['anchors']['container_target']
    try: d = json.load(open(os.path.join(C['quet'], os.path.basename(p)), encoding='utf-8'))
    except Exception:
        try: d = json.load(open(p, encoding='utf-8'))
        except Exception: return []
    out = []
    for x in d.get('details', []):
        if x.get('code') == f['raw_rule_id']:
            for a in x.get('alerts', []):
                m = re.search(r'Suspicious filename found : (\S+)', a)
                if m: out.append(m.group(1).lstrip('/'))
    return out

# ======================= vết V1–V4 =======================
E = []
def nhan(a, b):
    if a['family'] == 'khac' or b['family'] == 'khac': return 'chua_ro_ho'
    return 'cung_loi' if a['family'] == b['family'] else 'cung_tai_san'
def vet(a, b, kind, ev, lab=None):
    E.append({'a': a['finding_id'], 'b': b['finding_id'], 'luat': kind, 'nhan': lab or nhan(a, b), 'bang_chung': ev})
code = [f for f in F if f['phase'] == 'CODE' and f['nut'].get('endpoint')]
test = [f for f in F if f['phase'] == 'TEST' and f['nut'].get('endpoint')]
TE = collections.defaultdict(list)
for t in test:
    for (ep, ev) in t['nut']['endpoint']: TE[ep].append((t, ev))
for a in code:
    seen = set()
    for (ep, ev) in a['nut']['endpoint']:
        for (b, ev2) in TE.get(ep, []):
            if b['finding_id'] in seen: continue
            seen.add(b['finding_id']); vet(a, b, 'V1', ev + ev2)
# V2 bí mật: gitleaks tệp p -> COPY -> tệp q trong image -> dockle CIS-DI-0010 liệt kê q (cùng dịch vụ)
gl = [f for f in F if f['tool'] == 'gitleaks']; dk = [f for f in F if f['tool'] == 'dockle' and f['raw_rule_id'] == 'CIS-DI-0010']
DKP = {f['finding_id']: dockle_paths(f) for f in dk}
for a in gl:
    p = rel(a['anchors']['file_path']); s = svc_of_path(p)
    if not s: continue
    for (q, ev) in image_path(s, p):
        for b in dk:
            if b['nut'].get('svc') == s and any(x == q or x.endswith('/' + q) or q.endswith('/' + x) for x in DKP[b['finding_id']]):
                vet(a, b, 'V2', [f'E5 {p} thuộc dịch vụ {s}', f'E2 {ev} => {q}', f'dockle {os.path.basename(b["anchors"]["container_target"])} liệt kê {q}'], 'cung_loi')
    # bí mật lộ qua HTTP: cảnh báo TEST có tên tệp nhạy cảm trùng tên, route thuộc dịch vụ có image chứa tệp (nginx/web phục vụ)
    for b in [f for f in F if f['phase'] == 'TEST' and f['anchors'].get('sens_file')]:
        if os.path.basename(p).lower() == str(b['anchors']['sens_file']).lower() and image_path(s, p):
            vet(a, b, 'V2', [f'E2 {p} được COPY vào image dịch vụ {s}', f'URL {b["anchors"]["url_route"]} trả tệp cùng tên'], 'cung_loi')
# V2b: tệp nhạy cảm q trong image dịch vụ s (dockle CIS-DI-0010) <-> URL TEST trả tệp cùng tên trên route của dịch vụ s
def svc_of_url(u):
    if not C['multi']: return C['svc']
    seg = (u or '').strip('/').split('/')[0]
    return seg if seg in SVCS else ('web' if 'web' in SVCS else None)   # cổng chung (nginx) chuyển /<dịch vụ>/ tới dịch vụ đó, còn lại do web phục vụ
for b in [f for f in F if f['phase'] == 'TEST' and f['anchors'].get('sens_file')]:
    for a in dk:
        if a['nut'].get('svc') == svc_of_url(b['anchors']['url_route']) and any(os.path.basename(x).lower() == str(b['anchors']['sens_file']).lower() for x in DKP[a['finding_id']]):
            vet(a, b, 'V2', [f'dockle image dịch vụ {a["nut"]["svc"]} chứa ' + ', '.join(x for x in DKP[a['finding_id']] if os.path.basename(x).lower() == str(b['anchors']['sens_file']).lower()),
                             f'URL {b["anchors"]["url_route"]} thuộc dịch vụ {svc_of_url(b["anchors"]["url_route"])} (nginx location)'], 'cung_loi')
# Lan truyền (không phải cạnh giữa hai cảnh báo): bí mật trong repo được COPY vào image và chạy trong container của dịch vụ
LAN = []
for a in gl:
    p = rel(a['anchors']['file_path']); s = svc_of_path(p)
    if s:
        for (q, ev) in image_path(s, p):
            ct = [c for c, v in CONT.items() if v == s]
            a.setdefault('lan_truyen', []).append({'image_path': q, 'bang_chung': ev, 'container': ct}); LAN.append((a['finding_id'], p, q, ev, ct))
# V3 gói: cùng (CVE, gói), lockfile thuộc dịch vụ s (E5) và image của s (E4)
bd = [f for f in F if f['phase'] == 'BUILD']; rl = [f for f in F if f['tool'] == 'grype' and f['anchors']['container_target'] == 'image']
IDX = collections.defaultdict(list)
for b in rl: IDX[(b['anchors']['cve_id'], b['anchors']['package_name'], b['nut'].get('svc'))].append(b)
for a in bd:
    s = a['nut'].get('svc')
    for b in IDX.get((a['anchors']['cve_id'], a['anchors']['package_name'], s), []):
        vet(a, b, 'V3', [f'E5 {rel(a["anchors"]["file_path"])} thuộc dịch vụ {s}', f'E4 image dịch vụ {s}', f'cùng {a["anchors"]["package_name"]} / {a["anchors"]["cve_id"]}'], 'cung_loi')
# V4 cấu hình: lớp kiểm soát theo bảng L4 của lõi cũ (giữ nguyên) + cùng dịch vụ qua E4
L4 = {'run_as_root': (r'user|root', 'CIS-DI-0001'), 'mem_limit': (r'memory|cpu|resource', None), 'rw_rootfs': (r'read.?only|writable', None),
      'privileged': (r'privileged container|privileged mode|no-new-privileges|escalation|security_opt', None), 'healthcheck': (r'health', 'CIS-DI-0006')}
DB_DESC = {'run_as_root': r'user', 'mem_limit': r'memory usage', 'rw_rootfs': r'root filesystem', 'privileged': r'acquiring additional privileges|privileged containers', 'healthcheck': r'health'}
def l4class(f):
    t = str(f['anchors']['cis_control_class'] or '')
    for k, (rx, dk_) in L4.items():
        if f['tool'] == 'dockle' and dk_ and t == dk_: return k
        if f['tool'] == 'docker_bench' and re.search(DB_DESC[k], t, re.I): return k
        if f['tool'] == 'kics' and re.search(rx, t, re.I): return k
cfg = [f for f in F if f['tool'] in ('kics', 'dockle')]; dbn = [f for f in F if f['tool'] == 'docker_bench']
for a in cfg:
    ka = l4class(a); sa = a['nut'].get('svc')
    if not ka or not sa: continue
    for b in dbn:
        if l4class(b) == ka and sa in b['nut'].get('svcs', []):
            vet(a, b, 'V4', [f'{a["tool"]} thuộc dịch vụ {sa} ({a["nut"].get("svc_nguon") or "image " + os.path.basename(str(a["anchors"]["container_target"]))})', f'E4 container của {sa} trong docker_bench', f'cùng lớp {ka}'], 'cung_loi')
    for b in cfg:
        if b['tool'] != a['tool'] and b['finding_id'] > a['finding_id'] and l4class(b) == ka and b['nut'].get('svc') == sa:
            vet(a, b, 'V4', [f'{a["tool"]} và {b["tool"]} cùng dịch vụ {sa}', f'cùng lớp {ka}'], 'cung_loi')
# L0 giữ nguyên từ v1.4 (cùng pha, cùng tệp ±5 dòng, cùng họ, khác công cụ)
for e in R['canh']:
    if e['luat'] == 'L0': E.append(dict(e, nhan='cung_loi', bang_chung=['L0 v1.4']))

# ======================= cụm, Tier =======================
P = {f['finding_id']: f['finding_id'] for f in F}
def fd(x):
    while P[x] != x: P[x] = P[P[x]]; x = P[x]
    return x
for e in E:
    if e['nhan'] in (('cung_loi',) if A_.cum == 'chat' else ('cung_loi', 'chua_ro_ho')): P[fd(e['a'])] = fd(e['b'])   # B30_CUM=chat: biến thể hậu nghiệm 2.0b (ghi phiếu mục 9)
CL = collections.defaultdict(list)
for f in F: CL[fd(f['finding_id'])].append(f)
for k, fs in CL.items():
    ph = {f['phase'] for f in fs}; tl = {f['tool'] for f in fs}; t = 1 if len(ph) >= 2 else 2 if len(tl) >= 2 else 3
    for f in fs: f['tier'] = t; f['cum'] = k
    for f in fs: f['routes'] = sorted({ep[1] for ep, _ in f['nut'].get('endpoint', [])}) or f.get('routes', [])
cnt = collections.Counter((e['luat'], e['nhan']) for e in E)
res = {'phien_ban': '2.3-poc', 'repo': REPO, 'mot_dich_vu': None if MULTI else SVC1, 'dich_vu': SVCS, 'cum': A_.cum, 'tong_phat_hien': len(F), 'theo_cong_cu': R['theo_cong_cu'], 'cong_cu_thieu': R.get('cong_cu_thieu', []),
       'so_canh': {r: sum(1 for e in E if e['luat'] == r) for r in ('L0', 'V1', 'V2', 'V3', 'V4')},
       'canh_theo_nhan': {f'{a}|{b}': v for (a, b), v in sorted(cnt.items())}, 'so_cum': len(CL), 'tier_theo_phat_hien': dict(collections.Counter(f['tier'] for f in F)),
       'lan_truyen_bi_mat': LAN, 'so_endpoint': len(ENDP), 'container_dich_vu': CONT, 'khoi_compose': COMPOSE_BLOCKS,
       'cum_list': [{'id': k, 'tier': fs[0]['tier'], 'pha': sorted({f['phase'] for f in fs}), 'cong_cu': sorted({f['tool'] for f in fs}), 'so_phat_hien': len(fs)} for k, fs in CL.items() if len(fs) > 1],
       'phat_hien': F, 'canh': E}
json.dump(res, open(A_.ra, 'w', encoding='utf-8'), ensure_ascii=False, indent=0, default=list)
print(json.dumps({k: res[k] for k in ('phien_ban', 'so_canh', 'canh_theo_nhan', 'so_cum', 'tier_theo_phat_hien', 'so_endpoint')}, ensure_ascii=False))
