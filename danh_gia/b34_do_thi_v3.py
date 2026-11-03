"""Bước 34 – Đồ thị nguồn gốc tài sản v3.0 (PHIEU_BUOC34.md). Nhánh 2.
Đầu vào: kết quả lõi v1.4 (tập phát hiện chuẩn hoá) + repo đã ghim + bản đồ route + tệp quét thô — cùng đầu vào của v2.1 (b31_do_thi.py). KHÔNG quét động.
Đầu ra: cùng định dạng v2.1 (phat_hien/canh/cum/tier) để chấm bằng b24_cham.py nguyên văn, cộng:
  ds_lien_ket_chinh (cạnh V1 giữ lại theo cải tiến 3), canh_loai_v1 (cạnh V1 bị loại + lý do), ham_hub, 'muc_phoi_nhiem_tinh', 'da_lam_sach' trên từng phát hiện CODE.
Các cải tiến: E6_v3 (import_map + lọc receiver + loại mã không chạy), E1_v3 (xếp hạng độ đặc hiệu route), Hub + gom cụm 2 bước, V1_intra + V4 mở rộng + M1..M4 + sanitizer.
Usage: B34_DATA=<thư mục dữ liệu> python b34_do_thi_v3.py <app>   (app trong APPS)"""
import json, os, re, sys, glob, collections, fnmatch, posixpath
from tree_sitter_language_pack import get_parser

CANCU_TOL = int(os.environ.get('B34_CANCU_TOL', '2'))
B = os.environ.get('B34_DATA', '/home/claude/b34'); OUT = os.environ.get('B34_OUT', B + '/kq3'); sys.path.insert(0, B)
X32 = B + '/x/buoc32_ai_sinh_code'
APPS = {
    'JuiceShop': dict(repo=B + '/juiceshop', quet=B + '/quet', rmap=B + '/route_map_juiceshop_v3.json', v14=B + '/kq/v14c_JuiceShop.json', multi=False, svc='juiceshop', compose=[], deploy=None),
    'crAPI': dict(repo=B + '/crapi', quet=B + '/vao/crapi_quet', rmap=B + '/route_map_crapi.json', v14=B + '/kq/v14_crAPI.json', multi=True, compose=['deploy/docker/docker-compose.yml']),
    'VAmPI': dict(repo=B + '/VAmPI', quet=B + '/vao/buoc24_nhieu_ung_dung/quet/VAmPI', rmap=B + '/vao/buoc24_nhieu_ung_dung/dap_an/route_map_VAmPI.json',
                  v14=B + '/kq/v14_VAmPI.json', multi=False, svc='vampi', compose=['docker-compose.yaml'], deploy=B + '/vao/buoc24_nhieu_ung_dung/deploy/vampi/docker-compose.yml'),
    'NodeGoat': dict(repo=B + '/NodeGoat', quet=B + '/vao/buoc24_nhieu_ung_dung/quet/NodeGoat', rmap=B + '/vao/buoc24_nhieu_ung_dung/dap_an/route_map_NodeGoat.json',
                     v14=B + '/kq/v14_NodeGoat.json', multi=False, svc='nodegoat', compose=['docker-compose.yml'], deploy=B + '/vao/buoc24_nhieu_ung_dung/deploy/nodegoat/docker-compose.yml'),
    'DVWA': dict(repo=B + '/DVWA', quet=B + '/vao/buoc24_nhieu_ung_dung/quet/DVWA', rmap=B + '/vao/buoc24_nhieu_ung_dung/dap_an/route_map_DVWA.json',
                 v14=B + '/kq/v14_DVWA.json', multi=False, svc='dvwa', compose=['compose.yml'], deploy=B + '/vao/buoc24_nhieu_ung_dung/deploy/dvwa/docker-compose.yml'),
    'AIBook': dict(repo=X32 + '/app', quet=X32 + '/quet', rmap=X32 + '/cham/route_map_v17.json', v14=X32 + '/kq/vet_v2.json', multi=False, svc='clb-doc-sach', compose=['docker-compose.yml'], deploy=None),
}
if sys.argv[1] == '--cau-hinh':   # chế độ MCP: cấu hình ứng dụng truyền qua tệp JSON (repo, quet, rmap, v14, multi, svc, compose, deploy, ra)
    C = json.load(open(sys.argv[2], encoding='utf-8')); APP = C.get('ten', 'App'); OUTFILE = C['ra']
else:
    APP = sys.argv[1]; C = APPS[APP]; OUTFILE = None
REPO = C['repo']
R = json.load(open(C['v14'], encoding='utf-8')); F = R['phat_hien']; FB = {f['finding_id']: f for f in F}
RM = json.load(open(C['rmap'], encoding='utf-8'))
def rel(p):
    if not p: return None
    p = p.replace('\\', '/'); p = re.sub(r'^(?:\.\./)*/?src/', '', p); p = re.sub(r'^/?juiceshop/', '', p); return p.lstrip('/')

# ======================= dịch vụ (E4, E5) — giữ nguyên v2.1 =======================
SVCS = sorted(d for d in os.listdir(REPO + '/services') if os.path.isdir(REPO + '/services/' + d)) if C['multi'] else [C['svc']]
def svc_of_path(p):
    p = rel(p) or ''
    if C['multi']:
        m = re.match(r'services/([^/]+)/', p); return m.group(1) if m else None
    return C['svc']
def svc_of_image_file(fn):
    b = os.path.basename(fn or '')
    if C['multi']:
        m = re.match(r'^(?:grype_image|dockle)_crapi_(?:crapi-)?(.+)\.json$', b); return m.group(1) if m else None
    return C['svc'] if (re.match(r'^(?:grype_image|dockle)_gr2_.+-pin\.json$', b) or (APP == 'AIBook' and re.match(r'^(?:grype_image|dockle)_.+\.json$', b))) else None
CONT = {}; COMPOSE_BLOCKS = []
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
            m = re.match(r'crapi/(?:crapi-)?([\w\-]+)', bl['image'] or '')
            if m and m.group(1) in SVCS: s = m.group(1)
        else:
            if bl['build'] is not None or (bl['image'] or '').startswith('gr2/'): s = C['svc']
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
    m = re.match(r'deploy/(?:k8s|helm)/.*?/(?:crapi-)?(identity|community|workshop|chatbot|web|gateway-service)[/.]', p)
    if C['multi'] and m: return m.group(1), 'thư mục/tệp k8s mang tên dịch vụ'
    return None, None
def svc_of_containers(txt):
    out = set()
    for tok in re.split(r'[,\s]+', txt or ''):
        tok = tok.split(':')[0]
        if tok in CONT: out.add(CONT[tok])
    return out

# ======================= E6_v3: chỉ mục hàm, import_map, lọc receiver =======================
EXT = {'.js': 'javascript', '.ts': 'typescript', '.py': 'python', '.java': 'java', '.go': 'go', '.php': 'php'}
FN_T = {'function_declaration', 'function_definition', 'method_declaration', 'method_definition', 'constructor_declaration', 'function_expression', 'arrow_function', 'func_literal'}
CALL_T = {'call_expression', 'call', 'method_invocation', 'function_call_expression', 'member_call_expression', 'scoped_call_expression'}
# (1) thư mục KHÔNG phải mã chạy thật — loại trước khi lập chỉ mục (phiếu 34, cải tiến 1, bước 1)
DEAD_DIRS = {'codefixes', 'test', 'tests', '__tests__', 'spec', 'frontend', 'node_modules', 'dist', 'build', 'vendor'}
def dead_reason(r):
    parts = (r or '').split('/')
    for p in parts[:-1]:
        if p in DEAD_DIRS: return f'thư mục {p}/ không phải mã chạy thật'
    if re.search(r'\.(test|spec)\.[jt]sx?$', r or ''): return 'tệp kiểm thử'
    return None
# (3) Kiểu A: gốc của chuỗi gọi thuộc tập đối tượng HTTP / built-in / ORM → cấm nối sang hàm top-level tệp khác
BLOCK = {'req', 'res', 'next', 'request', 'response', 'ctx', 'app', 'router', 'console', 'JSON', 'Math', 'Object', 'Array', 'String', 'Number', 'Promise', 'Date', 'RegExp',
         'Buffer', 'process', 'window', 'document', 'db', 'models', 'Sequelize', 'mongoose', 'this', 'super', 'err', 'error'}
SAMEFILE_ONLY = {'this', 'self', 'cls'}   # gọi qua this/self: chỉ được nối tới hàm CÙNG TỆP
# Kiểu C ưu tiên 3 (fallback cùng dịch vụ, chỉ Go/Java/PHP): loại tên phổ biến
COMMON = {'status', 'init', 'main', 'check', 'verify', 'handle', 'index', 'create', 'update', 'delete', 'get', 'set', 'run', 'execute', 'render', 'send', 'json'}
STOP = {'save', 'find', 'load', 'tostring', 'equals', 'hashcode', 'valueof', 'build', 'of', 'add', 'put', 'remove', 'contains', 'size', 'isempty', 'format', 'parse', 'error', 'info', 'debug',
        'warn', 'log', 'print', 'println', 'append', 'close', 'open', 'read', 'write', 'response', 'request', 'then', 'catch', 'filter', 'map', 'join', 'split', 'replace', 'length', 'push', 'call', 'apply', 'bind'}
_P = {}
def parser(lang):
    if lang not in _P: _P[lang] = get_parser(lang)
    return _P[lang]
def T(n, src): return src[n.start_byte:n.end_byte].decode('utf-8', 'replace')
FUNCS = collections.defaultdict(list)      # (dịch vụ, tên thường) -> [khoá hàm]
FILEDEF = collections.defaultdict(lambda: collections.defaultdict(list))   # tệp -> tên thường -> [khoá hàm]
FILE_FUNCS = collections.defaultdict(list)
CALLS = {}                                  # khoá hàm -> [(gốc|None, phương thức, trực_tiếp)]
TYPES = collections.defaultdict(dict)       # tệp -> {biến: kiểu}  (Java)
CLASSDEF = collections.defaultdict(list)    # (dịch vụ, tên lớp) -> [tệp]
RAWIMP = {}; ALLFILES = {}; SRC = {}; LANGOF = {}
def fname(n, src):
    nm = n.child_by_field_name('name')
    if nm is not None: return T(nm, src)
    p = n.parent
    if p is not None and p.type in ('variable_declarator', 'pair', 'assignment_expression'):
        k = p.child_by_field_name('name') or p.child_by_field_name('key') or p.child_by_field_name('left')
        if k is not None: return T(k, src).split('.')[-1]
    return None
def call_shape(x, src):
    """Nút gọi -> (gốc, phương thức, trực_tiếp) hoặc None. gốc = định danh đầu của chuỗi `a.b.c()`; None nếu gọi trực tiếp fn()."""
    t = x.type
    if t == 'method_invocation':            # Java
        obj = x.child_by_field_name('object'); nm = x.child_by_field_name('name')
        if nm is None: return None
        if obj is None: return (None, T(nm, src), True, False)
        ot = T(obj, src); m = re.match(r'^\s*([A-Za-z_$][\w$]*)', ot)
        return (m.group(1) if m else '<expr>', T(nm, src), False, bool(m) and ot.strip() == m.group(1))
    if t == 'member_call_expression':        # PHP $obj->m()
        obj = x.child_by_field_name('object'); nm = x.child_by_field_name('name')
        if nm is None: return None
        m = re.match(r'^\s*\$?([A-Za-z_]\w*)', T(obj, src)) if obj is not None else None
        return (m.group(1) if m else '<expr>', T(nm, src), False, True)
    if t == 'scoped_call_expression':        # PHP Class::m()
        sc = x.child_by_field_name('scope'); nm = x.child_by_field_name('name')
        if nm is None: return None
        return (T(sc, src) if sc is not None else '<expr>', T(nm, src), False, True)
    f = x.child_by_field_name('function') or x.child_by_field_name('name')
    if f is None: return None
    ft = T(f, src).strip()
    if re.match(r'^[A-Za-z_$][\w$]*$', ft): return (None, ft, True, False)
    m = re.match(r'^(?:await\s+)?([A-Za-z_$][\w$]*)\s*[\.\[\(]', ft) or re.match(r'^(?:await\s+)?([A-Za-z_$][\w$]*)\s*$', ft)
    root = m.group(1) if m else '<expr>'
    mm = re.search(r'(?:\.|->|::)\s*([A-Za-z_$][\w$]*)\s*$', ft)
    if not mm: return None
    two = re.match(r'^(?:await\s+)?[A-Za-z_$][\w$]*\s*(?:\.|->|::)\s*[A-Za-z_$][\w$]*\s*$', ft) is not None   # đúng dạng mod.fn
    return (root, mm.group(1), False, two)
def index_file(p, r, s, ext):
    try: src = open(p, 'rb').read()
    except Exception: return
    if len(src) > 2_000_000: return
    lang = EXT[ext]; LANGOF[r] = lang; SRC[r] = src
    tr = parser(lang).parse(src); st = [tr.root_node]
    cls_name = lambda n: (T(n.child_by_field_name('name'), src) if n.child_by_field_name('name') is not None else None)
    while st:
        n = st.pop(); st.extend(n.children)
        if n.type in FN_T:
            nm = fname(n, src); key = (r, n.start_point[0] + 1, n.end_point[0] + 1)
            if nm: FUNCS[(s, nm.lower())].append(key); FILEDEF[r][nm.lower()].append(key)
            FILE_FUNCS[r].append(key)
            cs = []; q = [n]
            while q:
                x = q.pop(); q.extend(x.children)
                if x.type in CALL_T:
                    sh = call_shape(x, src)
                    if sh: cs.append(sh)
            CALLS[key] = cs
        elif n.type in ('class_declaration', 'interface_declaration') and lang == 'java':
            nm = cls_name(n)
            if nm: CLASSDEF[(s, nm)].append(r)
        elif lang == 'java' and n.type in ('field_declaration', 'local_variable_declaration'):
            tn = n.child_by_field_name('type')
            if tn is not None:
                ty = re.sub(r'<.*>', '', T(tn, src)).strip()
                for c in n.children:
                    if c.type == 'variable_declarator' and c.child_by_field_name('name') is not None: TYPES[r][T(c.child_by_field_name('name'), src)] = ty
        elif lang == 'java' and n.type == 'formal_parameter':
            tn = n.child_by_field_name('type'); nm = n.child_by_field_name('name')
            if tn is not None and nm is not None: TYPES[r][T(nm, src)] = re.sub(r'<.*>', '', T(tn, src)).strip()
    ALLFILES[r] = s
    RAWIMP[r] = src.decode('utf-8', 'replace')
def index_repo():
    for dp, dn, fs in os.walk(REPO):
        dn[:] = [d for d in dn if d not in ('.git',) and d not in DEAD_DIRS]
        for fn in fs:
            ext = os.path.splitext(fn)[1]
            if ext not in EXT: continue
            p = os.path.join(dp, fn); r = os.path.relpath(p, REPO).replace(os.sep, '/'); s = svc_of_path(r)
            if not s or dead_reason(r): continue
            index_file(p, r, s, ext)
index_repo()
BYDIR = collections.defaultdict(list)
for r_ in ALLFILES: BYDIR[posixpath.dirname(r_)].append(r_)
# ---- import_map: tên cục bộ -> (tệp đích | None, ký hiệu | None, loại 'ns'|'named'|'default'|'cls'|'dir') ----
_IM = {}
def js_resolve(r, mod):
    if not mod.startswith('.'): return None
    base = posixpath.normpath(posixpath.join(posixpath.dirname(r), mod))
    for suf in ('', '.ts', '.js', '.tsx', '.jsx', '/index.ts', '/index.js'):
        if (base + suf) in ALLFILES: return base + suf
    return None
def py_resolve(r, mod, level=0):
    s = ALLFILES.get(r); parts = [x for x in mod.split('.') if x]
    if level:
        base = posixpath.dirname(r)
        for _ in range(level - 1): base = posixpath.dirname(base)
        cands = [posixpath.join(base, *parts)]
    else:
        cands = []
        d = posixpath.dirname(r)
        while True:   # từ thư mục hiện tại leo dần tới gốc dịch vụ/repo
            cands.append(posixpath.join(d, *parts))
            if not d: break
            d = posixpath.dirname(d)
    out = []
    for c in cands:
        for suf in ('.py', '/__init__.py'):
            q = posixpath.normpath(c + suf)
            if q in ALLFILES and ALLFILES[q] == s: out.append(q)
        if out: break
    return out[0] if out else None
def imports_of(r):
    if r in _IM: return _IM[r]
    src = RAWIMP.get(r, ''); lang = LANGOF.get(r); m_ = {}
    if lang in ('javascript', 'typescript'):
        for m in re.finditer(r"""(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)(?:\.([A-Za-z_$][\w$]*))?""", src):
            t = js_resolve(r, m.group(2))
            if t: m_[m.group(1)] = (t, m.group(3), 'named' if m.group(3) else 'ns')
        for m in re.finditer(r"""(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)""", src):
            t = js_resolve(r, m.group(2))
            if t:
                for it in m.group(1).split(','):
                    it = it.strip()
                    if not it: continue
                    a_, _, b_ = it.partition(':'); sym = a_.strip(); loc = (b_.strip() or sym); m_[loc] = (t, sym, 'named')
        for m in re.finditer(r"""import\s+(?:([A-Za-z_$][\w$]*)\s*,?\s*)?(?:\*\s+as\s+([A-Za-z_$][\w$]*)|\{([^}]*)\})?\s*from\s*['"]([^'"]+)['"]""", src):
            t = js_resolve(r, m.group(4))
            if not t: continue
            if m.group(1): m_[m.group(1)] = (t, None, 'default')
            if m.group(2): m_[m.group(2)] = (t, None, 'ns')
            if m.group(3):
                for it in m.group(3).split(','):
                    it = it.strip()
                    if not it: continue
                    sym, _, loc = it.partition(' as '); sym = sym.strip(); loc = (loc.strip() or sym); m_[loc] = (t, sym, 'named')
    elif lang == 'python':
        for m in re.finditer(r'^[ \t]*from\s+(\.*)([\w.]*)\s+import\s+(\([^)]*\)|[^\n]+)', src, re.M):
            lvl = len(m.group(1)); mod = m.group(2); names = m.group(3).strip('()').replace('\n', ' ')
            tmod = py_resolve(r, mod, lvl) if (mod or lvl) else None
            for it in names.split(','):
                it = it.strip()
                if not it or it == '*': continue
                sym, _, loc = it.partition(' as '); sym = sym.strip(); loc = (loc.strip() or sym)
                sub = py_resolve(r, (mod + '.' if mod else '') + sym, lvl)
                if tmod and sym.lower() in FILEDEF.get(tmod, {}): m_[loc] = (tmod, sym, 'named')
                elif sub: m_[loc] = (sub, None, 'ns')
                elif tmod: m_[loc] = (tmod, sym, 'named')
        for m in re.finditer(r'^[ \t]*import\s+([\w.]+)(?:\s+as\s+(\w+))?', src, re.M):
            t = py_resolve(r, m.group(1))
            if t: m_[m.group(2) or m.group(1).split('.')[0]] = (t, None, 'ns')
    elif lang == 'java':
        s = ALLFILES.get(r)
        for m in re.finditer(r'^\s*import\s+(?:static\s+)?([\w.]+)\.(\w+)\s*;', src, re.M):
            cand = [f for f in CLASSDEF.get((s, m.group(2)), []) if f.endswith(m.group(1).replace('.', '/') + '/' + m.group(2) + '.java')] or CLASSDEF.get((s, m.group(2)), [])
            if len(cand) >= 1: m_[m.group(2)] = (cand[0], None, 'cls')
    elif lang == 'go':
        s = ALLFILES.get(r)
        for m in re.finditer(r'^\s*(?:import\s+)?(?:(\w+)\s+)?"([^"]+)"', src, re.M):
            last = m.group(2).split('/')[-1]; alias = m.group(1) or last
            ds = [d for d in BYDIR if d and (d.endswith('/' + last) or d == last) and any(ALLFILES[f] == s for f in BYDIR[d])]
            if ds: m_[alias] = (ds[0], None, 'dir')
    elif lang == 'php':
        for m in re.finditer(r"""(?:require|include)(?:_once)?\s*\(?\s*(?:[A-Za-z_]+\s*\.\s*)?['"]([^'"]+)['"]""", src):
            tail = m.group(1).lstrip('./')
            cand = [f for f in ALLFILES if f.endswith('/' + tail) or f == tail]
            if len(cand) == 1: m_['__inc__' + cand[0]] = (cand[0], None, 'inc')
    _IM[r] = m_; return m_
def keys_named(tfile, names):
    for nm in names:
        ks = FILEDEF.get(tfile, {}).get(nm.lower())
        if ks: return ks
    return []
def default_fn(tfile, local):
    ks = keys_named(tfile, [local, posixpath.splitext(posixpath.basename(tfile))[0]])
    if ks: return ks
    allk = [k for k in FILE_FUNCS.get(tfile, [])]
    return allk if len(allk) == 1 else []
def resolve_call(r, s, call):
    """Một lời gọi -> ([khoá hàm đích], loại 'A'|'B'|'C'|'-', mô tả)."""
    root, meth, direct, two = call; imp = imports_of(r); lang = LANGOF.get(r)
    if root is not None:
        if root in SAMEFILE_ONLY or (root in BLOCK and root in ('this', 'super')):
            if root == 'super': return [], 'A', f'{root}.{meth}'
            return keys_named(r, [meth]), 'C', f'{root}.{meth}'
        if root in BLOCK: return [], 'A', f'{root}.{meth}'                       # Kiểu A: cấm nối
        if two and root in imp:                                           # Kiểu B: qua module đã import
            t, sym, kind = imp[root]
            if kind in ('ns', 'named', 'default', 'cls'): return keys_named(t, [meth]), 'B', f'{root}.{meth}'   # v3.1 (1.1): gồm Class import kiểu named/default (Python: from m import User; User.get_user())
            if kind == 'dir': return [k for f in BYDIR.get(t, []) for k in FILEDEF[f].get(meth.lower(), [])], 'B', f'{root}.{meth}'
            return [], '-', f'{root}.{meth}'
        if lang == 'java':
            ty = TYPES.get(r, {}).get(root) or (root if root[:1].isupper() else None)
            if ty:
                tf = imp.get(ty, (None,))[0] or ([f for f in CLASSDEF.get((s, ty), []) if posixpath.dirname(f) == posixpath.dirname(r)] or CLASSDEF.get((s, ty), [None]))[0]
                if tf: return keys_named(tf, [meth]), 'B', f'{root}:{ty}.{meth}'
        if lang == 'php' and root[:1].isupper():
            return [], '-', f'{root}::{meth}'
        return [], '-', f'{root}.{meth}'
    nm = meth                                                                    # Kiểu C: gọi trực tiếp fn()
    ks = keys_named(r, [nm])
    if ks: return ks, 'C', nm
    if nm in imp:
        t, sym, kind = imp[nm]
        if kind == 'default': return default_fn(t, nm), 'C', nm
        if kind == 'named': return keys_named(t, [sym or nm]), 'C', nm
    for ik, (t, sym, kind) in imp.items():                                       # PHP include: hàm định nghĩa trong tệp được nạp
        if kind == 'inc':
            ks = keys_named(t, [nm])
            if ks: return ks, 'C', nm
    if lang in ('go', 'java', 'php') and len(nm) >= 4 and nm.lower() not in COMMON and nm.lower() not in STOP:
        d = FUNCS.get((s, nm.lower()), [])
        if len(d) == 1: return d, 'C', nm
    return [], '-', nm
def reach(svc, fileh, a, b, depth=2):
    """Hàm handler (tệp, a, b) -> {hàm đích: (chuỗi bằng chứng, số bước)}; ranh giới: lời gọi đã phân giải Kiểu A/B/C."""
    start = [k for k in FILE_FUNCS.get(fileh, []) if k[1] <= a <= k[2] or a <= k[1] <= b]
    start = [k for k in start if k[1] >= a - 2 and k[2] <= b + 2] or [(fileh, a, b)]
    out = {k: ([], 0) for k in start}; fr = list(start)
    for h in range(1, depth + 1):
        nx = []
        for k in fr:
            seen = set()
            for call in CALLS.get(k, ()):
                ks, kind, desc = resolve_call(k[0], svc, call)
                for d in ks:
                    if d == k or d in out or (k, d) in seen: continue
                    seen.add((k, d)); out[d] = (out[k][0] + [f'{k[0]}:{k[1]} gọi {desc}() -> {d[0]}:{d[1]}-{d[2]} [E6_v3 kiểu {kind}]'], h); nx.append(d)
        fr = nx
    return out

# ======================= E1_v3: route, khớp URL có xếp hạng độ đặc hiệu =======================
V21 = True
def pat(r, rx=None):
    if rx: return re.compile(rx)           # regex đã bảo toàn nhóm lookahead/non-capturing (b34_route_juiceshop.py)
    return re.compile('^' + re.sub(r'\\\{[^}]+\\\}', r'[^/]+', re.escape(r)) + ('?$' if r.endswith('/') else '$'))   # như v2.1
URLM = collections.defaultdict(set)
for p in glob.glob(os.path.join(C['quet'], 'nuclei*.jsonl')):
    for ln in open(p, encoding='utf-8'):
        if ln.strip():
            r_ = json.loads(ln); u = re.sub(r'^https?://[^/]+', '', r_.get('matched-at', r_.get('host', ''))).split('?')[0]
            m_ = re.search(r"curl -X '(\w+)'", r_.get('curl-command', '') or ''); URLM[u].add(m_.group(1) if m_ else 'GET')
for p in glob.glob(os.path.join(C['quet'], 'zap*.json')):
    for s_ in json.load(open(p, encoding='utf-8')).get('site', []):
        for a_ in s_.get('alerts', []):
            for i_ in a_.get('instances', []): URLM[re.sub(r'^https?://[^/]+', '', i_.get('uri', '')).split('?')[0]].add(i_.get('method', 'GET'))
def specificity(m, route, regex):
    segs = [s for s in (route or '').strip('/').split('/') if s]
    n_param = sum(1 for s in segs if s.startswith('{') or s.startswith(':') or '*' in s)
    n_static = len(segs) - n_param
    look = bool(regex and '(?' in regex) or n_param == 0
    return (1 if look else 0, n_static, -n_param, len(route or ''))
ENDP = []   # (method, route, svc, pattern, reach, nguồn, đặc_hiệu, tiền_tố)
for r in RM:
    s = r.get('service') if C['multi'] else C['svc']
    s = {'gateway-service': 'gateway-service'}.get(s, s)
    if r['method'] == 'ALL': pt = re.compile(r['regex']) if r.get('regex') else re.compile('^' + re.sub(r'\\\{[^}]+\\\}', r'[^/]+', re.escape(r['route'].rstrip('/'))) + '(/.*)?$')
    else: pt = pat(r['route'], r.get('regex'))
    ENDP.append((r['method'], r['route'], s, pt, reach(s, r['file'], r['line_start'], r['line_end']), f"{r['file']}:{r['line_start']}-{r['line_end']}", specificity(r['method'], r['route'], r.get('regex')), r))
# --- Hub: hàm con được gọi (qua E6_v3, số bước >= 1) bởi > 3 endpoint khác nhau ---
CALLERS = collections.defaultdict(set)
for (m, rt, s, _, fx, src, _, _) in ENDP:
    for k, (chain, hop) in fx.items():
        if hop >= 1: CALLERS[k].add((m, rt))
HUB = {k for k, v in CALLERS.items() if len(v) > 3}
EPSVC = {}
for (m, rt, s, *_r) in ENDP: EPSVC.setdefault((m, rt), s)

# ======================= gắn phát hiện vào nút =======================
def endpoints_of_code(f):
    """-> [(ep, chuỗi bằng chứng, số bước, khoá hàm chứa cảnh báo, các khoá trung gian)]"""
    p = rel(f['anchors']['file_path']); ln = f['anchors']['line_start']
    if not p or not ln: return []
    out = []
    for (m, rt, s, _, fx, src, _, _rr) in ENDP:
        best = None
        for (fp, a, b), (chain, hop) in fx.items():
            if (p == fp or p.endswith('/' + fp) or fp.endswith('/' + p)) and a <= ln <= b:
                cand = (hop, b - a, (fp, a, b), chain)
                if best is None or cand[:2] < best[:2]: best = cand
        cc = re.match(r'(.+?):(\d+)\s*$', rr_.get('can_cu') or '') if (rr_ := _rr) else None   # v3.1 (1.2)
        if not best and cc and (p == cc.group(1) or p.endswith('/' + cc.group(1))) and abs(ln - int(cc.group(2))) <= CANCU_TOL:   # phiếu 34B: ±2; biến thể 3.1b: B34_CANCU_TOL=0 (đúng dòng)
            out.append(((m, rt), [f'E1 route_map (đăng ký route): {m} {rt} tại {rr_["can_cu"]}'], 0, (cc.group(1), int(cc.group(2)), int(cc.group(2))), [])); continue
        if best:
            hop, _, key, chain = best
            mids = [k for k, (c2, h2) in fx.items() if 0 < h2 < hop and chain[:len(c2)] == c2]   # hàm trung gian trên đường đi
            out.append(((m, rt), [f'E1 route_map: {m} {rt} -> {src}'] + [f'E6 {c}' for c in chain], hop, key, mids))
    return out
def endpoints_of_test(f):
    u = f['anchors']['url_route']
    if not u: return []
    cand = [(m, rt, s, sp, rr) for (m, rt, s, pt, _, _, sp, rr) in ENDP if pt.match(u) and (not URLM.get(u) or m in URLM[u] or m == 'ALL')]
    if C['multi']:   # Django khớp theo thứ tự đầu tiên trong dịch vụ workshop (giữ nguyên v2.1)
        firsts = {}
        for (m, rt, s, sp, rr) in cand:
            if s == 'workshop': firsts.setdefault(m, rt)
        cand = [x for x in cand if not (x[2] == 'workshop' and x[1] != firsts.get(x[0], x[1]))]
    # xếp hạng độ đặc hiệu: theo từng phương thức giữ route đặc hiệu nhất; ALL (app.use, khớp tiền tố) giữ nhóm có tiền tố dài nhất
    best = {}
    for (m, rt, s, sp, rr) in cand:
        if m == 'ALL': continue
        best.setdefault((m, s), []).append((sp, rt))
    out = []
    for (m, s), L in best.items():
        top = max(sp for sp, _ in L)
        for sp, rt in L:
            if sp == top: out.append(((m, rt), [f'E1_v3 route_map: URL {u} khớp {m} {rt} (độ đặc hiệu {top})']))
    alls = [(len([x for x in rt.strip('/').split('/') if x]), rt) for (m, rt, s, sp, rr) in cand if m == 'ALL']
    if alls:
        mx = max(n for n, _ in alls)
        for n, rt in alls:
            if n == mx: out.append((('ALL', rt), [f'E1_v3 route_map: URL {u} khớp tiền tố ALL {rt}']))
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

# ======================= E2: tệp repo -> tệp trong image (giữ nguyên v2.1) =======================
def stages(svc):
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
            st[-1][1].append((pp[:-1], dest_abs, dest.endswith('/') or dest in ('.', './') or len(pp) > 2, fr, f'{os.path.relpath(df, REPO)}:{i} {k} {v}'))
    return st, d
def paths_in(st, idx, r, depth=0):
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
def dockerignored(svc, repo_file):
    st, ctx = stages(svc)
    r = os.path.relpath(os.path.join(REPO, repo_file), ctx)
    di = os.path.join(ctx, '.dockerignore')
    if os.path.exists(di):
        for pt in (x.strip() for x in open(di, encoding='utf-8', errors='ignore')):
            if not pt or pt.startswith('#') or pt.startswith('!'): continue
            p0 = pt[3:] if pt.startswith('**/') else pt.lstrip('/')
            if fnmatch.fnmatch(r, p0) or fnmatch.fnmatch(os.path.basename(r), p0) or r.startswith(p0.rstrip('/') + '/'): return pt
    return None
def image_path(svc, repo_file):
    st, ctx = stages(svc)
    if not st: return []
    r = os.path.relpath(os.path.join(REPO, repo_file), ctx)
    if r.startswith('..') or dockerignored(svc, repo_file): return []
    return [(q.lstrip('/'), ' => '.join(ev)) for q, ev in paths_in(st, len(st) - 1, r)]
def dockle_paths(f):
    p = f['anchors']['container_target']
    try: d = json.load(open(p if os.path.isabs(p) else os.path.join(B, p), encoding='utf-8'))
    except Exception:
        try: d = json.load(open(os.path.join(C['quet'], os.path.basename(p)), encoding='utf-8'))
        except Exception: return []
    out = []
    for x in d.get('details', []):
        if x.get('code') == f['raw_rule_id']:
            for a in x.get('alerts', []):
                m = re.search(r'Suspicious filename found : (\S+)', a)
                if m: out.append(m.group(1).lstrip('/'))
    return out

# ======================= vết V1 (có lọc), V1_intra, V2–V4 =======================
E = []; V1_LOAI = []; CHINH = []
EFF = {}   # v3.1 (1.3): (finding_id, endpoint) -> họ hiệu dụng kế thừa từ handler
def nhan(a, b, ep=None):
    fa = EFF.get((a['finding_id'], ep), a['family'])
    if fa != a['family'] and a['raw_cwe'] == ['CWE-843'] and b['raw_rule_id'] == '90022': return 'cung_loi'   # lỗi 500 do kiểm tra kiểu ở hàm chuyên biệt (phiếu 34B 1.3)
    if fa == 'khac' or b['family'] == 'khac': return 'chua_ro_ho'
    return 'cung_loi' if fa == b['family'] else 'cung_tai_san'
def vet(a, b, kind, ev, lab=None, **kw):
    e = {'a': a['finding_id'], 'b': b['finding_id'], 'luat': kind, 'nhan': lab or nhan(a, b), 'bang_chung': ev}; e.update(kw); E.append(e); return e
code = [f for f in F if f['phase'] == 'CODE' and f['nut'].get('endpoint')]
test = [f for f in F if f['phase'] == 'TEST' and f['nut'].get('endpoint')]
TE = collections.defaultdict(list)
for t in test:
    for (ep, ev) in t['nut']['endpoint']: TE[ep].append((t, ev))
_byep0 = collections.defaultdict(list)
for _a in code:
    for (_ep, _ev, _hop, _key, _mids) in _a['nut']['endpoint']: _byep0[_ep].append((_a, _hop, _key, _mids))
for _ep, _L in _byep0.items():
    _fam0 = {x[0]['family'] for x in _L if x[1] == 0 and x[0]['family'] != 'khac'}
    if len(_fam0) != 1: continue
    for (_a, _hop, _key, _mids) in _L:
        if _a['family'] in ('khac', 'validation') and _hop == 1 and _key not in HUB and len(CALLERS.get(_key, ())) == 1 and not any(k in HUB for k in _mids):
            EFF[(_a['finding_id'], _ep)] = next(iter(_fam0))
for _a in code:
    _v = {EFF[(_a['finding_id'], _ep)] for (_ep, *_x) in _a['nut']['endpoint'] if (_a['finding_id'], _ep) in EFF}
    if len(_v) == 1: _a['family_hieu_dung'] = next(iter(_v))
def danh_gia_v1(a, b, lab, hop, key, mids):
    """Lọc cạnh V1 (cải tiến 3). Trả (giữ?, qua_hub?, lý do)."""
    hub_fn = key in HUB; indeg = len(CALLERS.get(key, ())) if hop >= 1 else 1
    if any(k in HUB for k in mids): return False, True, 'đường đi qua hàm Hub trung gian'
    if lab == 'cung_loi':
        if hub_fn and hop != 1: return False, True, f'cảnh báo ở hàm Hub ({indeg} endpoint gọi) cách handler {hop} bước'
        return True, hub_fn, ('hàm Hub gọi trực tiếp từ handler, cùng họ lỗ hổng' if hub_fn else 'đường E1+E6_v3 hợp lệ')
    if b['sev'] not in ('High', 'Medium', 'Critical'): return False, False, f'v3.1 (1.4): không cùng họ lỗi và cảnh báo TEST mức {b["sev"]} (thông tin bề mặt)'
    if hop == 0: return True, False, 'cảnh báo nằm ngay trong hàm handler'
    if hub_fn: return False, True, f'cảnh báo ở hàm Hub ({indeg} endpoint)'
    if indeg <= 2: return True, False, f'hàm chuyên biệt của route (in_degree_route={indeg})'
    return False, False, f'hàm dùng chung ({indeg} endpoint), nhãn {lab}'
for a in code:
    seen = set()
    for (ep, ev, hop, key, mids) in a['nut']['endpoint']:
        for (b, ev2) in TE.get(ep, []):
            if b['finding_id'] in seen: continue
            seen.add(b['finding_id']); lab = nhan(a, b, ep)
            ok, qh, why = danh_gia_v1(a, b, lab, hop, key, mids)
            if ok:
                e = vet(a, b, 'V1', ev + ev2, lab, qua_hub=qh, hop=hop, ly_do_giu=why, svc_code=a['nut'].get('svc'), svc_ep=EPSVC.get(ep)); CHINH.append(e)
            else: V1_LOAI.append({'a': a['finding_id'], 'b': b['finding_id'], 'nhan': lab, 'hop': hop, 'ly_do_loai': why, 'bang_chung': ev + ev2})
# V1_intra: CODE <-> CODE cùng họ fam2 trên cùng endpoint, một đầu ở handler (hop 0), đầu kia ở hàm con gọi qua E6_v3 (không Hub trung gian)
byep = collections.defaultdict(list)
for a in code:
    for (ep, ev, hop, key, mids) in a['nut']['endpoint']: byep[ep].append((a, hop, key, mids, ev))
seen_intra = set()
for ep, L in byep.items():
    for (a, ha, ka, ma, eva) in L:
        if ha != 0 or a['family'] == 'khac': continue
        for (b, hb, kb, mb, evb) in L:
            if hb < 1 or EFF.get((b['finding_id'], ep), b['family']) != a['family'] or a['finding_id'] == b['finding_id']: continue
            if any(k in HUB for k in mb) or (kb in HUB and hb != 1): continue
            pk = tuple(sorted((a['finding_id'], b['finding_id'])))
            if pk in seen_intra: continue
            seen_intra.add(pk); vet(a, b, 'V1_intra', [f'E1 {ep[0]} {ep[1]}: cảnh báo {a["finding_id"]} ở handler'] + evb[1:], 'cung_loi', qua_hub=(kb in HUB), hop=hb)
# V2 bí mật (giữ nguyên v2.1)
gl = [f for f in F if f['tool'] == 'gitleaks']; dk = [f for f in F if f['tool'] == 'dockle' and f['raw_rule_id'] == 'CIS-DI-0010']
DKP = {f['finding_id']: dockle_paths(f) for f in dk}
for a in gl:
    p = rel(a['anchors']['file_path']); s = svc_of_path(p)
    if not s: continue
    for (q, ev) in image_path(s, p):
        for b in dk:
            if b['nut'].get('svc') == s and any(x == q or x.endswith('/' + q) or q.endswith('/' + x) for x in DKP[b['finding_id']]):
                vet(a, b, 'V2', [f'E5 {p} thuộc dịch vụ {s}', f'E2 {ev} => {q}', f'dockle {os.path.basename(b["anchors"]["container_target"])} liệt kê {q}'], 'cung_loi')
    for b in [f for f in F if f['phase'] == 'TEST' and f['anchors'].get('sens_file')]:
        if os.path.basename(p).lower() == str(b['anchors']['sens_file']).lower() and image_path(s, p):
            vet(a, b, 'V2', [f'E2 {p} được COPY vào image dịch vụ {s}', f'URL {b["anchors"]["url_route"]} trả tệp cùng tên'], 'cung_loi')
def svc_of_url(u):
    if not C['multi']: return C['svc']
    seg = (u or '').strip('/').split('/')[0]
    return seg if seg in ('identity', 'community', 'workshop', 'chatbot') else 'web'
for b in [f for f in F if f['phase'] == 'TEST' and f['anchors'].get('sens_file')]:
    for a in dk:
        if a['nut'].get('svc') == svc_of_url(b['anchors']['url_route']) and any(os.path.basename(x).lower() == str(b['anchors']['sens_file']).lower() for x in DKP[a['finding_id']]):
            vet(a, b, 'V2', [f'dockle image dịch vụ {a["nut"]["svc"]} chứa ' + ', '.join(x for x in DKP[a['finding_id']] if os.path.basename(x).lower() == str(b['anchors']['sens_file']).lower()),
                             f'URL {b["anchors"]["url_route"]} thuộc dịch vụ {svc_of_url(b["anchors"]["url_route"])} (nginx location)'], 'cung_loi')
LAN = []
for a in gl:
    p = rel(a['anchors']['file_path']); s = svc_of_path(p)
    if s:
        for (q, ev) in image_path(s, p):
            ct = [c for c, v in CONT.items() if v == s]
            a.setdefault('lan_truyen', []).append({'image_path': q, 'bang_chung': ev, 'container': ct}); LAN.append((a['finding_id'], p, q, ev, ct))
# V3 gói (giữ nguyên v2.1)
bd = [f for f in F if f['phase'] == 'BUILD']; rl = [f for f in F if f['tool'] == 'grype' and f['anchors']['container_target'] == 'image']
IDX = collections.defaultdict(list)
for b in rl: IDX[(b['anchors']['cve_id'], b['anchors']['package_name'], b['nut'].get('svc'))].append(b)
for a in bd:
    s = a['nut'].get('svc')
    for b in IDX.get((a['anchors']['cve_id'], a['anchors']['package_name'], s), []):
        vet(a, b, 'V3', [f'E5 {rel(a["anchors"]["file_path"])} thuộc dịch vụ {s}', f'E4 image dịch vụ {s}', f'cùng {a["anchors"]["package_name"]} / {a["anchors"]["cve_id"]}'], 'cung_loi')
# V4 cấu hình: CIS_MAP mở rộng — 5 lớp cũ giữ nguyên + add_instead_of_copy, latest_tag, no_new_privileges (kics <-> dockle <-> docker bench)
CIS_MAP = {   # lớp: (regex kics, mã dockle, regex docker_bench)
    'no_new_privileges': (r'security opt not set|no-new-privileges', None, r'acquiring additional privileges'),
    'add_instead_of_copy': (r'add instead of copy|using add', 'CIS-DI-0009', r'(?!x)x'),
    'latest_tag': (r"image version using 'latest'|image tag not explicit|latest", 'DKL-DI-0006', r'(?!x)x'),
    'run_as_root': (r'user|root', 'CIS-DI-0001', r'user'),
    'mem_limit': (r'memory|cpu|resource', None, r'memory usage'),
    'rw_rootfs': (r'read.?only|writable', None, r'root filesystem'),
    'privileged': (r'privileged container|privileged mode|no-new-privileges|escalation|security_opt', None, r'privileged containers'),
    'healthcheck': (r'health', 'CIS-DI-0006', r'health'),
}
def l4class(f):
    t = str(f['anchors']['cis_control_class'] or '')
    for k, (rx, dk_, db) in CIS_MAP.items():
        if f['tool'] == 'dockle' and dk_ and t == dk_: return k
        if f['tool'] == 'docker_bench' and re.search(db, t, re.I): return k
        if f['tool'] == 'kics' and k not in ('latest_tag',) and re.search(rx, t, re.I): return k
        if f['tool'] == 'kics' and k == 'latest_tag' and re.search(r"image version using 'latest'|image tag not explicit", t, re.I): return k
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
for e in R['canh']:
    if e['luat'] == 'L0': E.append(dict(e, nhan='cung_loi', bang_chung=['L0 v1.4']))

# ======================= gom cụm phân cấp 2 bước =======================
P = {f['finding_id']: f['finding_id'] for f in F}
def fd(x):
    while P[x] != x: P[x] = P[P[x]]; x = P[x]
    return x
# Bước A — hạt nhân: Union-Find CHỈ trên cạnh cung_loi, bỏ cạnh qua hàm Hub
for e in E:
    if e['nhan'] == 'cung_loi' and not e.get('qua_hub'): P[fd(e['a'])] = fd(e['b'])
CORE = {f['finding_id']: fd(f['finding_id']) for f in F}
CORE_SIZE = collections.Counter(CORE.values())
# Bước B — vệ tinh: cạnh còn lại (chua_ro_ho / cung_tai_san / qua hàm Hub) đính kèm bằng chứng; KHÔNG bắc cầu giữa 2 hạt nhân
VT = collections.defaultdict(set); VT_EDGES = []
for e in E:
    if e['nhan'] != 'cung_loi' or e.get('qua_hub'):
        VT[e['a']].add(e['b']); VT[e['b']].add(e['a']); VT_EDGES.append(e)
ATTACH = {}; AMBIG = []
for s, nb in VT.items():
    if CORE_SIZE[CORE[s]] > 1: continue                     # đã thuộc hạt nhân nhiều phần tử: chỉ ghi bằng chứng, không gộp
    cores = {CORE[x] for x in nb if CORE[x] != CORE[s]}
    # ứng viên hạt nhân: chỉ hạt nhân chứa cảnh báo pha khác hoặc nhiều phần tử, hoặc CODE
    cores = {c for c in cores}
    if len(cores) == 1: ATTACH[s] = next(iter(cores))
    elif len(cores) > 1: AMBIG.append((s, sorted(cores)))
CL = collections.defaultdict(list)
for f in F:
    c = ATTACH.get(f['finding_id'], CORE[f['finding_id']]); CL[c].append(f)
for k, fs in CL.items():
    ph = {f['phase'] for f in fs}; tl = {f['tool'] for f in fs}; t = 1 if len(ph) >= 2 else 2 if len(tl) >= 2 else 3
    for f in fs: f['tier'] = t; f['cum'] = k; f['vai_tro_cum'] = 've_tinh' if f['finding_id'] in ATTACH else 'hat_nhan'
    for f in fs: f['routes'] = sorted({ep[1] for ep, *_ in f['nut'].get('endpoint', [])}) or f.get('routes', [])

# ======================= độ phơi nhiễm tĩnh M1–M4 và gợi ý làm sạch =======================
AUTH_RX = re.compile(r'isAuthorized|authorize\(|requireAuth|login_required|jwt_required|token_required|ensureLoggedIn|isLoggedIn|authenticate\(|passport\.authenticate|@PreAuthorize|@Secured|isAuthenticated|verify\.|security\.(?:is|append|deny)|auth_required|permission_classes|IsAuthenticated|before_request|requireLogin|sessionChecker', re.I)
def reg_text(r_):
    """Văn bản đăng ký route: dòng can_cu, 3 dòng trên handler (decorator), và middleware-only app.use/app.<m> trong tệp đăng ký có tiền tố trùng route."""
    txt = ''
    cc = r_.get('can_cu') or ''
    m = re.match(r'(.+?):(\d+)', cc)
    ls = None
    if m and m.group(1) in SRC_ALL: ls = SRC_ALL[m.group(1)].split('\n'); i0 = int(m.group(2)) - 1; txt += ' '.join(ls[max(0, i0 - 1):i0 + 4])
    hf = r_['file']
    if hf in SRC_ALL: L = SRC_ALL[hf].split('\n'); i0 = r_['line_start'] - 1; txt += ' ' + ' '.join(L[max(0, i0 - 3):i0 + 1])
    return txt
SRC_ALL = {}
def src_of(r_):
    if r_ not in SRC_ALL:
        try: SRC_ALL[r_] = open(os.path.join(REPO, r_), encoding='utf-8', errors='ignore').read()
        except Exception: SRC_ALL[r_] = ''
    return SRC_ALL[r_]
for (m, rt, s, _, fx, src, _, rr) in ENDP:
    src_of(rr['file']); mm = re.match(r'(.+?):\d+', rr.get('can_cu') or '')
    if mm: src_of(mm.group(1))
MW = []   # middleware-only (app.use('/prefix', auth)) trong các tệp đăng ký route
for fn_ in {re.match(r'(.+?):\d+', rr.get('can_cu') or '').group(1) for *_, rr in ENDP if re.match(r'(.+?):\d+', rr.get('can_cu') or '')}:
    for ln in src_of(fn_).split('\n'):
        m = re.match(r"\s*app\.(?:use|get|post|put|delete|all)\(\s*'([^']+)'\s*,\s*(.*)\)\s*;?\s*$", ln)
        if m and AUTH_RX.search(m.group(2)) and m.group(2).count('(') <= 2: MW.append((m.group(1), ln.strip()))
def ep_auth(m, rt, rr):
    if AUTH_RX.search(reg_text(rr)): return True
    for pre, ln in MW:
        pp = re.sub(r':\w+', '{}', pre.split('(')[0]).rstrip('/'); r2 = re.sub(r'\{[^}]+\}', '{}', rt).rstrip('/')
        if pp and (r2 == pp or r2.startswith(pp + '/')): return True
    return False
EPAUTH = {(m, rt): ep_auth(m, rt, rr) for (m, rt, s, _, fx, src, _, rr) in ENDP}
SAN = {   # họ lỗi -> mẫu hàm làm sạch (gọi hàm, quét bằng AST)
    'path': r'(?:path\.)?basename|path\.normalize|sanitize[-_]?filename|secure_filename|escapeshellarg',
    'sqli': r'parseInt|parseFloat|Number|\.escape|mysql\.escape|mysqli_real_escape_string|intval|int|escape_string',
    'xss': r'(?:validator\.)?escape(?:Html)?|encodeURIComponent|sanitizeHtml|DOMPurify\.sanitize|htmlspecialchars|html\.escape|bleach\.clean',
    'cmd': r'shellescape|shlex\.quote|escapeshellarg|escapeshellcmd',
    'ssrf': r'new URL|isAllowedHost|isRedirectAllowed',
    'redirect': r'isRedirectAllowed|isSafeUrl|url_has_allowed_host_and_scheme',
}
def sanitizer_hint(f):
    """Cảnh báo CODE: có lời gọi hàm làm sạch (theo họ lỗi) trong dòng/biểu thức chứa cảnh báo không? Quét AST bằng tree-sitter."""
    fam = f['family']; a = f['anchors']; r_ = rel(a['file_path'])
    if fam not in SAN or not r_ or r_ not in SRC: return None
    ls, le = a['line_start'], a['line_end'] or a['line_start']; src = SRC[r_]; rx = re.compile(r'^(?:' + SAN[fam] + r')$')
    tr = parser(LANGOF[r_]).parse(src); st = [tr.root_node]; hits = []
    while st:
        n = st.pop(); st.extend(n.children)
        if n.type in CALL_T and n.start_point[0] + 1 <= le and n.end_point[0] + 1 >= ls:
            sh = call_shape(n, src)
            if sh:
                root, meth, _, _ = sh; full = (root + '.' if root else '') + meth
                if rx.match(full) or rx.match(meth): hits.append((full, n.start_point[0] + 1))
    return hits[0] if hits else None
for f in F:
    if f['phase'] != 'CODE': continue
    a = f['anchors']; r_ = rel(a['file_path']); eps = f['nut'].get('endpoint', [])
    dead = dead_reason(r_ or '') if r_ else None; svc = f['nut'].get('svc')
    if not dead and r_ and svc:
        di = dockerignored(svc, r_) if stages(svc)[0] else None
        if di: dead = f'.dockerignore loại ({di})'
        elif LANGOF.get(r_) in ('javascript', 'typescript', 'python', 'php') and stages(svc)[0] and not image_path(svc, r_) and r_ in ALLFILES: dead = 'không được COPY vào image cuối (Dockerfile)'
    if dead: f['muc_phoi_nhiem_tinh'] = 'M4_UNPACKAGED_DEAD'; f['ly_do_muc'] = dead
    elif eps:
        pub = [ep for (ep, ev, hop, key, mids) in eps if not EPAUTH.get(ep)]
        f['muc_phoi_nhiem_tinh'] = 'M1_PUBLIC_ENDPOINT' if pub else 'M2_AUTH_ENDPOINT'
        f['ly_do_muc'] = f'nối ra endpoint {pub[0][0]} {pub[0][1]} không qua middleware xác thực' if pub else f'mọi endpoint nối tới ({len(eps)}) đều có middleware xác thực'
    else: f['muc_phoi_nhiem_tinh'] = 'M3_PACKAGED_IMAGE'; f['ly_do_muc'] = 'không nối tới endpoint HTTP; tệp thuộc dịch vụ / image cuối'
    sh = sanitizer_hint(f); f['da_lam_sach'] = bool(sh)
    if sh: f['sanitizer_hint'] = {'ham': sh[0], 'dong': sh[1]}

cnt = collections.Counter((e['luat'], e['nhan']) for e in E)
res = {'phien_ban': '3.1' + ('' if CANCU_TOL == 2 else 'b'), 'app': APP, 'tong_phat_hien': len(F), 'theo_cong_cu': R['theo_cong_cu'],
       'so_canh': {r: sum(1 for e in E if e['luat'] == r) for r in ('L0', 'V1', 'V1_intra', 'V2', 'V3', 'V4', 'L1', 'L2', 'L3', 'L4')},
       'canh_theo_nhan': {f'{a}|{b}': v for (a, b), v in sorted(cnt.items())}, 'so_cum': len(CL), 'tier_theo_phat_hien': dict(collections.Counter(f['tier'] for f in F)),
       'lan_truyen_bi_mat': LAN, 'so_endpoint': len(ENDP), 'so_ham_dich_trung_binh': round(sum(len(x[4]) for x in ENDP) / max(1, len(ENDP)), 2), 'container_dich_vu': CONT, 'khoi_compose': COMPOSE_BLOCKS,
       'ham_hub': sorted([f'{k[0]}:{k[1]}-{k[2]} ({len(v)} endpoint)' for k, v in CALLERS.items() if k in HUB]), 'so_canh_v1_loai': len(V1_LOAI),
       'muc_phoi_nhiem_tinh': dict(collections.Counter(f.get('muc_phoi_nhiem_tinh') for f in F if f['phase'] == 'CODE')),
       'da_lam_sach': [f['finding_id'] for f in F if f.get('da_lam_sach')], 've_tinh_mo_ho': AMBIG,
       'cum': [{'id': k, 'tier': fs[0]['tier'], 'pha': sorted({f['phase'] for f in fs}), 'cong_cu': sorted({f['tool'] for f in fs}), 'so_phat_hien': len(fs)} for k, fs in CL.items() if len(fs) > 1],
       'ds_lien_ket_chinh': [{'a': e['a'], 'b': e['b'], 'nhan': e['nhan'], 'hop': e['hop'], 'qua_hub': e['qua_hub'], 'ly_do_giu': e['ly_do_giu'], 'svc_code': e['svc_code'], 'svc_ep': e['svc_ep']} for e in CHINH], 'canh_loai_v1': V1_LOAI,
       'phat_hien': F, 'canh': E}
_p = OUTFILE or f'{OUT}/v3_{APP}.json'; os.makedirs(os.path.dirname(os.path.abspath(_p)), exist_ok=True); json.dump(res, open(_p, 'w', encoding='utf-8'), ensure_ascii=False, indent=0, default=list)
print(json.dumps({k: res[k] for k in ('app', 'so_canh', 'canh_theo_nhan', 'so_cum', 'tier_theo_phat_hien', 'so_endpoint', 'so_ham_dich_trung_binh', 'so_canh_v1_loai', 'muc_phoi_nhiem_tinh', 'da_lam_sach')}, ensure_ascii=False))
print('hub:', res['ham_hub'][:10])
