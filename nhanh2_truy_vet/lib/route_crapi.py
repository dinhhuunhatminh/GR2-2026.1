"""Trích bản đồ route kiểu crAPI (MCP nhánh 2, khung='crapi'; gốc: b30_route_crapi.py, bước 30) (cạnh E1): endpoint (method, route) -> hàm xử lý (tệp, dòng đầu, dòng cuối).
Nguồn: Spring (@*Mapping, identity), Django (urls.py + class-based views, workshop), gorilla/mux + net/http (community, gateway), Flask blueprint (chatbot).
Không dùng đáp án. Đường dẫn tệp tương đối gốc repo (services/...)."""
import os, re, sys, json
def _relp(*a): return os.path.relpath(*a).replace('\\', '/')   # v1.6: Windows -> dấu '/'
from tree_sitter_language_pack import get_parser
R = sys.argv[1]; OUT = sys.argv[2]
S = os.path.join(R, 'services')
routes = []
def add(svc, m, rt, f, a, b, src, regex=None):
    routes.append({'service': svc, 'method': m.upper(), 'route': rt, 'file': _relp(f, R), 'line_start': a, 'line_end': b, 'nguon': src, **({'regex': regex} if regex else {})})
def tx(n, src): return src[n.start_byte:n.end_byte].decode('utf-8', 'replace')
def walk(n):
    yield n
    for c in n.children: yield from walk(c)

# ---- Spring (identity) ----
JP = get_parser('java')
MAP = {'GetMapping': 'GET', 'PostMapping': 'POST', 'PutMapping': 'PUT', 'DeleteMapping': 'DELETE', 'PatchMapping': 'PATCH', 'RequestMapping': None}
def ann_paths(a, src):
    t = tx(a, src); return re.findall(r'"([^"]*)"', t.split('method')[0]) or ['']
def ann_methods(a, src):
    return re.findall(r'RequestMethod\.(\w+)', tx(a, src))
for dp, _, fs in os.walk(os.path.join(S, 'identity')):
    for fn in fs:
        if not fn.endswith('.java'): continue
        p = os.path.join(dp, fn); src = open(p, 'rb').read()
        if b'Mapping' not in src: continue
        tr = JP.parse(src)
        for cls in (n for n in walk(tr.root_node) if n.type == 'class_declaration'):
            pre = ['']
            mods = next((c for c in cls.children if c.type == 'modifiers'), None)
            if mods:
                for a in mods.children:
                    if a.type in ('annotation', 'marker_annotation') and tx(a, src).startswith('@RequestMapping'): pre = ann_paths(a, src)
            body = next((c for c in cls.children if c.type == 'class_body'), None)
            for md in (c for c in (body.children if body else []) if c.type == 'method_declaration'):
                mm = next((c for c in md.children if c.type == 'modifiers'), None)
                for a in (mm.children if mm else []):
                    if a.type not in ('annotation', 'marker_annotation'): continue
                    nm = tx(a, src)[1:].split('(')[0]
                    if nm not in MAP: continue
                    ms = [MAP[nm]] if MAP[nm] else (ann_methods(a, src) or ['GET'])
                    for pp in pre:
                        for sp in ann_paths(a, src):
                            for m in ms: add('identity', m, '/' + (pp.strip('/') + '/' + sp.strip('/')).strip('/'), p, md.start_point[0] + 1, md.end_point[0] + 1, 'spring')

# ---- Django (workshop) ----
PP = get_parser('python')
def py_classes(p):
    src = open(p, 'rb').read(); tr = PP.parse(src); out = {}
    for n in walk(tr.root_node):
        if n.type == 'class_definition':
            name = tx(n.child_by_field_name('name'), src); meths = {}
            for c in walk(n.child_by_field_name('body')):
                if c.type == 'function_definition':
                    mn = tx(c.child_by_field_name('name'), src)
                    if mn in ('get', 'post', 'put', 'delete', 'patch'): meths[mn] = (c.start_point[0] + 1, c.end_point[0] + 1)
            out[name] = (meths, n.start_point[0] + 1, n.end_point[0] + 1)
    return out
WK = os.path.join(S, 'workshop')
def mod_path(mod): return os.path.join(WK, *mod.split('.')) + '.py'
def rx2route(r):
    r = r.strip().lstrip('^').rstrip('$')
    r = re.sub(r'\(\?P<(\w+)>[^)]*\)', r'{\1}', r); return r
def django(mod, prefix, rxp=''):
    p = mod_path(mod)
    if not os.path.exists(p): return  # gói ngoài (health_check)
    src = open(p, encoding='utf-8').read()
    imports = dict(re.findall(r'import\s+([\w.]+)\s+as\s+(\w+)', src)); imports = {v: k for k, v in imports.items()}
    for m in re.finditer(r'(?:re_)?path\(\s*r?"([^"]*)"\s*,\s*(include\("([^"]+)"\)|([\w.]+)\.as_view\(\))', src, re.S):
        pat, inc = m.group(1), m.group(3)
        if inc: django(inc, prefix + pat, rxp + (pat if m.group(0).lstrip().startswith('re_') else re.escape(pat))); continue
        view = m.group(4); al, cls = view.rsplit('.', 1)
        vmod = imports.get(al, al); C = py_classes(mod_path(vmod)).get(cls)
        if not C: continue
        rt = '/' + (prefix + rx2route(pat)).strip('/')
        full = '^/' + rxp + (pat.lstrip('^').rstrip('$') if m.group(0).lstrip().startswith('re_') else re.escape(pat)) + '$'   # v2.1: giữ ràng buộc regex Django (vd \\d+), so khớp theo thứ tự urlpatterns
        for meth, (a, b) in C[0].items(): add('workshop', meth, rt, mod_path(vmod), a, b, 'django', full)
django('crapi_site.urls', '')

# ---- Go (community gorilla/mux, gateway net/http) ----
GP = get_parser('go')
def go_funcs(root):
    out = {}
    for dp, _, fs in os.walk(root):
        for fn in fs:
            if fn.endswith('.go') and not fn.endswith('_test.go'):
                p = os.path.join(dp, fn); src = open(p, 'rb').read()
                for n in walk(GP.parse(src).root_node):
                    if n.type in ('function_declaration', 'method_declaration'):
                        out.setdefault(tx(n.child_by_field_name('name'), src), []).append((p, n.start_point[0] + 1, n.end_point[0] + 1))
    return out
for svc in ('community', 'gateway-service'):
    root = os.path.join(S, svc); FN = go_funcs(root)
    for dp, _, fs in os.walk(root):
        for fn in fs:
            if not fn.endswith('.go'): continue
            p = os.path.join(dp, fn); src = open(p, encoding='utf-8').read()
            for m in re.finditer(r'HandleFunc\(\s*"([^"]+)"\s*,(.*?)\)\s*(?:\.Methods\(([^)]*)\))?\s*$', src, re.M):
                path, body, meths = m.group(1), m.group(2), m.group(3)
                cands = re.findall(r'(?:controller\.)?([A-Z]\w+)', body)
                hn = next((c for c in reversed(cands) if c in FN and not c.startswith('SetMiddleware')), None)
                if not hn: continue
                ms = [x for x in re.findall(r'"(\w+)"', meths or '"GET"') if x != 'OPTIONS'] or ['GET']
                for (fp, a, b) in FN[hn][:1]:
                    for mm in ms: add(svc, mm, path, fp, a, b, 'go')

# ---- Flask (chatbot) ----
CB = os.path.join(S, 'chatbot', 'src', 'chatbot')
pref = {'chat_bp': '/chatbot/genai', 'root_bp': '/chatbot'}  # từ Blueprint(url_prefix) + register_blueprint lồng (app.py:20-22)
for fn in os.listdir(CB):
    if not fn.endswith('.py'): continue
    p = os.path.join(CB, fn); src = open(p, 'rb').read()
    for n in walk(PP.parse(src).root_node):
        if n.type == 'decorated_definition':
            for d in (c for c in n.children if c.type == 'decorator'):
                m = re.match(r'@(\w+)\.route\(\s*"([^"]*)"(?:.*methods=\[([^\]]*)\])?', tx(d, src), re.S)
                if m and m.group(1) in pref:
                    for mm in re.findall(r'"(\w+)"', m.group(3) or '"GET"'):
                        add('chatbot', mm, (pref[m.group(1)] + m.group(2)).rstrip('/') or '/', p, n.start_point[0] + 1, n.end_point[0] + 1, 'flask')
json.dump(routes, open(OUT, 'w'), indent=0, ensure_ascii=False)
from collections import Counter
print(json.dumps({'so_route': len(routes), 'theo_dich_vu': Counter(r['service'] for r in routes)}, ensure_ascii=False))
