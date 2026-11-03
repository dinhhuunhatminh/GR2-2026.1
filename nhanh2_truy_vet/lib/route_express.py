"""Trích bản đồ route Express (MCP nhánh 2, khung='express'); gốc: b31_route_juiceshop.py (bước 31). Từ tệp vào (server.ts/app.js...): app.<method>(đường dẫn, ...handler) -> hàm handler (tệp, dòng).
Handler = định danh được gọi trong danh sách đối số, phân giải qua import của server.ts sang routes/*.ts hoặc lib/*.ts.
Bỏ middleware dùng chung: security.*, verify.*, metrics.*, antiCheat.* (kiểm quyền / phát hiện thử thách / đo đạc), và hàm của thư viện ngoài.
app.use(...) -> phương thức 'ALL'. Route tự sinh của finale (/api/<Model>) không có mã handler trong repo -> không đưa vào.
Không dùng đáp án.
v1.7 (29/10/2026, hậu nghiệm – phát hiện ở demo bài 4: app AI viết cho 0 route): THÊM nhánh dự phòng bằng cây cú pháp cho lời gọi app.<method>
mà cách cũ không phân giải được: handler viết ngay trong lời gọi (arrow/function) hoặc là hàm/biến cục bộ cùng tệp, hoặc require('./x').
Cách cũ giữ nguyên, chạy trước; nhánh mới chỉ dùng khi cách cũ ra 0 route (Juice Shop ra y hệt). Đường dẫn chấp nhận cả nháy đơn và nháy kép."""
import os, re, json, sys
def _relp(*a): return os.path.relpath(*a).replace('\\', '/')   # v1.6: Windows -> dấu '/'
from tree_sitter_language_pack import get_parser
R = sys.argv[1]; OUT = sys.argv[2]
VAO = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] else next((f for f in ('server.ts', 'app.ts', 'server.js', 'app.js', 'index.js', 'src/server.ts', 'src/app.ts', 'src/index.ts') if os.path.exists(os.path.join(R, f))), None)
if not VAO: print(json.dumps({'loi': 'không thấy tệp vào Express (server.ts/app.js/...)'})); sys.exit(2)
src = open(os.path.join(R, VAO), encoding='utf-8').read()
SVC = sys.argv[4] if len(sys.argv) > 4 else os.path.basename(os.path.realpath(R)).lower()
BO = {'security', 'verify', 'metrics', 'antiCheat'}
# import -> mô-đun
IMP = {}
for m in re.finditer(r"import\s+(?:\{([^}]+)\}|\*\s+as\s+(\w+)|(\w+))(?:\s*,\s*\{([^}]+)\})?\s+from\s+'(\.[^']+)'", src):
    mod = m.group(5)
    if m.group(1) or m.group(4):
        for nm in re.split(r',\s*', (m.group(1) or '') + ',' + (m.group(4) or '')):
            nm = nm.strip().split(' as ')[-1].strip()
            if nm: IMP[nm] = ('named', mod)
    if m.group(2): IMP[m.group(2)] = ('ns', mod)
    if m.group(3): IMP[m.group(3)] = ('default', mod)
TP = get_parser('typescript')   # TypeScript parser đọc được cả JavaScript thường
_cache = {}
def funcs(mod):
    p0 = os.path.normpath(os.path.join(R, os.path.dirname(VAO), mod))
    p = next((p0 + e for e in ('.ts', '.js', '/index.ts', '/index.js') if os.path.exists(p0 + e)), p0 + '.ts')
    if not os.path.exists(p): return p, {}
    if p in _cache: return p, _cache[p]
    s = open(p, 'rb').read(); tr = TP.parse(s); out = {}
    st = [tr.root_node]
    while st:
        n = st.pop(); st.extend(n.children)
        if n.type in ('function_declaration', 'generator_function_declaration'):
            nm = n.child_by_field_name('name'); out[s[nm.start_byte:nm.end_byte].decode()] = (n.start_point[0] + 1, n.end_point[0] + 1)
        if n.type == 'export_statement' and b'export default' in s[n.start_byte:n.start_byte + 20]:
            out['__default__'] = (n.start_point[0] + 1, n.end_point[0] + 1)
        if n.type == 'variable_declarator':
            v = n.child_by_field_name('value'); nm = n.child_by_field_name('name')
            if v is not None and v.type in ('arrow_function', 'function_expression', 'function'):
                out[s[nm.start_byte:nm.end_byte].decode()] = (n.start_point[0] + 1, n.end_point[0] + 1)
    _cache[p] = out; return p, out
def resolve(call):
    """'login' | 'basketItems.addBasketItem' -> (tệp, a, b) hoặc None"""
    if '.' in call:
        ns, fn = call.split('.', 1)
        if ns in BO or ns not in IMP or IMP[ns][0] != 'ns': return None
        p, F = funcs(IMP[ns][1]); return (_relp(p, R), *F[fn]) if fn in F else None
    if call not in IMP: return None
    kind, mod = IMP[call]; p, F = funcs(mod)
    key = '__default__' if kind == 'default' else call
    return (_relp(p, R), *F[key]) if key in F else None
routes = []
L = src.split('\n')
# gộp lời gọi app.X( ... ) nhiều dòng
i = 0
while i < len(L):
    m = re.match(r"\s*app\.(get|post|put|delete|patch|use|all)\(", L[i])
    if not m or L[i].lstrip().startswith('//'): i += 1; continue
    st = i; buf = L[i]; depth = buf.count('(') - buf.count(')')
    while depth > 0 and i + 1 < len(L): i += 1; buf += ' ' + L[i]; depth += L[i].count('(') - L[i].count(')')
    meth = m.group(1).upper(); meth = 'ALL' if meth in ('USE', 'ALL') else meth
    pm = re.match(r"\s*app\.\w+\(\s*(\[[^\]]*\]|'[^']*')", buf)
    if pm:
        paths = re.findall(r"'([^']*)'", pm.group(1)); rest = buf[pm.end():]
        calls = re.findall(r'([A-Za-z_][\w]*(?:\.[A-Za-z_]\w*)?)\s*\(', rest)
        for c in calls:
            if c.startswith('utils.') or c in ('express.static', 'serveIndex', 'rateLimit', 'IpFilter', 'require') : continue
            r = resolve(c)
            if r:
                for p in paths:
                    rt = re.sub(r':(\w+)', r'{\1}', p.split('(')[0]) if '(' not in p.split(':')[0] else re.sub(r'\(.*?\)', '', p).replace(':file', '{file}')
                    routes.append({'service': SVC, 'method': meth, 'route': rt, 'file': r[0], 'line_start': r[1], 'line_end': r[2], 'handler': c, 'can_cu': f'{VAO}:{st + 1}'})
    i += 1
# ---- v1.7: nhánh dự phòng theo cây cú pháp – CHỈ chạy khi cách cũ ra 0 route (giữ nguyên route map Juice Shop đã kiểm ở bước 31; trên Juice Shop nhánh này sẽ thêm 8 route, chưa kiểm) ----
DU_PHONG = not routes
da_co = {r['can_cu'] for r in routes}
sb = src.encode('utf-8'); TR = TP.parse(sb)
def _t(n): return sb[n.start_byte:n.end_byte].decode('utf-8', 'replace')
LOCAL = {}   # tên -> (dòng đầu, dòng cuối) của hàm/biến-hàm khai báo trong tệp vào
REQ = {}     # tên -> mô-đun require('./...')
st_ = [TR.root_node]
while st_:
    n = st_.pop(); st_.extend(n.children)
    if n.type in ('function_declaration', 'generator_function_declaration') and n.child_by_field_name('name') is not None:
        LOCAL[_t(n.child_by_field_name('name'))] = (n.start_point[0] + 1, n.end_point[0] + 1)
    if n.type == 'variable_declarator':
        v = n.child_by_field_name('value'); nm = n.child_by_field_name('name')
        if v is not None and nm is not None and nm.type == 'identifier':
            if v.type in ('arrow_function', 'function_expression', 'function'): LOCAL[_t(nm)] = (n.start_point[0] + 1, n.end_point[0] + 1)
            if v.type == 'call_expression' and _t(v.child_by_field_name('function')) == 'require':
                a = v.child_by_field_name('arguments'); m2 = re.search(r"['\"](\.[^'\"]+)['\"]", _t(a)) if a is not None else None
                if m2: REQ[_t(nm)] = m2.group(1)
def _han(arg):
    """đối số -> (tệp, a, b, tên) nếu là hàm xử lý trong repo"""
    if arg.type in ('arrow_function', 'function_expression', 'function'):
        return (VAO, arg.start_point[0] + 1, arg.end_point[0] + 1, '<inline>')
    if arg.type == 'identifier':
        nm = _t(arg)
        if nm in LOCAL: return (VAO, *LOCAL[nm], nm)
        r = resolve(nm)
        if r: return (*r, nm)
    if arg.type == 'member_expression':
        ob, pr = arg.child_by_field_name('object'), arg.child_by_field_name('property')
        if ob is not None and pr is not None and _t(ob) in REQ:
            p, F = funcs(REQ[_t(ob)]); fn = _t(pr)
            if fn in F: return (_relp(p, R), *F[fn], _t(arg))
        r = resolve(_t(arg))
        if r: return (*r, _t(arg))
    return None
st_ = [TR.root_node]
while st_ and DU_PHONG:
    n = st_.pop(); st_.extend(n.children)
    if n.type != 'call_expression': continue
    f = n.child_by_field_name('function')
    if f is None or f.type != 'member_expression': continue
    ob, pr = f.child_by_field_name('object'), f.child_by_field_name('property')
    if ob is None or pr is None or _t(ob) != 'app' or _t(pr) not in ('get', 'post', 'put', 'delete', 'patch', 'use', 'all'): continue
    can_cu = f'{VAO}:{n.start_point[0] + 1}'
    if can_cu in da_co: continue
    args = [a for a in n.child_by_field_name('arguments').named_children if a.type != 'comment']
    if not args or args[0].type not in ('string', 'array'): continue
    paths = re.findall(r"""['"]([^'"]*)['"]""", _t(args[0]))
    h = None
    for a in reversed(args[1:]):   # handler = đối số cuối phân giải được (middleware đứng trước)
        h = _han(a)
        if h: break
    if not h: continue
    meth = _t(pr).upper(); meth = 'ALL' if meth in ('USE', 'ALL') else meth
    for p in paths:
        rt = re.sub(r':(\w+)', r'{\1}', p)
        routes.append({'service': SVC, 'method': meth, 'route': rt, 'file': h[0], 'line_start': h[1], 'line_end': h[2], 'handler': h[3], 'can_cu': can_cu, 'nguon': 'v1.7_cay_cu_phap'})
json.dump(routes, open(OUT, 'w'), indent=0, ensure_ascii=False)
print(json.dumps({'so_route': len(routes), 'so_endpoint': len({(r['method'], r['route']) for r in routes}), 'tep_vao': VAO}, ensure_ascii=False))
