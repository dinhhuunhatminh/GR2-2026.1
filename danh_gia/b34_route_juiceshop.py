"""Bước 34 (E1_v3) – bản đồ route Juice Shop v20.3.0: GIỮ NGUYÊN regex/lookahead trong khai báo route Express (vd. /ftp(?!/quarantine)/:file); chỉ đổi :param thành [^/]+.
Xuất thêm: regex (để khớp URL), route_goc (chuỗi khai báo), nhãn route (route) vẫn bỏ nhóm regex để chấm theo cùng chuẩn hoá của b24_cham.py.
(Gốc: Bước 31 – bản đồ route Juice Shop v20.3.0 (cạnh E1) từ server.ts: app.<method>(đường dẫn, ...handler) -> hàm handler (tệp, dòng).
Handler = định danh được gọi trong danh sách đối số, phân giải qua import của server.ts sang routes/*.ts hoặc lib/*.ts.
Bỏ middleware dùng chung: security.*, verify.*, metrics.*, antiCheat.* (kiểm quyền / phát hiện thử thách / đo đạc), và hàm của thư viện ngoài.
app.use(...) -> phương thức 'ALL'. Route tự sinh của finale (/api/<Model>) không có mã handler trong repo -> không đưa vào.
Không dùng đáp án.)"""
import os, re, json, sys
from tree_sitter_language_pack import get_parser
R = sys.argv[1] if len(sys.argv) > 1 else '/home/claude/b34/juiceshop'
OUT = sys.argv[2] if len(sys.argv) > 2 else '/home/claude/b34/route_map_juiceshop_v3.json'
src = open(os.path.join(R, 'server.ts'), encoding='utf-8').read()
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
TP = get_parser('typescript')
_cache = {}
def funcs(mod):
    p = os.path.normpath(os.path.join(R, mod)) + '.ts'
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
        p, F = funcs(IMP[ns][1]); return (os.path.relpath(p, R), *F[fn]) if fn in F else None
    if call not in IMP: return None
    kind, mod = IMP[call]; p, F = funcs(mod)
    key = '__default__' if kind == 'default' else call
    return (os.path.relpath(p, R), *F[key]) if key in F else None

def express_regex(p, meth):
    """Đường dẫn Express -> (regex khớp URL, nhãn). Giữ nhóm (...) nguyên vẹn (lookahead (?!...), (?:...), lớp ký tự); :param -> [^/]+; * -> .*; ký tự khác escape."""
    out = []; lab = []; i = 0
    while i < len(p):
        ch = p[i]
        if ch == '(':
            d = 0; j = i
            while j < len(p):
                if p[j] == '\\': j += 2; continue
                if p[j] == '(': d += 1
                elif p[j] == ')':
                    d -= 1
                    if d == 0: break
                j += 1
            out.append(p[i:j + 1]); i = j + 1   # nhãn: bỏ nhóm
        elif ch == ':':
            m = re.match(r':(\w+)', p[i:]); out.append('[^/]+'); lab.append('{' + m.group(1) + '}'); i += m.end()
        elif ch == '*': out.append('.*'); lab.append('*'); i += 1
        else: out.append(re.escape(ch)); lab.append(ch); i += 1
    body = ''.join(out); label = ''.join(lab)
    if meth == 'ALL': rx = '^' + body.rstrip('/') + '(/.*)?$'
    else: rx = '^' + body.rstrip('/') + '/?$'
    return rx, label
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
                    rx, label = express_regex(p, meth)
                    routes.append({'service': 'juiceshop', 'method': meth, 'route': label, 'regex': rx, 'route_goc': p, 'file': r[0], 'line_start': r[1], 'line_end': r[2], 'handler': c, 'can_cu': f'server.ts:{st + 1}'})
    i += 1
json.dump(routes, open(OUT, 'w'), indent=0, ensure_ascii=False)
print(len(routes), len({(r['method'], r['route']) for r in routes}))
for r in routes[:8]: print(r)
