# -*- coding: utf-8 -*-
"""Quét ĐỘNG nhiều ứng dụng (bước 24): hồ sơ theo ứng dụng + đăng nhập tài khoản thử.
Ứng dụng hỗ trợ: vampi (token Bearer), dvwa (cookie PHPSESSID + security=low), nodegoat (cookie phiên, có _csrf).
crAPI vẫn dùng đường cũ trong quet_dong.py. Mật khẩu/token/cookie chỉ ở bộ nhớ, KHÔNG ghi ra đâu.
CHÚ Ý TRUNG THỰC: luồng đăng nhập của 3 ứng dụng này mới viết, được thử bằng máy chủ giả; chạy thật lần đầu sẽ cho biết còn sai chỗ nào."""
import http.cookiejar, json, re, secrets, string, urllib.error, urllib.parse, urllib.request

HOSO = {
    'vampi': {'net': 'http://gr2-vampi:5000', 'host': 'http://localhost:5002', 'mang': 'gr2net_vampi', 'kieu': 'bearer', 'zap': 'api', 'container': 'gr2-vampi'},
    'dvwa': {'net': 'http://gr2-dvwa', 'host': 'http://localhost:4280', 'mang': 'gr2net_dvwa', 'kieu': 'cookie', 'zap': 'web', 'container': 'gr2-dvwa',
             'loai_tru_zap': r'.*(logout|setup|security|phpinfo)\.php.*'},
    'nodegoat': {'net': 'http://gr2-nodegoat-web:4000', 'host': 'http://localhost:4000', 'mang': 'gr2net_nodegoat', 'kieu': 'cookie', 'zap': 'web', 'container': 'gr2-nodegoat',
                 'loai_tru_zap': r'.*/logout.*'},
}
# URL cho nuclei DAST: các trang GET có tham số lấy từ chính giao diện/mã của ứng dụng (như đặc tả OpenAPI của crAPI ở bước 23: công cụ động ĐƯỢC BIẾT trước route)
URLS = {
    'vampi': ['/books/v1/bookTitle1', '/users/v1/name1', '/users/v1/_debug', '/users/v1', '/books/v1', '/me'],
    'dvwa': ['/vulnerabilities/sqli/?id=1&Submit=Submit', '/vulnerabilities/sqli_blind/?id=1&Submit=Submit', '/vulnerabilities/xss_r/?name=test', '/vulnerabilities/xss_d/?default=English',
             '/vulnerabilities/fi/?page=include.php', '/vulnerabilities/brute/?username=admin&password=password&Login=Login', '/vulnerabilities/csrf/?password_new=test&password_conf=test&Change=Change',
             '/vulnerabilities/open_redirect/source/low.php?redirect=info.php', '/vulnerabilities/weak_id/', '/vulnerabilities/authbypass/', '/vulnerabilities/bac/', '/vulnerabilities/csp/',
             '/vulnerabilities/javascript/', '/vulnerabilities/cryptography/', '/vulnerabilities/exec/', '/vulnerabilities/upload/', '/vulnerabilities/captcha/'],
    'nodegoat': ['/allocations/1?threshold=1', '/research?symbol=AAPL', '/learn?url=http://example.com', '/profile', '/contributions', '/memos', '/benefits', '/dashboard'],
}


def urls(ung_dung, base):
    return [base.rstrip('/') + u for u in URLS[ung_dung]]


def _opener():
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar)), jar


def _doc(op, url, data=None, hdr=None, timeout=30):
    body = urllib.parse.urlencode(data).encode() if isinstance(data, dict) else data
    rq = urllib.request.Request(url, body, hdr or {})
    try:
        with op.open(rq, timeout=timeout) as r: return r.status, r.read().decode('utf-8', 'replace'), r.geturl()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', 'replace'), url


def _json_post(url, obj):
    rq = urllib.request.Request(url, json.dumps(obj).encode(), {'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(rq, timeout=30) as r: return r.status, json.loads(r.read().decode() or '{}')
    except urllib.error.HTTPError as e:
        try: return e.code, json.loads(e.read().decode() or '{}')
        except Exception: return e.code, {}


def _mk(n=10):
    return 'Aa1!' + ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(n))


def _token_html(html):
    m = re.search(r'user_token[\'"]\s+value=[\'"]([^\'"]+)[\'"]', html) or re.search(r'name=[\'"]_csrf[\'"]\s+value=[\'"]([^\'"]+)[\'"]', html) or re.search(r'value=[\'"]([^\'"]+)[\'"]\s+name=[\'"]_csrf[\'"]', html)
    return m.group(1) if m else None


def _vampi(host):
    r = secrets.token_hex(4); u = 'vsecops' + r; mk = _mk()
    try: urllib.request.urlopen(host + '/createdb', timeout=60).read()
    except urllib.error.HTTPError: pass
    st, _ = _json_post(host + '/users/v1/register', {'username': u, 'password': mk, 'email': f'{u}@example.com'})
    if st not in (200, 201): raise RuntimeError(f'VAmPI: đăng ký thất bại, mã HTTP {st}')
    st, j = _json_post(host + '/users/v1/login', {'username': u, 'password': mk})
    if st != 200 or not j.get('auth_token'): raise RuntimeError(f'VAmPI: đăng nhập thất bại, mã HTTP {st}')
    return j['auth_token'], u


def _snip(h, n=260):
    """Đoạn chữ ngắn của trang (bỏ thẻ HTML) để chẩn đoán khi đăng nhập lỗi. Không chứa bí mật: chỉ nội dung trang trả về."""
    return re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', ' ', re.sub(r'(?is)<(script|style).*?</\1>', ' ', h)))[:n]


def _dvwa(host):
    op, jar = _opener()
    st, h, _ = _doc(op, host + '/setup.php')
    t = _token_html(h)
    if not t: raise RuntimeError('DVWA: không thấy user_token ở /setup.php')
    st_s, h_s, _ = _doc(op, host + '/setup.php', {'create_db': 'Create / Reset Database', 'user_token': t})
    chan_doan = f'setup mã {st_s}: ' + _snip(h_s)
    st, h, _ = _doc(op, host + '/login.php'); t = _token_html(h)
    if not t: raise RuntimeError('DVWA: không thấy user_token ở /login.php')
    st, h, url = _doc(op, host + '/login.php', {'username': 'admin', 'password': 'password', 'Login': 'Login', 'user_token': t})
    ck = {c.name: c.value for c in jar}
    if 'PHPSESSID' not in ck: raise RuntimeError('DVWA: không có PHPSESSID sau đăng nhập; ' + chan_doan)
    cookie = f"PHPSESSID={ck['PHPSESSID']}; security=low"
    st, h, url = _doc(op, host + '/vulnerabilities/sqli/', hdr={'Cookie': cookie})
    if st != 200 or 'login.php' in url or 'SQL Injection' not in h: raise RuntimeError(f'DVWA: đăng nhập chưa thành công (mã {st}, url {url[-40:]}); trang: ' + _snip(h) + ' | ' + chan_doan)
    return cookie, 'admin (tài khoản mặc định của DVWA)'


def _nodegoat(host):
    """NodeGoat ở commit ghim: CSRF bị tắt (chú thích 'Fix for A8') nên _csrf có thể rỗng; đăng ký xong trang trả luôn dashboard (không chuyển hướng) nên kiểm bằng GET /dashboard."""
    op, jar = _opener(); r = secrets.token_hex(3); u = 'vsecops' + r; mk = _mk(8)
    st, h, _ = _doc(op, host + '/signup'); t = _token_html(h) or ''
    st, h, url = _doc(op, host + '/signup', {'userName': u, 'firstName': 'Vsecops', 'lastName': r, 'password': mk, 'verify': mk, 'email': f'{u}@example.com', '_csrf': t})
    st, h, url = _doc(op, host + '/dashboard')
    if st != 200 or '/login' in url:
        st, h, _ = _doc(op, host + '/login'); t = _token_html(h) or ''
        _doc(op, host + '/login', {'userName': u, 'password': mk, '_csrf': t})
        st, h, url = _doc(op, host + '/dashboard')
    if st != 200 or '/login' in url: raise RuntimeError(f'NodeGoat: đăng ký/đăng nhập chưa thành công (mã {st})')
    cookie = '; '.join(f'{c.name}={c.value}' for c in jar)
    if not cookie: raise RuntimeError('NodeGoat: không có cookie phiên')
    return cookie, u


def lay_xac_thuc(ung_dung, host):
    """Trả (chuỗi_xác_thực, tên_tài_khoản). Bearer: chỉ token. Cookie: 'a=b; c=d'."""
    return {'vampi': _vampi, 'dvwa': _dvwa, 'nodegoat': _nodegoat}[ung_dung](host)


def bi_mat_phu(token):
    """Các mảnh nhạy cảm cần xóa riêng (giá trị từng cookie)."""
    out = []
    for kv in token.split(';'):
        v = kv.strip().split('=', 1)[-1]
        if len(v) >= 8 and v != token: out.append(v)
    return out
