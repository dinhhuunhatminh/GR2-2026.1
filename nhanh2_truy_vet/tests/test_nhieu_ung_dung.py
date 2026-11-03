# -*- coding: utf-8 -*-
"""Kiểm thử bước 24 (không cần Docker): đăng nhập 3 ứng dụng bằng máy chủ GIẢ, kế hoạch quét động theo ứng dụng, xóa token/cookie, --mot-dich-vu.
Chạy: python tests/test_nhieu_ung_dung.py"""
import json, os, subprocess, sys, tempfile, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE); LIB = os.path.join(ROOT, 'lib'); B23 = os.path.dirname(ROOT)
sys.path.insert(0, LIB)
import quet_dong as QD, quet_dong_ud as UD
KQ = []


def kt(ten, ok, ghi=''):
    KQ.append(ok); print(('PASS ' if ok else 'FAIL ') + ten + (' - ' + str(ghi)[:150] if ghi else ''))


SESS = 'ABCDEF1234567890SESSION'; VTOK = 'VAMPI.FAKE.TOKEN987654'


class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _s(self, code, body='', hdr=None, ct='text/html'):
        b = body.encode(); self.send_response(code); self.send_header('Content-Type', ct); self.send_header('Content-Length', str(len(b)))
        for k, v in (hdr or {}).items(): self.send_header(k, v)
        self.end_headers(); self.wfile.write(b)

    def do_GET(self):
        p = self.path.split('?')[0]; ck = self.headers.get('Cookie', '')
        if p == '/createdb': return self._s(200, '{"message":"ok"}', ct='application/json')
        if p == '/setup.php': return self._s(200, "<input type='hidden' name='user_token' value='tok_setup' />")
        if p == '/login.php': return self._s(200, "<input type='hidden' name='user_token' value='tok_login' />")
        if p == '/vulnerabilities/sqli/':
            return self._s(200, 'Vulnerability: SQL Injection') if ('PHPSESSID=' + SESS) in ck and 'security=low' in ck else self._s(302, '', {'Location': '/login.php'})
        if p == '/signup' or p == '/login': return self._s(200, '<input type="hidden" name="_csrf" value=""></input>', {'Set-Cookie': 'sid=NGSESSION_ABCDEF99; Path=/'})
        if p == '/dashboard': return self._s(200, 'Dashboard') if 'sid=NGSESSION_ABCDEF99' in ck else self._s(302, '', {'Location': '/login'})
        self._s(404)

    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0)); d = self.rfile.read(n).decode(); p = self.path.split('?')[0]
        if p == '/users/v1/register': return self._s(200, '{"status":"success"}', ct='application/json')
        if p == '/users/v1/login': return self._s(200, json.dumps({'auth_token': VTOK}), ct='application/json')
        if p == '/setup.php': return self._s(200, 'ok')
        if p == '/login.php':
            return self._s(302, '', {'Location': 'index.php', 'Set-Cookie': 'PHPSESSID=' + SESS + '; Path=/'}) if 'user_token=tok_login' in d else self._s(200, 'bad')
        if p == '/signup': return self._s(200, 'Dashboard (hiển thị ngay, không chuyển hướng như NodeGoat thật)')
        self._s(404)


def main():
    srv = HTTPServer(('127.0.0.1', 0), H); threading.Thread(target=srv.serve_forever, daemon=True).start(); base = f'http://127.0.0.1:{srv.server_port}'
    t, u = UD.lay_xac_thuc('vampi', base); kt('N1 VAmPI: lấy token Bearer sau createdb/đăng ký/đăng nhập', t == VTOK and u.startswith('vsecops'), u)
    t, u = UD.lay_xac_thuc('dvwa', base); kt('N2 DVWA: setup + login có user_token, cookie PHPSESSID + security=low', t == f'PHPSESSID={SESS}; security=low', u)
    t2, u = UD.lay_xac_thuc('nodegoat', base); kt('N3 NodeGoat: _csrf rỗng (CSRF tắt), đăng ký trả 200 không chuyển hướng, xác nhận bằng /dashboard', t2 == 'sid=NGSESSION_ABCDEF99', u)
    # kế hoạch theo ứng dụng
    out = tempfile.mkdtemp()
    for app in ('vampi', 'dvwa', 'nodegoat'):
        hs = UD.HOSO[app]; S = QD.ke_hoach_dong(out, os.path.join(HERE, 'vampi_openapi.json'), hs['net'], hs['mang'], None, app, bat_zap=True)  # v1.4: ZAP chỉ có khi bật
        ids = {s['id']: s for s in S}; txt = json.dumps(S)
        kt(f'N4 kế hoạch {app}: dùng mạng {hs["mang"]}, header đúng kiểu, chưa lộ bí mật, docker_bench -i {hs["container"]}',
           hs['mang'] in txt and ('Cookie: {{TOKEN}}' in txt if hs['kieu'] == 'cookie' else 'Authorization: Bearer {{TOKEN}}' in txt) and SESS not in txt and VTOK not in txt and hs['container'] in json.dumps(ids['docker_bench']['lenh']), sorted(ids))
        kt(f'N5 kế hoạch {app}: ZAP đúng kiểu ({"api-scan" if hs["zap"] == "api" else "full-scan + loại trừ URL"})',
           ('zap_api' in ids and 'zap-api-scan.py' in json.dumps(ids['zap_api']['lenh'])) if hs['zap'] == 'api' else ('zap_web' in ids and 'zap-full-scan.py' in json.dumps(ids['zap_web']['lenh']) and 'globalexcludeurl' in json.dumps(ids['zap_web']['lenh']) and 'matchstr=Cookie' in json.dumps(ids['zap_web']['lenh'])))
    S = QD.ke_hoach_dong(out, os.path.join(HERE, 'vampi_openapi.json'), 'http://crapi-web', 'docker_default', None, bat_zap=True)
    kt('N6 crAPI không đổi: vẫn zap_api + Bearer + -i crapi', any(s['id'] == 'zap_api' for s in S) and 'crapi' in json.dumps([s for s in S if s['id'] == 'docker_bench']) and 'Cookie' not in json.dumps(S))
    # xóa bí mật
    tk = f'PHPSESSID={SESS}; security=low'
    kt('N7 che_token xóa cả chuỗi cookie lẫn giá trị từng cookie', SESS not in QD.che_token(f'lỗi: {tk} / tách {SESS}', tk) and 'low' in UD.bi_mat_phu(tk).__repr__() + 'low')
    d = tempfile.mkdtemp(); open(os.path.join(d, 'a.json'), 'w').write(json.dumps({'h': SESS, 'k': tk}))
    n = QD.xoa_token_trong_tep(d, tk) + sum(QD.xoa_token_trong_tep(d, x) for x in UD.bi_mat_phu(tk))
    kt('N8 xóa bí mật khỏi tệp kết quả', SESS not in open(os.path.join(d, 'a.json')).read() and n >= 1, n)
    ls = UD.urls('dvwa', 'http://gr2-dvwa'); kt('N9 danh sách URL DVWA: có tham số, đúng host', len(ls) >= 10 and all(x.startswith('http://gr2-dvwa/vulnerabilities/') for x in ls) and any('id=1' in x for x in ls))
    # ---- v1.4: ZAP tùy chọn + dọn container khi quá giờ ----
    import quet_tinh as QT, subprocess as sp
    for app in ('vampi', 'dvwa', 'nodegoat'):
        hs = UD.HOSO[app]; S0 = QD.ke_hoach_dong(out, os.path.join(HERE, 'vampi_openapi.json'), hs['net'], hs['mang'], None, app)
        S1 = QD.ke_hoach_dong(out, os.path.join(HERE, 'vampi_openapi.json'), hs['net'], hs['mang'], None, app, bat_zap=True, zap_giay=77)
        zid = 'zap_api' if hs['zap'] == 'api' else 'zap_web'
        kt(f'N11 {app}: mặc định KHÔNG có ZAP; bat_zap=True có ZAP với giới hạn giờ 77s', not any(x['cong_cu'] == 'zap' for x in S0) and {x['id']: x for x in S1}[zid]['timeout'] == 77 and any(x['id'] == 'nuclei_dast' for x in S0))
    S2 = QD.ke_hoach_dong(out, os.path.join(HERE, 'vampi_openapi.json'), 'http://crapi-web', 'docker_default', ['zap'])
    kt('N12 cong_cu=["zap"] vẫn bật ZAP (chọn rõ ràng)', [x['id'] for x in S2] == ['zap_api'])
    l, ten = QT._dat_ten_container(['docker', 'run', '--rm', 'img'])
    l2, ten2 = QT._dat_ten_container(['docker', 'run', '--rm', '--name', 'abc', 'img']); l3, ten3 = QT._dat_ten_container(['git', 'status'])
    kt('N13 đặt tên container: thêm --name nếu thiếu, giữ tên có sẵn, bỏ qua lệnh không phải docker run', ten and ['--name', ten] == l[2:4] and ten2 == 'abc' and l2.count('--name') == 1 and ten3 is None and l3 == ['git', 'status'])
    goi = []; real = sp.run
    def gia(cmd, *a, **k):
        goi.append(list(cmd))
        if cmd[:3] == ['docker', 'rm', '-f']: return sp.CompletedProcess(cmd, 0, '', '')
        raise sp.TimeoutExpired(cmd, 1)
    QT.subprocess.run = gia
    try: r = QT.chay_buoc({'id': 'x', 'cong_cu': 'zap', 'lenh': ['docker', 'run', '--rm', 'img'], 'tep_ra': [], 'ma_chap_nhan': [0]}, tempfile.mkdtemp(), 1)
    finally: QT.subprocess.run = real
    kt('N14 quá giờ -> trạng thái het_gio VÀ gọi docker rm -f đúng tên container', r['trang_thai'] == 'het_gio' and r.get('da_xoa_container') is True and goi[-1][:3] == ['docker', 'rm', '-f'] and goi[-1][3] == goi[0][goi[0].index('--name') + 1], goi)
    # ---- v1.4: họ lỗi nuclei suy từ nhãn (PHIEU_L1_HO_TU_NHAN_NUCLEI.md) ----
    qd = tempfile.mkdtemp(); R_ = lambda tid, tags, cwe, u: json.dumps({'template-id': tid, 'matched-at': 'http://x' + u, 'info': {'severity': 'high', 'tags': tags, **({'classification': {'cwe-id': [cwe]}} if cwe else {})}})
    open(os.path.join(qd, 'nuclei_dast.jsonl'), 'w').write('\n'.join([R_('t-sqli', ['sqli', 'dast'], None, '/a/?id=1'), R_('t-cve', ['cve', 'sqli'], 'cwe-787', '/a/?id=2'), R_('t-rfi', ['rfi', 'dast'], None, '/a/?p=3'), R_('t-xss', ['dast', 'xss'], None, '/b/?q=1')]) + '\n')
    open(os.path.join(qd, 'semgrep_python.json'), 'w').write(json.dumps({'results': [{'check_id': 'python.sqli.tainted-sql-string', 'path': '/src/app.py', 'start': {'line': 5}, 'end': {'line': 6}, 'extra': {'severity': 'ERROR', 'metadata': {'category': 'security', 'cwe': ['CWE-89: SQL Injection']}}}]}))
    rm_ = os.path.join(qd, 'rm.json'); json.dump([{'service': 'app', 'method': 'GET', 'route': '/a/', 'file': 'app.py', 'line_start': 1, 'line_end': 20}], open(rm_, 'w'))
    def chay(*extra):
        o_ = os.path.join(qd, 'o%d.json' % len(extra)); p_ = subprocess.run([sys.executable, '-I', os.path.join(LIB, 'truy_vet_core.py'), qd, rm_, o_, '--lib', LIB, '--mot-dich-vu', 'app'] + list(extra), capture_output=True, text=True)
        return json.load(open(o_, encoding='utf-8')) if p_.returncode == 0 else {'phat_hien': [], 'so_canh': {}, 'err': p_.stderr[-200:]}
    Rn, Ro = chay(), chay('--khong-ho-nuclei'); fam = lambda R, t: [f['family'] for f in R['phat_hien'] if f['raw_rule_id'] == t]
    kt('N15 nhãn sqli/xss -> họ sqli/xss; có CWE thì giữ CWE; rfi (không trong bảng) vẫn khác', fam(Rn, 't-sqli') == ['sqli'] and fam(Rn, 't-xss') == ['xss'] and fam(Rn, 't-cve') == ['bo_nho'] and fam(Rn, 't-rfi') == ['khac'], Rn.get('err') or [(f['raw_rule_id'], f['family']) for f in Rn['phat_hien'] if f['tool'] == 'nuclei'])
    kt('N16 công tắc --khong-ho-nuclei trả hành vi v1.3 (mọi nuclei không CWE là khác, L1 = 0); bản mới nối L1 semgrep<->nuclei sqli', fam(Ro, 't-sqli') == ['khac'] and Ro['so_canh'].get('L1') == 0 and Rn['so_canh'].get('L1', 0) >= 1, (Ro['so_canh'], Rn['so_canh']))
    kt('N17 raw_cwe KHÔNG bị chạm (vẫn rỗng) và có dấu ho_suy_ra', all(f['raw_cwe'] == [] and f.get('ho_suy_ra') == 'nhan_nuclei' for f in Rn['phat_hien'] if f['raw_rule_id'] == 't-sqli'))
    import bao_cao_vet as BCV
    hb = os.path.join(qd, 'bc.html'); oo = os.path.join(qd, 'o0.json'); r_ = BCV.sinh(oo, hb); h_ = open(hb, encoding='utf-8').read()
    kt('N18 v1.5 báo cáo: có thẻ "Vết L1" ghi route chung, tệp:dòng của mã, không còn tên crAPI viết cứng', 'Vết L1' in h_ and 'route = /a' in h_ and 'app.py:5' in h_ and 'crapi-chatbot' not in h_, r_)
    # --mot-dich-vu
    o = os.path.join(out, 'tv.json')
    p = subprocess.run([sys.executable, '-I', os.path.join(LIB, 'truy_vet_core.py'), os.path.join(B23, 'quet_tho'), os.path.join(HERE, 'route_map_crapi.json'), o, '--lib', LIB, '--mot-dich-vu', 'app'], capture_output=True, text=True)
    R = json.load(open(o, encoding='utf-8')) if p.returncode == 0 else {'phat_hien': []}
    sv = {x for f in R['phat_hien'] for x in f.get('svc', [])}
    kt('N10 --mot-dich-vu: mọi dịch vụ gán là "app" (image crAPI không khớp mẫu image dựng từ repo thì để trống)', p.returncode == 0 and sv == {'app'}, sv or p.stderr[-150:])
    n = sum(1 for x in KQ if x); print(f'\nTỔNG: {n}/{len(KQ)} đạt'); sys.exit(0 if n == len(KQ) else 1)


main()
