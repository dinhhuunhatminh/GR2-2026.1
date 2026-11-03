# -*- coding: utf-8 -*-
"""Kiểm thử giai đoạn 2 KHÔNG cần Docker thật: máy chủ crAPI giả + lệnh `docker` giả.
Kiểm: chặn mục tiêu ngoài danh sách, chỉ lập kế hoạch khi chưa xác nhận, lấy token, token KHÔNG lọt ra kết quả/stderr/tệp, đổi tên tệp, bật/tắt app.
Chạy: python tests/test_giai_doan2.py"""
import asyncio, json, os, stat, sys, tempfile, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE); B23 = os.path.dirname(ROOT)
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
KQ = []; TOKEN = 'FAKE.JWT.SECRETTOKEN123'; DA_DK = []


def kt(ten, ok, ghi=''):
    KQ.append(ok); print(('PASS ' if ok else 'FAIL ') + ten + (' - ' + str(ghi)[:140] if ghi else ''))


class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _j(self, code, o):
        b = json.dumps(o).encode(); self.send_response(code); self.send_header('Content-Type', 'application/json'); self.send_header('Content-Length', str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self): self._j(200, {'ok': 1})
    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0)); d = json.loads(self.rfile.read(n) or b'{}')
        if self.path.endswith('/signup'): DA_DK.append(d); self._j(200, {'message': 'ok'})
        elif self.path.endswith('/login'): self._j(200, {'token': TOKEN, 'type': 'Bearer'})
        else: self._j(404, {})


FAKE = '''#!/usr/bin/env python3
import sys, os, json
a = sys.argv[1:]; tok = ''
for x in a:
    if x.startswith('Authorization: Bearer '): tok = x.split()[-1]
    if 'replacement=Bearer ' in x: tok = x.split('Bearer ')[-1].strip("'")
def mount(suffix):
    for i, x in enumerate(a):
        if x == '-v' and a[i + 1].endswith(suffix): return a[i + 1][:-len(suffix)]
if 'compose' in a: print('compose ok'); sys.exit(0)
sys.stderr.write('debug header ' + tok + '\\n')
if any('nuclei' in x for x in a):
    o = a[a.index('-o') + 1].replace('/out/', ''); open(os.path.join(mount(':/out'), o), 'w').write(json.dumps({'template-id': 't', 'request': 'GET / Authorization: Bearer ' + tok, 'matched-at': 'http://crapi-web/x'}) + '\\n')
elif any('zaproxy' in x for x in a):
    open(os.path.join(mount(':/zap/wrk:rw'), 'zap_api.json'), 'w').write(json.dumps({'site': [], 'note': tok})); sys.exit(2)
else:
    open(os.path.join(mount(':/out'), 'docker_bench.log.json'), 'w').write('{"tests": []}')
'''


async def goi(S, ten, **a):
    r = await S.call_tool(ten, a)
    if r.isError: return {'__loi__': r.content[0].text if r.content else ''}
    return json.loads(r.content[0].text) if r.content else {}


async def doi(S, jid, tmax=60):
    for _ in range(tmax):
        st = await goi(S, 'trang_thai_job', job_id=jid)
        if st.get('trang_thai') == 'xong': return st
        await asyncio.sleep(1)
    return st


async def main():
    srv = HTTPServer(('127.0.0.1', 0), H); port = srv.server_address[1]; threading.Thread(target=srv.serve_forever, daemon=True).start()
    tmp = tempfile.mkdtemp(); binp = os.path.join(tmp, 'bin'); os.makedirs(binp); fp = os.path.join(binp, 'docker'); open(fp, 'w').write(FAKE); os.chmod(fp, os.stat(fp).st_mode | stat.S_IEXEC)
    out = os.path.join(tmp, 'ra'); comp = os.path.join(tmp, 'docker-compose.yml'); open(comp, 'w').write('services: {}')
    env = dict(os.environ); env['PATH'] = binp + os.pathsep + env['PATH']; env['VSECOPS_ALLOWED_ROOTS'] = B23 + os.pathsep + tmp + os.pathsep + tempfile.gettempdir(); env['VSECOPS_ALLOWED_TARGETS'] = 'crapi-web,localhost,127.0.0.1'
    spec = os.path.join(HERE, 'crapi-openapi-spec.json'); host = f'http://127.0.0.1:{port}'
    p = StdioServerParameters(command=sys.executable, args=[os.path.join(ROOT, 'server.py')], env=env)
    async with stdio_client(p) as (r, w):
        async with ClientSession(r, w) as S:
            await S.initialize()
            tools = {t.name for t in (await S.list_tools()).tools}
            kt('G1 có công cụ chay_ung_dung và chay_quet_dong', {'chay_ung_dung', 'chay_quet_dong'} <= tools)
            e = await goi(S, 'chay_quet_dong', ra_dir=out, openapi_spec=spec, muc_tieu_host='http://evil.example.com')
            kt('G2 chặn mục tiêu ngoài danh sách cho phép', '__loi__' in e and 'không nằm trong danh sách' in e['__loi__'], e)
            e = await goi(S, 'chay_quet_dong', ra_dir=out, openapi_spec=spec, muc_tieu_mang='http://10.0.0.5')
            kt('G3 chặn cả mục tiêu trong mạng Docker lạ', '__loi__' in e)
            d = await goi(S, 'chay_quet_dong', ra_dir=out, openapi_spec=spec, muc_tieu_host=host)
            kt('G4 mặc định chỉ lập kế hoạch (v1.4: 3 bước, ZAP tắt), không tạo thư mục kết quả', d.get('che_do', '').startswith('ke_hoach') and not os.path.exists(out) and len(d.get('buoc', [])) == 3 and 'TẮT' in d.get('zap', ''), [b['id'] for b in d.get('buoc', [])])
            kt('G5 kế hoạch KHÔNG lộ token và dùng chỗ giữ chỗ', 'FAKE' not in json.dumps(d) and '{{TOKEN}}' in json.dumps(d))
            u = await goi(S, 'chay_ung_dung', compose_file=comp, hanh_dong='len')
            kt('G6 chay_ung_dung len mặc định chỉ lập kế hoạch', u.get('che_do', '').startswith('ke_hoach'), u.get('lenh'))
            j = await goi(S, 'chay_quet_dong', ra_dir=out, openapi_spec=spec, muc_tieu_host=host, xac_nhan=True, bat_zap=True)
            st = await doi(S, j['job_id'])
            ids = {x['id']: x['trang_thai'] for x in st['bo_loi']} if st.get('bo_loi') else {}
            kt('G7 job chạy xong, tất cả bước ok (docker giả)', st.get('trang_thai') == 'xong' and st.get('so_ok') == 6 and not st.get('bo_loi'), st)
            kt('G8 đã đăng ký tài khoản thử trên ứng dụng giả', len(DA_DK) == 1 and DA_DK[0]['email'].endswith('@example.com'))
            allout = ''
            for dp, _, fs in os.walk(out):
                for f in fs: allout += open(os.path.join(dp, f), encoding='utf-8', errors='ignore').read()
            kt('G9 TOKEN không còn trong bất kỳ tệp kết quả nào', 'SECRETTOKEN123' not in allout and '<DA_XOA_TOKEN>' in allout)
            kt('G10 TOKEN không lọt vào kết quả trả về của job', 'SECRETTOKEN123' not in json.dumps(st))
            kt('G11 tệp đầu ra đúng tên cho bộ truy vết', all(os.path.exists(os.path.join(out, f)) for f in ('nuclei_dast.jsonl', 'nuclei_exp.jsonl', 'zap_api.json', 'docker_bench.json')))
            urls = open(os.path.join(out, '_dong', 'urls.txt')).read().split()
            sp = json.load(open(os.path.join(out, '_dong', 'spec_zap.json')))
            kt('G12 danh sách URL 7 route và đặc tả ZAP trỏ đúng mục tiêu', len(urls) == 7 and sp['servers'][0]['url'] == 'http://crapi-web', len(urls))
            u = await goi(S, 'chay_ung_dung', compose_file=comp, hanh_dong='xuong', xac_nhan=True)
            st = await doi(S, u['job_id'], 20)
            kt('G13 chay_ung_dung xuong (xác nhận) chạy nền và xong', st.get('so_ok') == 1, st)
    n = sum(KQ); print(f'\nTỔNG: {n}/{len(KQ)} đạt'); sys.exit(0 if n == len(KQ) else 1)

asyncio.run(main())
