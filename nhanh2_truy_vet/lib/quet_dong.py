# -*- coding: utf-8 -*-
"""Giai đoạn 2: quét ĐỘNG có đăng nhập (nuclei, ZAP, docker_bench) + bật/tắt ứng dụng.
An toàn: mục tiêu phải nằm trong danh sách cho phép; token chỉ ở bộ nhớ, bị xóa khỏi stderr, tệp kết quả và kế hoạch hiển thị.
CHÚ Ý TRUNG THỰC: các lệnh ở đây CHƯA chạy thật; cú pháp truyền header cho ZAP là điểm rủi ro nhất (xem KE_HOACH_GIAI_DOAN_2.md)."""
import json, os, re, secrets, string, time, urllib.error, urllib.parse, urllib.request
import quet_dong_ud as UD

IMG = {'nuclei': 'projectdiscovery/nuclei:latest', 'zap': 'ghcr.io/zaproxy/zaproxy:stable', 'docker_bench': 'gr2-docker-bench2'}
CONG_CU_DONG = ['nuclei', 'zap', 'docker_bench']
ZAP_GIAY_MAC_DINH = 1200  # Claude đề xuất (20 phút), chưa đo; ZAP bản cũ không giới hạn nên treo máy ở lần chạy 22/10/2026
TOKEN = '{{TOKEN}}'
MAC_DINH_CHO_PHEP = 'crapi-web,localhost'


def muc_tieu_cho_phep():
    return {x.strip().lower() for x in os.environ.get('VSECOPS_ALLOWED_TARGETS', MAC_DINH_CHO_PHEP).split(',') if x.strip()}


def kiem_tra_muc_tieu(url):
    h = (urllib.parse.urlparse(url).hostname or '').lower()
    if h not in muc_tieu_cho_phep():
        raise ValueError(f'Mục tiêu "{h}" không nằm trong danh sách cho phép {sorted(muc_tieu_cho_phep())} (biến môi trường VSECOPS_ALLOWED_TARGETS).')
    return url.rstrip('/')


def _spec(spec_path):
    return json.load(open(spec_path, encoding='utf-8'))


def sinh_urls(spec_path, base):
    """URL các route GET có tham số truy vấn trong đặc tả OpenAPI (như bước 23), tham số đường dẫn thay bằng 1."""
    d = _spec(spec_path); out = []
    for p, v in d['paths'].items():
        g = v.get('get')
        if not g: continue
        q = [x for x in g.get('parameters', []) if x.get('in') == 'query']
        if not q: continue
        qs = '&'.join(f"{x['name']}={x.get('schema', {}).get('example', 1) if x.get('schema', {}).get('type') in ('integer', 'number') else 'test'}" for x in q)
        out.append(base + re.sub(r'\{[^}]+\}', '1', p) + '?' + qs)
    return out


def ghi_spec_cho_zap(spec_path, base, out_file):
    d = _spec(spec_path); d['servers'] = [{'url': base}]
    json.dump(d, open(out_file, 'w', encoding='utf-8'), ensure_ascii=False)


def kiem_song(base, giay=120):
    t0 = time.time(); loi = ''
    while time.time() - t0 < giay:
        try:
            urllib.request.urlopen(base + '/', timeout=5); return True, ''
        except urllib.error.HTTPError:
            return True, ''  # máy chủ trả mã lỗi HTTP = đang sống
        except Exception as e:
            loi = str(e)[:150]; time.sleep(3)
    return False, loi


def _post(url, obj):
    rq = urllib.request.Request(url, json.dumps(obj).encode(), {'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(rq, timeout=30) as r: return r.status, json.loads(r.read().decode() or '{}')
    except urllib.error.HTTPError as e:
        try: return e.code, json.loads(e.read().decode() or '{}')
        except Exception: return e.code, {}


def lay_token(base):
    """Đăng ký tài khoản thử (ngẫu nhiên) rồi đăng nhập crAPI; trả (token, email). KHÔNG ghi mật khẩu/token ra đâu cả."""
    r = secrets.token_hex(4); email = f'vsecops.{r}@example.com'
    mk = 'Aa1!' + ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(8)) + '#9'
    st, _ = _post(base + '/identity/api/auth/signup', {'name': 'vsecops' + r, 'email': email, 'number': '9' + ''.join(secrets.choice(string.digits) for _ in range(9)), 'password': mk})
    if st not in (200, 201): raise RuntimeError(f'đăng ký thất bại, mã HTTP {st}')
    st, j = _post(base + '/identity/api/auth/login', {'email': email, 'password': mk})
    if st != 200 or not j.get('token'): raise RuntimeError(f'đăng nhập thất bại, mã HTTP {st}')
    return j['token'], email


def ke_hoach_dong(out, spec_path, muc_tieu_mang, mang_docker='docker_default', cong_cu=None, ung_dung='crapi', bat_zap=False, zap_giay=ZAP_GIAY_MAC_DINH):
    """v1.4: ZAP chủ động MẶC ĐỊNH TẮT (cong_cu=None -> nuclei + docker_bench). Bật bằng bat_zap=True hoặc ghi 'zap' trong cong_cu. ZAP có giới hạn giờ cứng zap_giay (quá giờ thì xóa container)."""
    cc = list(cong_cu) if cong_cu else [c for c in CONG_CU_DONG if c != 'zap' or bat_zap]; S = []
    hs = UD.HOSO.get(ung_dung)  # None = crAPI (đường cũ, giữ nguyên)
    D = ['docker', 'run', '--rm', '--network', mang_docker]
    sub = os.path.join(out, '_dong'); o = f'{out}:/out'
    H = ('Cookie: ' if (hs and hs['kieu'] == 'cookie') else 'Authorization: Bearer ') + TOKEN

    def add(i, c, mo_ta, lenh, tep, ok=(0,), doi_ten=None, timeout=None):
        S.append({'id': i, 'cong_cu': c, 'mo_ta': mo_ta, 'lenh': lenh, 'tep_ra': tep, 'ma_chap_nhan': list(ok), 'ghi_stdout': None, 'doi_ten': doi_ten or [], 'timeout': timeout, 'dong': True})
    if 'nuclei' in cc:
        add('nuclei_dast', 'nuclei', 'DAST fuzz các route GET có tham số, có đăng nhập', D + ['-v', o, IMG['nuclei'], '-l', '/out/_dong/urls.txt', '-dast', '-jsonl', '-o', '/out/nuclei_dast.jsonl', '-es', 'info', '-or', '-H', H], ['nuclei_dast.jsonl'])
        add('nuclei_exp', 'nuclei', 'tìm tệp cấu hình lộ (.env...)', D + ['-v', o, IMG['nuclei'], '-u', muc_tieu_mang, '-tags', 'exposure,dotenv,files', '-jsonl', '-o', '/out/nuclei_exp.jsonl', '-es', 'info', '-or', '-H', H], ['nuclei_exp.jsonl'])
    if 'zap' in cc and hs and hs['zap'] == 'web':
        opt = ['-config replacer.full_list(0).description=auth1', '-config replacer.full_list(0).enabled=true', '-config replacer.full_list(0).matchtype=REQ_HEADER',
               '-config replacer.full_list(0).matchstr=Cookie', '-config replacer.full_list(0).regex=false', "-config 'replacer.full_list(0).replacement=" + TOKEN + "'"]
        if hs.get('loai_tru_zap'):
            opt += ["-config 'globalexcludeurl.url_list.url(0).regex=" + hs['loai_tru_zap'] + "'", '-config globalexcludeurl.url_list.url(0).enabled=true']
        add('zap_web', 'zap', 'ZAP full-scan (spider + quét chủ động, giới hạn thời gian) có cookie đăng nhập, loại trừ đăng xuất/thiết lập CSDL (cú pháp loại trừ chưa kiểm chạy thật)',
            D + ['-v', f'{sub}:/zap/wrk:rw', IMG['zap'], 'zap-full-scan.py', '-t', muc_tieu_mang, '-J', 'zap_web.json', '-m', '3', '-T', '20', '-I', '-z', ' '.join(opt)],
            ['_dong/zap_web.json'], ok=(0, 1, 2), doi_ten=[(os.path.join(sub, 'zap_web.json'), os.path.join(out, 'zap_web.json'))], timeout=zap_giay)
    elif 'zap' in cc:
        opt = ' '.join(['-config replacer.full_list(0).description=auth1', '-config replacer.full_list(0).enabled=true', '-config replacer.full_list(0).matchtype=REQ_HEADER',
                        '-config replacer.full_list(0).matchstr=Authorization', '-config replacer.full_list(0).regex=false', "-config 'replacer.full_list(0).replacement=Bearer " + TOKEN + "'"])
        add('zap_api', 'zap', 'ZAP api-scan theo OpenAPI, có đăng nhập (cú pháp truyền header chưa kiểm chạy thật)', D + ['-v', f'{sub}:/zap/wrk:rw', IMG['zap'], 'zap-api-scan.py', '-t', '/zap/wrk/spec_zap.json', '-f', 'openapi', '-J', 'zap_api.json', '-I', '-T', '15', '-z', opt],
            ['_dong/zap_api.json'], ok=(0, 1, 2), doi_ten=[(os.path.join(sub, 'zap_api.json'), os.path.join(out, 'zap_api.json'))], timeout=zap_giay)
    if 'docker_bench' in cc:
        add('docker_bench', 'docker_bench', 'CIS runtime của container crapi (image dựng từ mã nguồn tên gr2-docker-bench2 như bước 23)',
            ['docker', 'run', '--rm', '--net', 'host', '--pid', 'host', '--userns', 'host', '--cap-add', 'audit_control', '-v', '/var/run/docker.sock:/var/run/docker.sock:ro', '-v', '/etc:/etc:ro', '-v', f'{sub}:/out', IMG['docker_bench'], '-c', 'container_runtime', '-i', (hs['container'] if hs else 'crapi'), '-l', '/out/docker_bench.log'],
            ['_dong/docker_bench.log.json'], ok=(0, 1), doi_ten=[(os.path.join(sub, 'docker_bench.log.json'), os.path.join(out, 'docker_bench.json'))])
    return S


def thay_token(lenh, token):
    return [x.replace(TOKEN, token) for x in lenh]


def che_token(text, token):
    t = text or ''
    if not token: return t
    for x in [token] + UD.bi_mat_phu(token): t = t.replace(x, '<DA_XOA_TOKEN>')
    return t


def xoa_token_trong_tep(out, token):
    """Xóa token khỏi mọi tệp văn bản kết quả (nuclei có thể ghi header yêu cầu)."""
    n = 0
    for dp, _, fs in os.walk(out):
        for f in fs:
            if not f.lower().endswith(('.json', '.jsonl', '.log', '.txt', '.html')): continue
            p = os.path.join(dp, f)
            try:
                s = open(p, encoding='utf-8', errors='ignore').read()
                if token in s: open(p, 'w', encoding='utf-8').write(s.replace(token, '<DA_XOA_TOKEN>')); n += 1
            except Exception:
                pass
    return n
