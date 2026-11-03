# -*- coding: utf-8 -*-
"""Lập kế hoạch và chạy các công cụ quét TĨNH bằng Docker (giai đoạn 1 của MCP nhánh 2).
Không dùng shell: mọi lệnh là danh sách đối số. Phiên bản công cụ ghim theo catalog nhánh 1 (v8).
Tên tệp đầu ra khớp với bộ phân tích trong truy_vet_core.py.
CHÚ Ý TRUNG THỰC: lệnh grype/dockle lấy từ chay_tinh_windows.ps1 đã chạy thật ở bước 23; các lệnh còn lại
(gitleaks, osv-scanner, kics, semgrep, bandit qua Docker) chưa được kiểm chạy thật trong Docker -> mỗi bước tự ghi mã thoát,
stderr và kiểm tệp JSON hợp lệ để lần chạy đầu cho biết ngay bước nào cần sửa."""
import json, os, re, shutil, subprocess, time

IMG = {'gitleaks': 'ghcr.io/gitleaks/gitleaks:v8.30.1', 'osv': 'ghcr.io/google/osv-scanner:v2.7.0', 'grype': 'anchore/grype:v0.120.0',
       'kics': 'checkmarx/kics:v2.1.20', 'dockle': 'goodwithtech/dockle:v0.4.15', 'semgrep': 'semgrep/semgrep:latest', 'bandit': 'python:3.11-slim'}
SEMGREP_RULES_REPO = 'https://github.com/semgrep/semgrep-rules.git'
SEMGREP_RULES_COMMIT = '9bbf021d'
CONG_CU_HO_TRO = ['semgrep', 'bandit', 'gitleaks', 'osv-scanner', 'grype', 'kics', 'dockle']
CHUA_HO_TRO = {'njsscan': 'chưa đóng gói ở giai đoạn 1 (crAPI: 0 phát hiện)', 'eslint_security': 'cần cấu hình eslint riêng', 'eslint_mo_rong': 'cần cấu hình eslint riêng',
               'codeql': 'cần build, chưa chạy ở bước 23', 'zap': 'quét động - giai đoạn 2', 'nuclei': 'quét động - giai đoạn 2', 'docker_bench': 'quét động - giai đoạn 2'}
LANG_EXT = {'.php': 'php', '.java': 'java', '.go': 'go', '.py': 'python', '.js': 'javascript', '.jsx': 'javascript', '.ts': 'typescript', '.tsx': 'typescript'}
SKIP = {'.git', 'node_modules', 'vendor'}
DNS_LOI = re.compile(r'no such host|temporary failure in name resolution|i/o timeout|TLS handshake timeout', re.I)


def _walk(repo):
    for dp, dn, fn in os.walk(repo):
        dn[:] = [d for d in dn if d not in SKIP]
        yield dp, fn


def phat_hien_ngon_ngu(repo):
    ng = set()
    for dp, fn in _walk(repo):
        for f in fn:
            ng.add(LANG_EXT.get(os.path.splitext(f)[1].lower()))
    ng.discard(None)
    return sorted(ng)


def thu_muc_loai_kics(repo):
    out = []
    for dp, dn, fn in os.walk(repo):
        keep = []
        for d in dn:
            if d == '.git': continue
            if d in ('vendor', 'node_modules'):
                out.append('/src/' + os.path.relpath(os.path.join(dp, d), repo).replace('\\', '/'))
            else:
                keep.append(d)
        dn[:] = keep
    return out


def ten_tep(image):
    return image.split(':')[0].replace('/', '_')


def ke_hoach(repo, out, cong_cu=None, images=None, rules_dir=None, kics_paths=None):
    """Trả về (danh sách bước, ghi chú). Mỗi bước: id, cong_cu, mo_ta, lenh, tep_ra, ma_chap_nhan, ghi_stdout."""
    cc = [c for c in (cong_cu or CONG_CU_HO_TRO)]
    ghi_chu, S = [], []
    for c in cc:
        if c in CHUA_HO_TRO: ghi_chu.append(f'{c}: {CHUA_HO_TRO[c]}')
        elif c not in CONG_CU_HO_TRO: ghi_chu.append(f'{c}: không thuộc bộ công cụ cố định')
    cc = [c for c in cc if c in CONG_CU_HO_TRO]
    src = f'{repo}:/src:ro'; o = f'{out}:/out'
    D = ['docker', 'run', '--rm']

    def add(i, c, mo_ta, lenh, tep, ok=(0,), stdout=None):
        S.append({'id': i, 'cong_cu': c, 'mo_ta': mo_ta, 'lenh': lenh, 'tep_ra': tep, 'ma_chap_nhan': list(ok), 'ghi_stdout': stdout})
    if 'gitleaks' in cc:
        add('gitleaks', 'gitleaks', 'quét cây tệp, không quét lịch sử', D + ['-v', src, '-v', o, IMG['gitleaks'], 'detect', '--no-git', '--source', '/src', '-f', 'json', '-r', '/out/gitleaks.json', '--exit-code', '0'], ['gitleaks.json'])
    if 'osv-scanner' in cc:
        add('osv', 'osv-scanner', 'quét tệp khóa/manifest (cần mạng tới osv.dev)', D + ['-v', src, IMG['osv'], 'scan', 'source', '-r', '--no-resolve', '--format', 'json', '/src'], ['osv.json'], ok=(0, 1), stdout='osv.json')
    if 'grype' in cc:
        add('grype_dir', 'grype', 'pha BUILD: quét cây thư mục', D + ['-v', src, '-v', o, IMG['grype'], 'dir:/src', '-o', 'json=/out/grype_dir.json'], ['grype_dir.json'])
    if 'kics' in cc:
        ex = thu_muc_loai_kics(repo)
        kp = ','.join('/src/' + p.strip('/\\').replace('\\', '/') for p in kics_paths) if kics_paths else '/src'
        lenh = D + ['-v', src, '-v', o, IMG['kics'], 'scan', '-p', kp, '--no-progress', '--report-formats', 'json', '-o', '/out', '--output-name', 'kics']
        if ex: lenh += ['--exclude-paths', ','.join(ex)]
        add('kics', 'kics', ('IaC; chỉ các đường dẫn: ' + ', '.join(kics_paths)) if kics_paths else 'IaC toàn repo; loại vendor/node_modules (bài học bước 23)', lenh, ['kics.json'], ok=(0, 20, 30, 40, 50, 60))
    if 'semgrep' in cc:
        rd = rules_dir or os.path.join(out, '_semgrep_rules')
        if not os.path.isdir(rd):
            add('semgrep_luat_clone', 'semgrep', f'tải semgrep-rules rồi checkout {SEMGREP_RULES_COMMIT}', ['git', 'clone', '--quiet', SEMGREP_RULES_REPO, rd], [])
            add('semgrep_luat_checkout', 'semgrep', 'ghim commit luật', ['git', '-C', rd, 'checkout', '--quiet', SEMGREP_RULES_COMMIT], [])
        for lg in phat_hien_ngon_ngu(repo):
            add(f'semgrep_{lg}', 'semgrep', f'quét {lg} (bộ lọc category=security làm ở bước truy vết)',
                D + ['-v', src, '-v', o, '-v', f'{rd}:/rules:ro', IMG['semgrep'], 'semgrep', 'scan', '--config', f'/rules/{lg}', '--exclude', 'test', '--exclude', 'tests', '--exclude', 'docs', '--exclude', 'examples', '--exclude', 'vendor', '--json', '-o', f'/out/semgrep_{lg}.json', '/src'],
                [f'semgrep_{lg}.json'], ok=(0, 1))
    if 'bandit' in cc:
        add('bandit', 'bandit', 'Python; bỏ B101 và thư mục test', D + ['-v', src, '-v', o, IMG['bandit'], 'sh', '-c', 'pip install -q bandit >/dev/null 2>&1 && bandit -r /src -s B101 -x /src/tests,/src/test,/src/docs,/src/examples -f json -o /out/bandit.json'], ['bandit.json'], ok=(0, 1))
    for im in (images or []):
        n = ten_tep(im)
        if 'grype' in cc: add(f'pull_{n}', 'grype', f'kéo image {im} (image dựng cục bộ không có trên registry nên mã 1 được chấp nhận; bước quét image sau sẽ báo lỗi nếu image thiếu)', ['docker', 'pull', im], [], ok=(0, 1))
        if 'grype' in cc: add(f'grype_image_{n}', 'grype', f'pha RELEASE: {im}', D + ['-v', '/var/run/docker.sock:/var/run/docker.sock', '-v', o, IMG['grype'], f'docker:{im}', '-o', f'json=/out/grype_image_{n}.json'], [f'grype_image_{n}.json'])
        if 'dockle' in cc: add(f'dockle_{n}', 'dockle', f'pha RELEASE: {im}', D + ['-v', '/var/run/docker.sock:/var/run/docker.sock', '-v', o, IMG['dockle'], '-f', 'json', '-o', f'/out/dockle_{n}.json', im], [f'dockle_{n}.json'])
    if not images and ('grype' in cc or 'dockle' in cc): ghi_chu.append('không có danh sách image -> bỏ qua grype-image và dockle (pha RELEASE)')
    return S, ghi_chu


def kiem_tra_moi_truong(images=None):
    r = {'docker': False, 'git': bool(shutil.which('git')), 'image_thieu': [], 'ghi_chu': []}
    try:
        p = subprocess.run(['docker', 'version', '--format', '{{.Server.Version}}'], capture_output=True, text=True, timeout=30)
        r['docker'] = p.returncode == 0
        if p.returncode != 0: r['ghi_chu'].append('Docker không chạy: ' + (p.stderr or '')[-200:])
    except Exception as e:
        r['ghi_chu'].append('Không gọi được docker: ' + str(e)[:200])
    if r['docker']:
        for k, im in IMG.items():
            p = subprocess.run(['docker', 'image', 'inspect', im], capture_output=True, text=True)
            if p.returncode != 0: r['image_thieu'].append(im)
    r['ghi_chu'].append('image công cụ thiếu sẽ được docker tự kéo ở lần chạy đầu (cần mạng).')
    return r


def _json_ok(p):
    """JSON hợp lệ. Tệp .jsonl: mỗi dòng không rỗng phải là JSON; tệp .jsonl RỖNG hợp lệ (công cụ quét xong, 0 phát hiện)."""
    try:
        if p.lower().endswith('.jsonl'):
            for ln in open(p, encoding='utf-8-sig'):
                if ln.strip(): json.loads(ln)
            return True
        json.load(open(p, encoding='utf-8-sig')); return True
    except Exception:
        return False


def _dat_ten_container(lenh):
    """Nếu là `docker run ...` mà chưa có --name thì thêm tên duy nhất để còn dừng được khi quá giờ. Trả (lệnh, tên|None)."""
    if len(lenh) >= 2 and lenh[0] == 'docker' and lenh[1] == 'run':
        for i, x in enumerate(lenh):
            if x == '--name' and i + 1 < len(lenh): return lenh, lenh[i + 1]
        ten = 'vsecops-' + os.urandom(4).hex()
        return lenh[:2] + ['--name', ten] + lenh[2:], ten
    return lenh, None


def _xoa_container(ten):
    try:
        r = subprocess.run(['docker', 'rm', '-f', ten], capture_output=True, text=True, timeout=60)
        return r.returncode == 0
    except Exception:
        return False


def chay_buoc(b, out, timeout):
    timeout = b.get('timeout') or timeout
    t0 = time.time(); kq = {'id': b['id'], 'cong_cu': b['cong_cu'], 'ma_thoat': None, 'trang_thai': 'loi', 'stderr_cuoi': ''}
    for lan in (1, 2):
        try:
            lenh, ten = _dat_ten_container(b['lenh'])
            p = subprocess.run(lenh, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=timeout)
        except subprocess.TimeoutExpired:
            # v1.4: tắt lệnh docker KHÔNG dừng container (sự cố 22/10/2026: ZAP chạy tiếp, ăn ~1600% CPU) -> xóa container theo tên
            kq['trang_thai'] = 'het_gio'; kq['giay'] = round(time.time() - t0, 1)
            if ten: kq['da_xoa_container'] = _xoa_container(ten)
            return kq
        except FileNotFoundError as e:
            kq['stderr_cuoi'] = str(e); kq['giay'] = round(time.time() - t0, 1); return kq
        kq['ma_thoat'] = p.returncode; kq['stdout_ky_tu'] = len(p.stdout or ''); kq['stderr_cuoi'] = (p.stderr or '')[-400:]
        if p.returncode not in b['ma_chap_nhan'] and lan == 1 and DNS_LOI.search(p.stderr or ''):
            kq['da_thu_lai'] = True; time.sleep(5); continue
        break
    if b.get('ghi_stdout') and p.stdout:
        open(os.path.join(out, b['ghi_stdout']), 'w', encoding='utf-8').write(p.stdout)
    tep = []
    for t in b['tep_ra']:
        pth = os.path.join(out, t); tep.append({'ten': t, 'co': os.path.exists(pth), 'json_hop_le': _json_ok(pth) if os.path.exists(pth) else False})
    kq['tep_ra'] = tep
    ok_ma = p.returncode in b['ma_chap_nhan']
    kq['trang_thai'] = 'ok' if ok_ma and all(x['json_hop_le'] for x in tep) else 'loi'
    kq['giay'] = round(time.time() - t0, 1)
    return kq
