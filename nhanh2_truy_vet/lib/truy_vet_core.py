#!/usr/bin/env python3
"""Bước 23.3: chuẩn hoá phát hiện -> NormalizedFinding -> nối theo luật L1-L4 -> Tier 1/2/3.
Usage: python b23_3_truy_vet.py <thu_muc_quet_tho> <route_map.json> <out.json> [--lib <duong_dan_lib_v8>]
Tên tệp công cụ trong thu_muc_quet_tho: semgrep_*.json, bandit.json, njsscan.json, gitleaks.json, osv.json, grype*.json,
kics.json, dockle.json, docker_bench.json|.log, nuclei.jsonl, zap.json. Công cụ thiếu tệp -> bỏ qua và ghi vào 'cong_cu_thieu'.
Quy tắc đã chốt trước (PHIEU_BUOC23): không chỉnh luật sau khi thấy kết quả mà không ghi log.
"""
import glob, json, os, random, re, sys

QUET, RMAP, OUT = sys.argv[1], sys.argv[2], sys.argv[3]
LIB = sys.argv[sys.argv.index('--lib') + 1] if '--lib' in sys.argv else None
if LIB:
    sys.path.insert(0, LIB)
    from fam2 import family2  # họ lỗi của nhánh 1
else:
    family2 = lambda cw: next((c for c in cw), 'khac')
PHASE = {'semgrep': 'CODE', 'bandit': 'CODE', 'njsscan': 'CODE', 'eslint_security': 'CODE', 'eslint_mo_rong': 'CODE', 'codeql': 'CODE', 'gitleaks': 'CODE',
         'osv-scanner': 'BUILD', 'grype': 'BUILD', 'kics': 'DEPLOY', 'dockle': 'RELEASE', 'docker_bench': 'OPERATE', 'nuclei': 'TEST', 'zap': 'TEST'}
SECRET_CWE = {'CWE-798', 'CWE-538', 'CWE-321', 'CWE-200', 'CWE-312'}
SENS = re.compile(r'(\.env|id_rsa|\.git/config|\.pem|\.key|secret|credential)', re.I)
RM = json.load(open(RMAP))
F = []


def cwes(x):
    out = []
    for v in (x if isinstance(x, list) else [x]):
        for m in re.findall(r'CWE-?(\d+)', str(v or ''), re.I):
            out.append('CWE-' + m)
    return out


# ---- v1.1 (21/10/2026): THÊM trường 'sev' (mức nặng do chính công cụ gắn, chuẩn hóa theo PHIEU). Không đổi luật nối, không đổi cạnh. ----
SEV_SEMGREP = {'ERROR': 'High', 'WARNING': 'Medium', 'INFO': 'Low'}
SEV_GRYPE = {'Critical': 'Critical', 'High': 'High', 'Medium': 'Medium', 'Low': 'Low'}
SEV_OSV = {'CRITICAL': 'Critical', 'HIGH': 'High', 'MODERATE': 'Medium', 'LOW': 'Low'}
SEV_DOCKLE = {'FATAL': 'High', 'WARN': 'Medium', 'INFO': 'Low'}
SEV_ZAP = {'3': 'High', '2': 'Medium', '1': 'Low', '0': 'Info'}


# ---- v1.2 (21/10/2026): trường 'svc' + ràng buộc cùng dịch vụ cho L2/L3 (công tắc --khong-dich-vu tắt = hành vi v1.1). Xem PHIEU_BUOC23.md. ----
DV = '--khong-dich-vu' not in sys.argv
# v1.3 (21/10/2026): ứng dụng MỘT dịch vụ chính (DVWA, NodeGoat, VAmPI): --mot-dich-vu <ten> gán mọi mã/route/image dựng từ repo vào dịch vụ đó; image khác (CSDL) không thuộc dịch vụ nào.
SINGLE = sys.argv[sys.argv.index('--mot-dich-vu') + 1] if '--mot-dich-vu' in sys.argv else None


def svc_path(p):
    if SINGLE: return SINGLE if p else None
    m = re.search(r'services/([^/]+)', (p or '').replace('\\', '/'))
    return m.group(1) if m else None


def svc_image(p):
    if SINGLE: return SINGLE if re.match(r'^(?:grype_image|dockle)_gr2_.+-pin\.json$', os.path.basename(p or '')) else None
    m = re.match(r'^(?:grype_image|dockle)_crapi_(?:crapi-)?(.+)\.json$', os.path.basename(p or ''))
    return m.group(1) if m else None


def svc_route(r):
    if SINGLE: return SINGLE
    seg = (r or '').strip('/').split('/')[0]
    return seg if seg in ('identity', 'community', 'workshop') else 'web'


# ---- v1.4 (22/10/2026): suy họ lỗi của cảnh báo nuclei KHÔNG có CWE từ info.tags (bảng cố định trong PHIEU_L1_HO_TU_NHAN_NUCLEI.md). --khong-ho-nuclei = hành vi v1.3. ----
HO_NUCLEI = '--khong-ho-nuclei' not in sys.argv
NHAN2CWE = [('sqli', 'CWE-89'), ('xss', 'CWE-79'), ('rxss', 'CWE-79'), ('lfi', 'CWE-22'), ('pathtraversal', 'CWE-22'), ('traversal', 'CWE-22'), ('redirect', 'CWE-601'),
            ('cmdi', 'CWE-78'), ('ssrf', 'CWE-918'), ('xxe', 'CWE-611'), ('csrf', 'CWE-352')]
_N2C = dict(NHAN2CWE)


def ho_tu_nhan(info):
    """Quét tags theo thứ tự xuất hiện, lấy nhãn đầu tiên có trong bảng -> họ lỗi (family2 của CWE tương ứng); không có -> None."""
    tg = info.get('tags') or []
    tg = tg if isinstance(tg, list) else str(tg).split(',')
    for t in tg:
        c = _N2C.get(str(t).strip().lower())
        if c: return family2([c])
    return None


def add(tool, rule, cw, sev='Info', svc=None, fam=None, **an):
    f = {'finding_id': f'{PHASE[tool]}_{tool}_{len(F):04d}', 'phase': PHASE[tool], 'tool': tool, 'raw_rule_id': rule, 'raw_cwe': cw,
         'family': fam or (family2(cw) if cw else 'khac'), 'sev': sev, 'svc': sorted({x for x in (svc or []) if x}), 'anchors': {k: an.get(k) for k in ('file_path', 'line_start', 'line_end', 'url_route', 'package_name', 'cve_id', 'container_target', 'cis_control_class', 'sens_file')}}
    if fam: f['ho_suy_ra'] = 'nhan_nuclei'
    F.append(f)


def load(pat):
    return [(p, json.load(open(p, encoding='utf-8'))) for p in sorted(glob.glob(os.path.join(QUET, pat)))]


thieu = []
S = load('semgrep_*.json')
if not S: thieu.append('semgrep')
for _, d in S:
    for r in d.get('results', []):
        m = r['extra'].get('metadata', {})
        if m.get('category') != 'security': continue  # cấu hình khuyến nghị bước 13
        add('semgrep', r['check_id'], cwes(m.get('cwe')), sev=SEV_SEMGREP.get(r['extra'].get('severity'), 'Info'), file_path=r['path'], line_start=r['start']['line'], line_end=r['end']['line'])
B = load('bandit.json')
if not B: thieu.append('bandit')
for _, d in B:
    for r in d.get('results', []):
        add('bandit', r['test_id'], (['CWE-%s' % r['issue_cwe']['id']] if r.get('issue_cwe', {}).get('id') else []), sev=str(r.get('issue_severity', 'LOW')).title(), file_path=r['filename'].replace('\\', '/').split('crAPI/')[-1], line_start=r['line_number'], line_end=r['line_number'])
N = load('njsscan.json')
if not N: thieu.append('njsscan')
for _, d in N:
    for sec in ('nodejs', 'templates'):
        for rule, v in d.get(sec, {}).items():
            for fl in v.get('files', []):
                ml = fl.get('match_lines', [1, 1])
                add('njsscan', rule, cwes(v.get('metadata', {}).get('cwe')), sev=SEV_SEMGREP.get(v.get('metadata', {}).get('severity'), 'Info'), file_path=fl['file_path'], line_start=ml[0], line_end=ml[-1])
for _, d in load('eslint_security.json'):
    for x in d:
        for m in x['messages']:
            add('eslint_security', m.get('ruleId'), [], sev='Low', file_path=os.path.relpath(x['filePath'], '/tmp/claude-0/crapi/src') if x['filePath'].startswith('/tmp/') else x['filePath'].replace('\\', '/').split('crAPI/')[-1], line_start=m['line'], line_end=m.get('endLine', m['line']))
for _, d in load('eslint_security.json'):
    for x in d:
        for m in x['messages']:
            add('eslint_security', m.get('ruleId'), [], sev='Low', file_path=x['filePath'].replace('\\', '/').split('crAPI/')[-1].replace('/tmp/claude-0/crapi/src/', ''), line_start=m['line'], line_end=m.get('endLine', m['line']))
# v1.4c (bước 31): THÊM đọc CodeQL SARIF (pha CODE), không đổi luật nối. Thẻ cwe-0xx -> CWE-xx.
for p, d in load('codeql_*.sarif'):
    for run in d.get('runs', []):
        tags = {}
        for comp in [run['tool']['driver']] + run['tool'].get('extensions', []):
            for rl in comp.get('rules', []):
                tags[rl['id']] = ['CWE-%d' % int(t.split('cwe-')[-1]) for t in rl.get('properties', {}).get('tags', []) if 'external/cwe/cwe-' in t]
        for r in run.get('results', []):
            loc = r['locations'][0]['physicalLocation']; rg = loc.get('region', {})
            add('codeql', r['ruleId'], tags.get(r['ruleId'], []), sev={'error': 'High', 'warning': 'Medium', 'note': 'Low'}.get(r.get('level', 'warning'), 'Medium'), file_path=loc['artifactLocation']['uri'], line_start=rg.get('startLine'), line_end=rg.get('endLine', rg.get('startLine')))
for p, d in load('gitleaks.json'):
    for r in (d or []):
        fp = r.get('File', '').replace('\\', '/')
        add('gitleaks', r.get('RuleID'), ['CWE-798'], svc=[svc_path(fp)], sev=('High' if r.get('RuleID') in ('private-key', 'pkcs12-file') else 'Medium'), file_path=fp, line_start=r.get('StartLine'), line_end=r.get('EndLine'), sens_file=os.path.basename(fp))
if not glob.glob(os.path.join(QUET, 'gitleaks.json')): thieu.append('gitleaks')
for p, d in load('osv*.json'):
    for res in d.get('results', []):
        for pk in res.get('packages', []):
            for v in pk.get('vulnerabilities', []):
                add('osv-scanner', v['id'], cwes(v.get('database_specific', {}).get('cwe_ids')), svc=[svc_path(res.get('source', {}).get('path'))], sev=SEV_OSV.get(str(v.get('database_specific', {}).get('severity', '')).upper(), 'Info'), package_name=pk['package']['name'], cve_id=([a for a in v.get('aliases', []) if a.startswith('CVE')] or [v['id']])[0], file_path=res.get('source', {}).get('path'))
if not glob.glob(os.path.join(QUET, 'osv*.json')): thieu.append('osv-scanner')
for p, d in load('grype*.json'):
    tgt = 'image' if 'image' in os.path.basename(p) else 'dir'
    for m in d.get('matches', []):
        add('grype', m['vulnerability']['id'], [], svc=([svc_image(p)] if tgt == 'image' else [svc_path(l.get('path')) for l in m['artifact'].get('locations', [])]), sev=SEV_GRYPE.get(m['vulnerability'].get('severity'), 'Info'), package_name=m['artifact']['name'], cve_id=m['vulnerability']['id'], container_target=tgt)
        if tgt == 'image': F[-1]['phase'] = 'RELEASE'; F[-1]['finding_id'] = F[-1]['finding_id'].replace('BUILD_', 'RELEASE_')
if not glob.glob(os.path.join(QUET, 'grype*.json')): thieu.append('grype')
for p, d in load('kics.json'):
    for q in d.get('queries', []):
        if q.get('severity') not in ('HIGH', 'MEDIUM', 'CRITICAL'): continue  # cấu hình khuyến nghị bước 13/21
        for fl in q.get('files', []):
            add('kics', q.get('query_name'), cwes(q.get('cwe')), sev=str(q.get('severity', 'INFO')).title(), file_path=fl.get('file_name'), line_start=fl.get('line'), line_end=fl.get('line'), cis_control_class=q.get('query_name'))
if not glob.glob(os.path.join(QUET, 'kics.json')): thieu.append('kics')
for p, d in load('dockle*.json'):
    for x in d.get('details', []):
        if x.get('level') in ('FATAL', 'WARN'):
            al = ' '.join(x.get('alerts', []))
            add('dockle', x['code'], ['CWE-538'] if x['code'] in ('CIS-DI-0010', 'DKL-DI-0005') else [], svc=[svc_image(p)], sev=SEV_DOCKLE.get(x.get('level'), 'Info'), container_target=p, cis_control_class=x['code'], sens_file=(SENS.search(al).group(1) if SENS.search(al) else None))
if not glob.glob(os.path.join(QUET, 'dockle*.json')): thieu.append('dockle')
for p in sorted(glob.glob(os.path.join(QUET, 'docker_bench*'))):
    txt = open(p, encoding='utf-8-sig', errors='ignore').read()
    if p.endswith('.json'):  # docker-bench-security.log.json
        dj = json.loads(txt)
        for t in (dj['tests'] if isinstance(dj, dict) else dj):
            for x in t.get('results', []):
                if x.get('result') == 'WARN': add('docker_bench', x['id'], [], sev='Medium', cis_control_class='WARN ' + x['id'] + ' | ' + x.get('desc', ''), container_target=','.join(x.get('items', [])) or x.get('desc', '')[:80])
        continue
    txt = re.sub(r'\x1b\[[0-9;]*m', '', txt)  # bỏ mã màu ANSI
    for ln in txt.splitlines():
        m = re.search(r'\[WARN\]\s+(\d+\.\d+)\s*-?\s*(.*)', ln)
        if m: add('docker_bench', m.group(1), [], sev='Medium', cis_control_class='WARN ' + m.group(1), container_target=m.group(2)[:80])
if not glob.glob(os.path.join(QUET, 'docker_bench*')): thieu.append('docker_bench')
for p in sorted(glob.glob(os.path.join(QUET, 'nuclei*.jsonl'))):
    for ln in open(p, encoding='utf-8'):
        if ln.strip():
            r = json.loads(ln)
            u = re.sub(r'^https?://[^/]+', '', r.get('matched-at', r.get('host', '')))
            _cw = cwes(r.get('info', {}).get('classification', {}).get('cwe-id')); add('nuclei', r.get('template-id'), _cw, fam=(ho_tu_nhan(r.get('info', {})) if (HO_NUCLEI and not _cw) else None), svc=[svc_route(u.split('?')[0])], sev=str(r.get('info', {}).get('severity', 'info')).title(), url_route=u.split('?')[0], sens_file=(SENS.search(u).group(1) if SENS.search(u) else None))
if not glob.glob(os.path.join(QUET, 'nuclei*.jsonl')): thieu.append('nuclei')
for p, d in load('zap*.json'):
    for s in d.get('site', []):
        for a in s.get('alerts', []):
            for i in a.get('instances', []):
                u = re.sub(r'^https?://[^/]+', '', i.get('uri', ''))
                add('zap', a.get('pluginid'), ['CWE-' + str(a['cweid'])] if str(a.get('cweid', '0')) not in ('0', '-1') else [], svc=[svc_route(u.split('?')[0])], sev=SEV_ZAP.get(str(a.get('riskcode')), 'Info'), url_route=u.split('?')[0], sens_file=(SENS.search(u).group(1) if SENS.search(u) else None))
if not glob.glob(os.path.join(QUET, 'zap*.json')): thieu.append('zap')

# ---- route cho CODE (qua route_map) và cho TEST (so khớp mẫu) ----
UUID = re.compile(r'[0-9a-fA-F-]{8,}')
def pat(r): return re.compile('^' + re.sub(r'\\\{[^}]+\\\}', r'[^/]+', re.escape(r.rstrip('/'))) + '/?$')
RP = [(pat(r['route']), r) for r in RM]
def route_of_code(f):
    a = f['anchors']
    if not a['file_path'] or not a['line_start']: return []
    fp = a['file_path'].replace('\\', '/')
    return sorted({(r['method'], r['route']) for r in RM if fp.endswith(r['file']) and r['line_start'] <= a['line_start'] <= r['line_end']})
def route_of_test(f):
    u = f['anchors']['url_route']
    if not u: return []
    return sorted({(r['method'], r['route']) for p, r in RP if p.match(u)})
for f in F:
    rs = route_of_code(f) if f['phase'] == 'CODE' else route_of_test(f) if f['phase'] == 'TEST' else []
    f['routes'] = [x[1] for x in rs]

# ---- luật nối ----
E = []
def edge(a, b, rule): E.append({'a': a['finding_id'], 'b': b['finding_id'], 'luat': rule})
code = [f for f in F if f['phase'] == 'CODE']; test = [f for f in F if f['phase'] == 'TEST']
for a in code:
    for b in test:
        if a['family'] == b['family'] and a['family'] != 'khac' and set(a['routes']) & set(b['routes']): edge(a, b, 'L1')
# L0 (bổ sung 20/10, xem PHIEU mục Nhật ký điều chỉnh): cùng pha, cùng tệp, cách <=5 dòng, cùng họ lỗi, khác công cụ -> Tier 2
for i, a in enumerate(code):
    for b in code[i + 1:]:
        A_, B_ = a['anchors'], b['anchors']
        if a['tool'] != b['tool'] and a['family'] == b['family'] and a['family'] != 'khac' and A_['file_path'] and B_['file_path'] and A_['file_path'].split('services/')[-1] == B_['file_path'].split('services/')[-1] and A_['line_start'] and B_['line_start'] and abs(A_['line_start'] - B_['line_start']) <= 5: edge(a, b, 'L0')
def secret(f): return f['anchors']['sens_file'] and (set(f['raw_cwe']) & SECRET_CWE or f['tool'] in ('gitleaks', 'dockle', 'nuclei', 'zap'))
sec = [f for f in F if secret(f)]
for i, a in enumerate(sec):
    for b in sec[i + 1:]:
        if a['phase'] != b['phase'] and os.path.basename(str(a['anchors']['sens_file'])).lower() == os.path.basename(str(b['anchors']['sens_file'])).lower():
            if DV and not (set(a['svc']) & set(b['svc'])): continue
            edge(a, b, 'L2')
bd = [f for f in F if f['phase'] == 'BUILD' and f['tool'] in ('osv-scanner', 'grype') and f['anchors']['container_target'] != 'image']
rl = [f for f in F if f['tool'] == 'grype' and f['anchors']['container_target'] == 'image']
for a in bd:
    for b in rl:
        if a['anchors']['cve_id'] == b['anchors']['cve_id'] and a['anchors']['package_name'] == b['anchors']['package_name']:
            if DV and not (set(b['svc']) & set(a['svc'])): continue
            edge(a, b, 'L3')
L4 = {'run_as_root': (r'user|root', 'CIS-DI-0001', '4.1'), 'mem_limit': (r'memory|cpu|resource', None, '5.10'), 'rw_rootfs': (r'read.?only|writable', None, '5.12'),
      'privileged': (r'privileged container|privileged mode|no-new-privileges|escalation|security_opt', None, '5.26'), 'healthcheck': (r'health', 'CIS-DI-0006', '4.6')}
DB_DESC = {'run_as_root': r'user', 'mem_limit': r'memory usage', 'rw_rootfs': r'root filesystem', 'privileged': r'acquiring additional privileges|privileged containers', 'healthcheck': r'health'}
def l4class(f):
    t = (f['tool'], str(f['anchors']['cis_control_class'] or ''))
    for k, (rx, dk, db) in L4.items():
        if f['tool'] == 'dockle' and dk and t[1] == dk: return k
        if f['tool'] == 'docker_bench' and re.search(DB_DESC[k], t[1], re.I): return k  # khớp theo MÔ TẢ (số mục đổi giữa các bản CIS; v1.6.0: bộ nhớ=5.11, rootfs=5.13, không tăng đặc quyền=5.26, healthcheck=5.27)
        if f['tool'] == 'kics' and re.search(rx, t[1], re.I): return k
for a in [f for f in F if f['tool'] in ('kics', 'dockle')]:
    for b in [f for f in F if f['tool'] == 'docker_bench']:
        if l4class(a) and l4class(a) == l4class(b): edge(a, b, 'L4')

# ---- cụm và Tier ----
P = {f['finding_id']: f['finding_id'] for f in F}
def fd(x):
    while P[x] != x: P[x] = P[P[x]]; x = P[x]
    return x
for e in E: P[fd(e['a'])] = fd(e['b'])
C = {}
for f in F: C.setdefault(fd(f['finding_id']), []).append(f)
byid = {f['finding_id']: f for f in F}
for k, fs in C.items():
    ph = {f['phase'] for f in fs}; tl = {f['tool'] for f in fs}
    t = 1 if len(ph) >= 2 else 2 if len(tl) >= 2 else 3
    for f in fs: f['tier'] = t; f['cum'] = k

def tom(F_):
    from collections import Counter
    return dict(Counter(f['tier'] for f in F_))
res = {'tong_phat_hien': len(F), 'theo_cong_cu': {t: sum(1 for f in F if f['tool'] == t) for t in sorted({f['tool'] for f in F})}, 'cong_cu_thieu': thieu, 'rang_buoc_dich_vu': DV,
       'so_canh': {r: sum(1 for e in E if e['luat'] == r) for r in ('L0', 'L1', 'L2', 'L3', 'L4')}, 'so_cum': len(C), 'tier_theo_phat_hien': tom(F),
       'cum': [{'id': k, 'tier': fs[0]['tier'], 'pha': sorted({f['phase'] for f in fs}), 'cong_cu': sorted({f['tool'] for f in fs}), 'ho': sorted({f['family'] for f in fs}), 'routes': sorted({r for f in fs for r in f['routes']}), 'so_phat_hien': len(fs)} for k, fs in C.items() if len(fs) > 1],
       'phat_hien': F, 'canh': E}
# ---- đường cơ sở M4 (chỉ để so sánh) ----
nl = sum(1 for a in code for b in test if a['family'] == b['family'] and a['family'] != 'khac')
res['co_so_chi_theo_CWE'] = {'so_cap_CODE_TEST_noi': nl}
random.seed(0)
res['co_so_ngau_nhien'] = {'so_cap_CODE_TEST_noi': res['so_canh']['L1']}
json.dump(res, open(OUT, 'w'), ensure_ascii=False, indent=1)
print(json.dumps({k: res[k] for k in ('tong_phat_hien', 'theo_cong_cu', 'cong_cu_thieu', 'so_canh', 'so_cum', 'tier_theo_phat_hien')}, ensure_ascii=False))
