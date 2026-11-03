# -*- coding: utf-8 -*-
"""Bước 35: báo cáo HTML cho đầu ra truy_vet_v3. KHÔNG dùng AI, không mạng, không đồng hồ hệ thống (sinh lại cho cùng kết quả byte-for-byte).
Chỉ hiển thị các trường CÓ trong tệp kết quả. Tên cảnh báo ZAP chỉ lấy từ tệp quét thô nếu người dùng cho quet_tho_dir."""
import html, json, os, collections

E = html.escape
PHA = ['PLAN', 'CODE', 'BUILD', 'TEST', 'RELEASE', 'DEPLOY', 'OPERATE', 'MONITOR']
NHAN_GIAI = {
    'cung_loi': 'cùng chỗ trong mã và cùng họ lỗi (có thể là họ lỗi hiệu dụng, thừa kế từ hàm gọi ở hop 1, nên họ lỗi ghi trên từng phát hiện đôi khi khác nhau): nhãn mạnh nhất của hệ thống',
    'cung_tai_san': 'cùng endpoint hoặc hàm nhưng khác họ lỗi: chỉ là gợi ý',
    'chua_ro_ho': 'chưa rõ họ lỗi của một bên để so sánh: chỉ là gợi ý',
}
M_TEN = {'M1_PUBLIC_ENDPOINT': 'M1 endpoint công khai', 'M2_AUTH_ENDPOINT': 'M2 endpoint cần đăng nhập', 'M3_PACKAGED_IMAGE': 'M3 có trong image', 'M4_UNPACKAGED_DEAD': 'M4 không đóng gói (mã chết)'}


def ten_zap_tu_tho(quet_dir):
    """plugin id -> tên cảnh báo, đọc từ tệp JSON ZAP thô (nếu có). Không đoán."""
    out = {}
    if not quet_dir or not os.path.isdir(quet_dir): return out

    def walk(o):
        if isinstance(o, dict):
            pid = o.get('pluginid') or o.get('pluginId')
            nm = o.get('alert') or o.get('name')
            if pid is not None and nm: out.setdefault(str(pid), str(nm))
            for v in o.values(): walk(v)
        elif isinstance(o, list):
            for v in o: walk(v)
    for fn in sorted(os.listdir(quet_dir)):
        if 'zap' in fn.lower() and fn.lower().endswith('.json'):
            try: walk(json.load(open(os.path.join(quet_dir, fn), encoding='utf-8')))
            except Exception: pass
    return out


def vi_tri(f):
    a = f['anchors']
    if a.get('file_path'):
        return '%s:%s' % (a['file_path'], a.get('line_start')) if a.get('line_start') else a['file_path']
    return a.get('url_route') or a.get('package_name') or a.get('container_target') or ''


def rule_ngan(f):
    return f['raw_rule_id'].split('.')[-1] if f['tool'] != 'zap' else f['raw_rule_id']


def sinh(ket_qua_file, ra_html, quet_tho_dir=None, ten_ung_dung=None):
    R = json.load(open(ket_qua_file, encoding='utf-8'))
    if 'canh' not in R or 'cum' not in R or not R.get('phat_hien') or 'muc_phoi_nhiem_tinh' not in R:
        return {'loi': 'tệp không phải đầu ra truy_vet_v3 (thiếu canh/cum/muc_phoi_nhiem_tinh). Hãy dùng bao_cao_vet cho đầu ra v1.'}
    ten_zap = ten_zap_tu_tho(quet_tho_dir)
    F = {f['finding_id']: f for f in R['phat_hien']}
    app = ten_ung_dung or R.get('app') or ''
    nF = len(R['phat_hien'])
    xp = [c for c in R['cum'] if len(c['pha']) >= 2]
    n_trong = sum(c['so_phat_hien'] for c in xp)
    # cạnh theo cụm (cạnh gắn cả cụm của đầu a và đầu b)
    CC = collections.defaultdict(list)
    for e in R['canh']:
        ca, cb = F[e['a']]['cum'], F[e['b']]['cum']
        CC[ca].append(e)
        if cb != ca: CC[cb].append(e)

    def ten_alert(f):
        if f['tool'] == 'zap' and f['raw_rule_id'] in ten_zap: return ten_zap[f['raw_rule_id']]
        return None

    def mo_ta_f(f):
        s = '<b>%s</b> %s' % (E(f['tool']), E(rule_ngan(f)))
        n = ten_alert(f)
        if n: s += ' <i>(%s; tên từ tệp quét thô)</i>' % E(n)
        s += ' · %s · %s' % (E(f['sev']), E(vi_tri(f)))
        s += ' · họ lỗi theo tệp: %s' % E(str(f.get('family')))
        if f.get('raw_cwe'): s += ' · %s' % E(', '.join(f['raw_cwe']))
        if f.get('muc_phoi_nhiem_tinh'): s += ' · <span class="m">%s</span>' % E(f['muc_phoi_nhiem_tinh'].split('_')[0])
        return s

    # ---- tóm tắt ----
    nhan_v1 = {k.split('|')[1]: v for k, v in R['canh_theo_nhan'].items() if k.startswith('V1|')}
    nhan_intra = {k.split('|')[1]: v for k, v in R['canh_theo_nhan'].items() if k.startswith('V1_intra|')}
    n_v1 = R['so_canh'].get('V1', 0); n_in = R['so_canh'].get('V1_intra', 0)
    n_canh = sum(R['so_canh'].values())
    tiles = [
        ('tong_phat_hien', nF, 'phát hiện', 'từ %s' % ', '.join('%s %d' % (k, v) for k, v in sorted(R['theo_cong_cu'].items()))),
        ('so_cum', R.get('so_cum', len({f['cum'] for f in R['phat_hien']})), 'cụm (vết)', 'mỗi phát hiện thuộc đúng một cụm'),
        ('cum_xuyen_pha', len(xp), 'cụm xuyên pha', 'có phát hiện ở ≥ 2 pha (Tier 1 = nhiều pha cùng thấy, không phải mức nghiêm trọng)'),
        ('phat_hien_trong_cum_xuyen_pha', n_trong, 'phát hiện trong cụm xuyên pha', 'còn %d phát hiện không nối được với pha khác' % (nF - n_trong)),
        ('tong_canh', n_canh, 'cạnh', 'V1 (mã↔động) %d · V1_intra (mã↔mã) %d' % (n_v1, n_in)),
        ('canh_bi_loai', R.get('so_canh_v1_loai', len(R.get('canh_loai_v1', []))), 'cạnh bị loại', 'ứng viên V1 không được giữ'),
        ('ham_hub', len(R['ham_hub']), 'hàm dùng chung (Hub)', 'không dùng để bắc cầu'),
    ]
    th = ''.join('<div class="tile" data-k="%s"><div class="n">%d</div><div class="l">%s</div><div class="s">%s</div></div>' % (k, v, E(l), E(s)) for k, v, l, s in tiles)
    nhan_rows = ''.join('<tr><td><span class="b %s">%s</span></td><td data-k="v1_%s">%d</td><td data-k="intra_%s">%d</td><td>%s</td></tr>' % (
        k, k, k, nhan_v1.get(k, 0), k, nhan_intra.get(k, 0), E(NHAN_GIAI[k])) for k in ('cung_loi', 'cung_tai_san', 'chua_ro_ho'))
    mrow = ''.join('<tr><td>%s</td><td data-k="%s">%d</td></tr>' % (E(M_TEN.get(k, k)), E(k.split('_')[0]), v) for k, v in sorted(R['muc_phoi_nhiem_tinh'].items()))

    # ---- sơ đồ pha ----
    pt = collections.defaultdict(collections.Counter)
    for f in R['phat_hien']: pt[f['phase']][f['tool']] += 1
    phases = PHA + sorted(p for p in pt if p not in PHA)
    prow = ''
    for p in phases:
        if p in pt:
            cells = ' · '.join('<b>%s</b> %d' % (E(t), n) for t, n in sorted(pt[p].items()))
            prow += '<tr><td><b>%s</b></td><td>%d</td><td>%s</td></tr>' % (p, sum(pt[p].values()), cells)
        else:
            prow += '<tr class="mute"><td>%s</td><td>0</td><td>không có phát hiện trong dữ liệu này</td></tr>' % p

    # ---- thẻ truy vết ----
    def uu_tien(c):
        es = CC.get(c['id'], [])
        return (-sum(1 for e in es if e['nhan'] == 'cung_loi'), c['id'])
    cards = ''
    for c in sorted(xp, key=uu_tien):
        mem = [f for f in R['phat_hien'] if f['cum'] == c['id']]
        code = sorted([f for f in mem if f['phase'] != 'TEST'], key=lambda f: f['finding_id'])
        dyn = sorted([f for f in mem if f['phase'] == 'TEST'], key=lambda f: f['finding_id'])
        es = CC.get(c['id'], []); dem = collections.Counter(e['nhan'] for e in es)
        manh = dem.get('cung_loi', 0) > 0
        route = sorted({f['anchors'].get('url_route') for f in dyn if f['anchors'].get('url_route')})
        tit = ' · '.join(route) if route else c['id']
        badge = ''.join('<span class="b %s">%s ×%d</span> ' % (k, k, dem[k]) for k in ('cung_loi', 'cung_tai_san', 'chua_ro_ho') if dem.get(k))
        note = '' if manh else '<div class="warn">Cụm này chỉ có liên kết gợi ý (không có cạnh cung_loi).</div>'
        lc = ''.join('<li>%s <span class="id">%s</span></li>' % (mo_ta_f(f), E(f['finding_id'])) for f in code)
        ld = ''.join('<li>%s <span class="id">%s</span></li>' % (mo_ta_f(f), E(f['finding_id'])) for f in dyn)
        eh = ''
        for k in ('cung_loi', 'cung_tai_san', 'chua_ro_ho'):
            ek = [e for e in es if e['nhan'] == k]
            if not ek: continue
            li = ''
            for e in ek:
                a, b = F[e['a']], F[e['b']]
                bc = ''.join('<div class="bc">%s</div>' % E(x) for x in e['bang_chung'])
                hop = (', hop %s' % e['hop']) if e.get('hop') is not None else ''
                li += '<li><span class="id">%s</span> %s ↔ <span class="id">%s</span> %s <span class="id">[%s%s]</span>%s</li>' % (
                    E(e['a']), E(vi_tri(a)), E(e['b']), E(vi_tri(b)), E(e['luat']), hop, bc)
            eh += '<details%s><summary><span class="b %s">%s</span> %d cạnh <span class="mute">- %s</span></summary><ul class="edges">%s</ul></details>' % (
                ' open' if (k == 'cung_loi' and len(ek) <= 6) else '', k, k, len(ek), E(NHAN_GIAI[k]), li)
        cards += ('<article class="card%s" data-cum="%s"><h3>%s</h3><div class="meta">cụm %s · Tier %s · %d phát hiện · công cụ: %s</div><div class="bd">%s</div>%s'
                  '<div class="cols"><div><h4>Pha mã nguồn / tĩnh (%d)</h4><ul>%s</ul></div><div><h4>Pha quét động (%d)</h4><ul>%s</ul></div></div>'
                  '<h4>Bằng chứng nối (nguyên văn từ tệp)</h4>%s</article>') % (
            '' if manh else ' weak', E(c['id']), E(tit), E(c['id']), c['tier'], c['so_phat_hien'], E(', '.join(c['cong_cu'])), badge, note, len(code), lc, len(dyn), ld, eh)

    # ---- bảng toàn bộ ----
    tools = sorted({f['tool'] for f in R['phat_hien']}); phs = sorted({f['phase'] for f in R['phat_hien']})
    ms = sorted({f.get('muc_phoi_nhiem_tinh') or '-' for f in R['phat_hien']})
    rows = ''
    for f in sorted(R['phat_hien'], key=lambda f: f['finding_id']):
        m = f.get('muc_phoi_nhiem_tinh') or '-'
        n = ten_alert(f); rl = rule_ngan(f) + (' (%s)' % n if n else '')
        txt = ' '.join([f['finding_id'], f['tool'], f['raw_rule_id'], vi_tri(f), str(f.get('family')), f['sev'], n or '']).lower()
        rows += '<tr data-tool="%s" data-pha="%s" data-tier="%s" data-m="%s" data-t="%s"><td class="id">%s</td><td>%s</td><td>%s</td><td title="%s">%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td class="id">%s</td></tr>' % (
            E(f['tool']), E(f['phase']), f['tier'], E(m), E(txt, quote=True), E(f['finding_id']), E(f['phase']), E(f['tool']), E(f['raw_rule_id']), E(rl), E(f['sev']), f['tier'], E(str(f.get('family'))), E(vi_tri(f)), E(m.split('_')[0] if m != '-' else '-'), E(f['cum']))
    opt = lambda xs: ''.join('<option>%s</option>' % E(x) for x in xs)

    # ---- cạnh bị loại + hub ----
    lo = ''.join('<tr><td class="id">%s</td><td class="id">%s</td><td>%s</td><td>%s</td></tr>' % (E(e['a']), E(e['b']), E(e['nhan']), E(e.get('ly_do_loai', ''))) for e in R.get('canh_loai_v1', []))
    hub = ''.join('<li>%s</li>' % E(h if isinstance(h, str) else json.dumps(h, ensure_ascii=False)) for h in R['ham_hub'])

    gh = ('<li><b>Liên kết theo endpoint.</b> Một cạnh nối cảnh báo trong mã với cảnh báo động khi dòng mã nằm trong hàm xử lý của route mà công cụ động đã gọi, và hai bên cùng họ lỗi (với cung_loi). Đây chưa chứng minh hai cảnh báo là cùng một điểm khai thác.</li>'
          '<li><b>M1–M4 và <code>da_lam_sach</code> là heuristic.</b> Mức phơi nhiễm tĩnh M1–M4 suy từ cấu trúc thư mục và route; <code>da_lam_sach</code> chỉ là gợi ý từ sanitizer_hint. Cả hai chưa có đáp án chuẩn và không phải kết luận về lỗi.</li>'
          '<li><b>Số liệu kiểm độc lập là trên cùng tập dữ liệu (in-sample).</b> Các phép đo độ đúng ở Bước 31 và 34 dùng chính ứng dụng đã dùng để thiết kế luật; không suy ra độ đúng trên ứng dụng khác. Số đo này là của lõi v2.1, không phải của lõi trong tệp đang xem: trên Juice Shop, cặp cung_loi đúng 11/12, còn cung_tai_san và chua_ro_ho chỉ khoảng 25–32%.</li>'
          '<li><b>Dữ liệu quét động là kết quả có sẵn.</b> Báo cáo này không chạy quét mới; các cảnh báo ở pha TEST đến từ tệp quét thô đã có.</li>'
          '<li>Họ lỗi (<code>family</code>) và CWE hiển thị đúng như trong tệp kết quả; báo cáo không tự gán loại lỗi cho cảnh báo mà tệp không có. Nhãn họ lỗi do lõi gán theo bảng cố định nên có thể không khớp tên cảnh báo của công cụ; khi cần, đối chiếu với tên cảnh báo gốc.</li>')

    page = PAGE.replace('@@TITLE@@', E('Báo cáo truy vết – %s' % app)).replace('@@APP@@', E(app)).replace('@@SRC@@', E(os.path.basename(ket_qua_file))).replace('@@VER@@', E(str(R.get('phien_ban')))) \
        .replace('@@TILES@@', th).replace('@@NHAN@@', nhan_rows).replace('@@M@@', mrow).replace('@@PHA@@', prow).replace('@@NXP@@', str(len(xp))) \
        .replace('@@CARDS@@', cards).replace('@@ROWS@@', rows).replace('@@NF@@', str(nF)).replace('@@OPT_TOOL@@', opt(tools)).replace('@@OPT_PHA@@', opt(phs)).replace('@@OPT_M@@', opt(ms)) \
        .replace('@@LOAI_N@@', str(len(R.get('canh_loai_v1', [])))).replace('@@LOAI@@', lo).replace('@@HUB_N@@', str(len(R['ham_hub']))).replace('@@HUB@@', hub).replace('@@GH@@', gh)
    os.makedirs(os.path.dirname(os.path.abspath(ra_html)), exist_ok=True)
    with open(ra_html, 'w', encoding='utf-8', newline='\n') as fh: fh.write(page)
    return {'tep': ra_html, 'kich_thuoc_byte': os.path.getsize(ra_html), 'so_phat_hien': nF, 'so_the_vet': len(xp), 'so_canh': n_canh, 'ten_zap_tra_tu_tep_tho': len(ten_zap), 'ban_loi': R.get('phien_ban')}


PAGE = '''<!doctype html><html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>@@TITLE@@</title><style>
:root{--bg:#fff;--fg:#1d2330;--mu:#667085;--bd:#d9dee7;--pn:#f5f7fa;--ac:#1f6feb;--ok:#1a7f4b;--wk:#9a6700}
@media (prefers-color-scheme:dark){:root{--bg:#10141c;--fg:#e6eaf2;--mu:#98a2b3;--bd:#2a3342;--pn:#171d28;--ac:#6ea8fe;--ok:#4cc38a;--wk:#e0b04a}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 "Segoe UI",system-ui,Arial,sans-serif}
.w{max-width:1200px;margin:0 auto;padding:20px 16px 60px}h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:34px 0 10px;padding-bottom:6px;border-bottom:1px solid var(--bd)}h3{font-size:16px;margin:0 0 2px;word-break:break-all}h4{font-size:13px;margin:12px 0 4px;color:var(--mu);text-transform:uppercase;letter-spacing:.03em}
.sub{color:var(--mu);margin:0 0 14px}.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px}.tile{background:var(--pn);border:1px solid var(--bd);border-radius:8px;padding:10px 12px}.tile .n{font-size:26px;font-weight:700}.tile .l{font-weight:600}.tile .s{color:var(--mu);font-size:12px}
table{border-collapse:collapse;width:100%}th,td{border:1px solid var(--bd);padding:4px 7px;text-align:left;vertical-align:top;font-size:13px}th{background:var(--pn);position:sticky;top:0}tr.mute td,.mute{color:var(--mu)}
.two{display:grid;grid-template-columns:1fr 1fr;gap:16px}@media(max-width:800px){.two,.cols{grid-template-columns:1fr!important}}
.b{display:inline-block;border-radius:10px;padding:0 8px;font-size:12px;font-weight:600;border:1px solid var(--bd)}.b.cung_loi{background:var(--ok);color:#fff;border-color:var(--ok)}.b.cung_tai_san,.b.chua_ro_ho{background:transparent;color:var(--wk);border-color:var(--wk)}
.card{border:1px solid var(--bd);border-left:5px solid var(--ok);border-radius:8px;padding:12px 14px;margin:14px 0;background:var(--pn)}.card.weak{border-left-color:var(--wk);opacity:.92}.meta{color:var(--mu);font-size:12px}.warn{color:var(--wk);margin:6px 0;font-weight:600}
.cols{display:grid;grid-template-columns:1fr 1fr;gap:16px}ul{margin:4px 0;padding-left:18px}li{margin:2px 0}.id{font-family:Consolas,monospace;font-size:12px;color:var(--mu)}.bc{font-family:Consolas,monospace;font-size:12px;color:var(--mu);margin-left:14px}.m{font-size:11px;border:1px solid var(--bd);border-radius:4px;padding:0 4px}
details{margin:6px 0}summary{cursor:pointer}ul.edges{list-style:none;padding-left:6px}.bar{display:flex;gap:8px;flex-wrap:wrap;margin:8px 0}.bar input,.bar select{padding:5px 8px;border:1px solid var(--bd);border-radius:6px;background:var(--bg);color:var(--fg)}.bar input{min-width:240px}
.tw{max-height:560px;overflow:auto;border:1px solid var(--bd)}th.s{cursor:pointer}code{font-family:Consolas,monospace;font-size:12px}
@media print{.bar,.tw{max-height:none}.card{break-inside:avoid}}
</style></head><body><div class="w">
<h1>Báo cáo truy vết xuyên pha – @@APP@@</h1>
<p class="sub">Sinh tự động từ tệp <code>@@SRC@@</code> (lõi truy vết @@VER@@) bằng quy tắc cố định, không dùng AI. Một tệp, xem ngoại tuyến.</p>
<h2>1. Tóm tắt</h2><div class="tiles">@@TILES@@</div>
<div class="two"><div><h4>Cạnh V1 theo nhãn</h4><table><tr><th>Nhãn</th><th>V1</th><th>V1_intra</th><th>Nghĩa</th></tr>@@NHAN@@</table></div>
<div><h4>Mức phơi nhiễm tĩnh của phát hiện mã (heuristic)</h4><table><tr><th>Mức</th><th>Số phát hiện</th></tr>@@M@@</table></div></div>
<h2>2. Phát hiện theo pha DevOps và công cụ</h2><table><tr><th>Pha</th><th>Số phát hiện</th><th>Công cụ</th></tr>@@PHA@@</table>
<h2>3. Các vết đã nối xuyên pha (@@NXP@@ cụm)</h2><p class="sub">Mỗi thẻ là một cụm có phát hiện ở ít nhất hai pha. Sắp theo số cạnh cung_loi giảm dần; thẻ viền cam chỉ có liên kết gợi ý. <b>Cùng một cụm không có nghĩa là cùng một lỗi:</b> chỉ cạnh cung_loi là liên kết mạnh; cung_tai_san và chua_ro_ho chỉ là gợi ý cùng endpoint hoặc hàm (xem mục 6).</p>@@CARDS@@
<h2>4. Toàn bộ phát hiện (@@NF@@)</h2>
<div class="bar"><input id="q" type="search" placeholder="Tìm: id, công cụ, luật, tệp, đường dẫn…"><select id="fTool"><option value="">Mọi công cụ</option>@@OPT_TOOL@@</select><select id="fPha"><option value="">Mọi pha</option>@@OPT_PHA@@</select><select id="fTier"><option value="">Mọi tier</option><option>1</option><option>2</option><option>3</option></select><select id="fM"><option value="">Mọi mức phơi nhiễm</option>@@OPT_M@@</select><span id="cnt" class="mute"></span></div>
<div class="tw"><table id="tb"><thead><tr><th class="s">ID</th><th class="s">Pha</th><th class="s">Công cụ</th><th class="s">Luật</th><th class="s">Mức nặng</th><th class="s">Tier</th><th class="s">Họ lỗi (tệp)</th><th class="s">Vị trí</th><th class="s">Phơi nhiễm</th><th class="s">Cụm</th></tr></thead><tbody>@@ROWS@@</tbody></table></div>
<h2>5. Cạnh bị loại và hàm dùng chung</h2>
<details><summary>@@LOAI_N@@ cạnh V1 ứng viên bị loại (kèm lý do của hệ thống)</summary><div class="tw"><table><tr><th>Mã</th><th>Động</th><th>Nhãn</th><th>Lý do loại</th></tr>@@LOAI@@</table></div></details>
<details><summary>@@HUB_N@@ hàm Hub (dùng chung nhiều endpoint, không dùng để bắc cầu)</summary><ul>@@HUB@@</ul></details>
<h2>6. Giới hạn cần đọc trước khi dùng kết quả</h2><ul>@@GH@@</ul>
</div><script>
(function(){var $=function(i){return document.getElementById(i)},rows=[].slice.call(document.querySelectorAll('#tb tbody tr'));
function ap(){var q=$('q').value.toLowerCase().trim(),t=$('fTool').value,p=$('fPha').value,r=$('fTier').value,m=$('fM').value,n=0;
rows.forEach(function(x){var ok=(!q||x.getAttribute('data-t').indexOf(q)>=0)&&(!t||x.getAttribute('data-tool')===t)&&(!p||x.getAttribute('data-pha')===p)&&(!r||x.getAttribute('data-tier')===r)&&(!m||x.getAttribute('data-m')===m);x.style.display=ok?'':'none';if(ok)n++});
$('cnt').textContent=n+' / '+rows.length+' dòng'}
['q','fTool','fPha','fTier','fM'].forEach(function(i){$(i).addEventListener('input',ap);$(i).addEventListener('change',ap)});
[].slice.call(document.querySelectorAll('#tb th')).forEach(function(th,c){var d=1;th.addEventListener('click',function(){var tb=document.querySelector('#tb tbody');rows.sort(function(a,b){var x=a.children[c].textContent,y=b.children[c].textContent,nx=parseFloat(x),ny=parseFloat(y);return d*((isNaN(nx)||isNaN(ny))?x.localeCompare(y):nx-ny)});d=-d;rows.forEach(function(r){tb.appendChild(r)})})});
ap()})();
</script></body></html>'''
