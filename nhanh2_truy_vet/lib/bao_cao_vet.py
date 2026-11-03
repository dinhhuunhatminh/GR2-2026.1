# -*- coding: utf-8 -*-
"""Sinh báo cáo HTML vết truy vết (ma trận đặc trưng, sơ đồ luồng, thẻ vết, vết đứt). Chỉ ĐỌC dữ liệu, không đổi kết quả."""
import json, html, collections


def sinh(TV, OUT, CHAM=None, GTP=None):
    R = json.load(open(TV, encoding='utf-8')); C = json.load(open(CHAM, encoding='utf-8')) if CHAM and GTP else None
    F = {f['finding_id']: f for f in R['phat_hien']}; E = R['canh']
    PH = ['CODE', 'BUILD', 'RELEASE', 'DEPLOY', 'TEST', 'OPERATE']
    FEAT = [('file_path', 'file+dòng'), ('url_route', 'route'), ('family', 'họ CWE'), ('package_name', 'gói'), ('cve_id', 'CVE'), ('container_target', 'image/dịch vụ'), ('cis_control_class', 'lớp điều khiển'), ('sens_file', 'tệp nhạy cảm')]
    e = html.escape
    def has(f, k): return bool(f.get(k)) and f.get(k) != 'khac' if k == 'family' else bool(f['anchors'].get(k))
    def evidence(a, b):
        out = []
        for k, n in FEAT:
            if k == 'family':
                if a['family'] == b['family'] and a['family'] != 'khac': out.append('họ CWE = ' + a['family'])
                rc = sorted(set(a.get('routes') or []) & set(b.get('routes') or []))  # v1.5: route chung (L1)
                if rc: out.append('route = ' + ', '.join(rc)[:40])
            else:
                x, y = a['anchors'].get(k), b['anchors'].get(k)
                if x and y and x == y: out.append(n + ' = ' + str(x).split('/')[-1][:40])
        return out
    # --- 1. ma trận ---
    tools = collections.OrderedDict()
    for f in R['phat_hien']: tools.setdefault((f['phase'], f['tool']), []).append(f)
    rows = ''
    for (ph, t), fs in sorted(tools.items(), key=lambda x: (PH.index(x[0][0]), x[0][1])):
        cells = ''
        for k, n in FEAT:
            c = sum(1 for f in fs if has(f, k)); p = c / len(fs)
            bg = 'rgba(39,174,96,%.2f)' % (0.15 + 0.7 * p) if c else '#fafafa'
            cells += '<td style="background:%s;text-align:center">%s</td>' % (bg, ('%d' % c) if c else '–')
        rows += '<tr><td>%s</td><td><b>%s</b></td><td style="text-align:right">%d</td>%s</tr>' % (ph, t, len(fs), cells)
    matrix = '<table><tr><th>Pha</th><th>Công cụ</th><th>Số phát hiện</th>%s</tr>%s</table>' % (''.join('<th>%s</th>' % n for _, n in FEAT), rows)
    # --- 2. sơ đồ luồng ---
    byph = collections.OrderedDict((p, collections.Counter()) for p in PH)
    for (ph, t), fs in tools.items(): byph[ph][t] += len(fs)
    svg = ['<svg viewBox="0 0 1000 330" width="100%" style="max-width:1000px">']
    X = {p: 20 + i * 160 for i, p in enumerate(PH)}
    for p in PH:
        svg.append('<rect x="%d" y="10" width="140" height="32" rx="6" fill="#34495e"/><text x="%d" y="31" fill="#fff" font-size="14" text-anchor="middle">%s</text>' % (X[p], X[p] + 70, p))
        y = 52
        for t, n in byph[p].items():
            svg.append('<rect x="%d" y="%d" width="140" height="24" rx="4" fill="#ecf0f1" stroke="#bbb"/><text x="%d" y="%d" font-size="12" text-anchor="middle">%s (%d)</text>' % (X[p], y, X[p] + 70, y + 16, t, n)); y += 30
        if not byph[p]: svg.append('<text x="%d" y="70" font-size="12" fill="#c0392b" text-anchor="middle">không có công cụ</text>' % (X[p] + 70))
    cnt = collections.Counter()
    for ed in E:
        a, b = F[ed['a']], F[ed['b']]; cnt[(ed['luat'], tuple(sorted((a['phase'], b['phase']))))] += 1
    yy = 255
    svg.append('<text x="20" y="235" font-size="13" font-weight="bold">Cạnh nối giữa các pha (số cạnh theo luật):</text>')
    for (l, (p1, p2)), n in sorted(cnt.items()):
        svg.append('<text x="20" y="%d" font-size="12">%s: %s ↔ %s = %d cạnh</text>' % (yy, l, p1, p2, n)); yy += 15
        if yy > 325: break
    svg.append('</svg>')
    flow = ''.join(svg)
    # --- 3. thẻ vết ---
    def card(title, nodes, links, verdict, cls):
        rowsn = collections.Counter(n[0] for n in nodes); H = 40 + 66 * max(rowsn.values()) + 30
        s = ['<svg viewBox="0 0 1000 %d" width="100%%" style="max-width:1000px">' % H]
        for p in PH:
            s.append('<rect x="%d" y="4" width="140" height="22" fill="#34495e" rx="4"/><text x="%d" y="20" fill="#fff" font-size="12" text-anchor="middle">%s</text>' % (X[p], X[p] + 70, p))
        pos = {}
        for i, nd in enumerate(nodes):
            ph, tool, lab = nd[:3]
            y = 40 + 66 * sum(1 for q in nodes[:i] if q[0] == ph); pos[i] = (ph, y)
            s.append('<rect x="%d" y="%d" width="140" height="56" rx="6" fill="#fff" stroke="#2c3e50"/><text x="%d" y="%d" font-size="12" font-weight="bold" text-anchor="middle">%s</text><text x="%d" y="%d" font-size="10" text-anchor="middle" fill="#555">%s</text>' % (X[ph], y, X[ph] + 70, y + 18, e(tool), X[ph] + 70, y + 34, e(lab[:24])))
            if len(nd) > 3 and nd[3]: s.append('<text x="%d" y="%d" font-size="10" text-anchor="middle" fill="#1d4ed8">%s</text>' % (X[ph] + 70, y + 49, e(str(nd[3])[:26])))
        for (i, j, lab, ok) in links:
            (p1, y1), (p2, y2) = pos[i], pos[j]; col = '#27ae60' if ok else '#c0392b'; da = '' if ok else '8 5'
            if p1 == p2:
                x = X[p1] + 70; s.append('<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="%s" stroke-width="3" stroke-dasharray="%s"/><text x="%d" y="%d" font-size="11" fill="%s">%s</text>' % (x, y1 + 56, x, y2, col, da, X[p1] + 150, y1 + 62, col, e(lab[:70])))
            else:
                if PH.index(p1) > PH.index(p2): p1, p2, y1, y2 = p2, p1, y2, y1
                xa, xb = X[p1] + 140, X[p2]; ya, yb = y1 + 28, y2 + 28
                s.append('<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="%s" stroke-width="3" stroke-dasharray="%s"/><text x="%d" y="%d" font-size="11" fill="%s" text-anchor="middle">%s</text>' % (xa, ya, xb, yb, col, da, (xa + xb) / 2, (max(ya, yb) + 38) if xb - xa < 30 else min(ya, yb) - 6, col, e(lab[:70])))
        s.append('</svg>')
        return '<div class="trace %s"><h3>%s</h3>%s<p>%s</p></div>' % (cls, e(title), ''.join(s), verdict)
    def node(f): return (f['phase'], f['tool'], (f['anchors']['package_name'] or (('CIS ' + f['raw_rule_id']) if f['tool'] == 'docker_bench' else f['raw_rule_id'].split('.')[-1]) or '')[:30])
    cards = []
    # v1.5: L1 — lỗi trong mã được quét động xác nhận (thẻ quan trọng nhất, đặt đầu)
    def vitri(f):
        a = f['anchors']
        if a.get('file_path') and a.get('line_start'): return a['file_path'].replace('\\', '/').split('/')[-1] + ':' + str(a['line_start'])
        return a.get('url_route') or ''
    l1c = collections.OrderedDict()
    for ed in E:
        if ed['luat'] != 'L1': continue
        a, b = F[ed['a']], F[ed['b']]; ma, dg = (a, b) if a['phase'] == 'CODE' else (b, a)
        l1c.setdefault(ma['cum'], []).append((ma, dg))
    for k, pairs in list(l1c.items())[:3]:
        ms, ds = [], []
        for ma, dg in pairs:
            if all(m['finding_id'] != ma['finding_id'] for m in ms): ms.append(ma)
            if all(d['raw_rule_id'] != dg['raw_rule_id'] for d in ds): ds.append(dg)
        ms, ds = ms[:3], ds[:3]
        nodes = [node(m) + (vitri(m),) for m in ms] + [node(d) + (vitri(d),) for d in ds]
        links = [(i, len(ms) + j, '; '.join(evidence(ms[i], ds[j])), True) for i in range(len(ms)) for j in range(len(ds)) if (i == 0 or j == 0)]
        rc = sorted(set(ms[0].get('routes') or []) & set(ds[0].get('routes') or []))
        cards.append(card('Vết L1 – lỗi trong mã được xác nhận khi chạy thật (route %s)' % ', '.join(rc), nodes, links,
            '<b>%s</b> thấy lỗi <b>%s</b> trong mã ở <code>%s</code> (pha CODE). Khi ứng dụng chạy, <b>%s</b> gửi tấn công thật vào route <code>%s</code> và xác nhận lỗi cùng loại (pha TEST). '
            'Hai đầu nối vì <b>cùng route</b> (route của mã suy từ bản đồ route) và <b>cùng họ lỗi</b>. Cụm này có %d cạnh L1. Luật không đọc nội dung lỗi: cần người xem xác nhận đây là cùng một lỗi.'
            % (e(ms[0]['tool']), e(ms[0]['family']), e(vitri(ms[0])), e(ds[0]['tool']), e(', '.join(rc)), len(pairs)), 'ok'))
    # L3 đúng
    l3 = [ed for ed in E if ed['luat'] == 'L3']
    if l3:
        ed = l3[0]; a, b = F[ed['a']], F[ed['b']]
        cards.append(card('Vết L3 – lỗ hổng thư viện đi từ BUILD sang RELEASE', [node(a), node(b)], [(0, 1, 'khớp: ' + '; '.join(evidence(a, b)), True)],
            'Đặc trưng nối: <b>CVE + gói</b>: cùng một thư viện có lỗ hổng thấy ở mã nguồn (BUILD) và còn trong image đã đóng gói (RELEASE). Từ v1.2 chỉ nối khi cùng dịch vụ. Đây là loại vết dễ nối nhất nhưng ít giá trị nhất.', 'ok'))
    # L2 đúng / sai
    l2 = [ed for ed in E if ed['luat'] == 'L2']
    for ed in l2:
        a, b = F[ed['a']], F[ed['b']]; d = a if a['tool'] == 'dockle' else b; o = b if d is a else a
        okk = 'crapi-web' in (d['anchors']['container_target'] or '') if C else None
        if okk is None:
            if sum(1 for c in cards if 'L2 (chưa kiểm' in c) < 2: cards.append(card('Vết L2 (chưa kiểm đúng/sai) – tệp nhạy cảm đi qua các pha', [node(d), node(o)], [(0, 1, 'khớp: ' + '; '.join(evidence(d, o)), True)], 'Cạnh L2 nối theo tên tệp. <b>Hãy kiểm thủ công hai đầu có cùng dịch vụ không</b> (bài học crAPI: 3/6 cạnh L2 nối nhầm dịch vụ).', 'warn'))
            continue
        if okk and sum(1 for c in cards if 'L2 đúng' in c) == 0:
            cards.append(card('Vết L2 đúng – lộ tệp .env của crapi-web', [node(d), node(o)], [(0, 1, 'khớp: tệp nhạy cảm .env', True)], 'dockle thấy .env trong image web (RELEASE), nuclei/ZAP thật sự truy cập được <code>/.env</code> trên web (TEST). Cùng dịch vụ nên <b>đúng</b>.', 'ok'))
        if okk is False and sum(1 for c in cards if 'L2 sai' in c) == 0:
            cards.append(card('Vết L2 sai – .env của workshop bị nối nhầm với web', [node(d), node(o)], [(0, 1, 'khớp tên .env nhưng KHÁC dịch vụ', False)], 'dockle thấy <code>app/.env</code> trong image <b>workshop</b>, nhưng kết quả nuclei/ZAP là của <b>web</b>. Nối chỉ vì trùng tên tệp. Cách sửa đề xuất: thêm điều kiện cùng dịch vụ.', 'bad'))
    # #13
    l0 = [ed for ed in E if ed['luat'] == 'L0']
    if l0:
        a, b = F[l0[0]['a']], F[l0[0]['b']]
        cards.append(card('Vết L0 – hai công cụ cùng thấy một lỗi ở mã (cùng pha)', [node(a), node(b), ('TEST', '(không có)', 'không thấy route')], [(0, 1, 'khớp: ' + '; '.join(evidence(a, b)), True), (0, 2, 'đứt: chưa có quét động cùng route + họ lỗi', False)],
            'Hai công cụ CODE cùng thấy lỗi → Tier 2. Nếu chưa có quét động (hoặc quét không đăng nhập) thì không nối được sang TEST: đây là <b>vết đứt</b>.', 'warn'))
    # L4
    l4 = [ed for ed in E if ed['luat'] == 'L4']
    if l4:
        a, b = F[l4[0]['a']], F[l4[0]['b']]
        cards.append(card('Vết L4 – lỗi cấu hình hạ tầng thấy cả ở container đang chạy', [node(a), node(b)], [(0, 1, 'khớp: lớp điều khiển ' + str(a['anchors']['cis_control_class']), True)], 'kics thấy lỗi cấu hình trong tệp hạ tầng (<code>%s</code>), docker_bench thấy cùng lớp điều khiển trên container đang chạy (<code>%s</code>).' % (e(str(a['anchors'].get('file_path') or b['anchors'].get('file_path') or '?').split('/')[-1]), e(str(b['anchors'].get('container_target') or a['anchors'].get('container_target') or '?'))), 'ok'))
    # --- 4. vết đứt ---
    G = {g['id']: g for g in json.load(open(GTP))['thu_thach']} if C else {}
    rows2 = ''
    for i in (range(1, 16) if C else []):
        d = C['chi_tiet'][str(i)]; g = G[i]
        if not d['lo']: why, cl = 'Không công cụ nào (CODE lẫn TEST) chạm tới; đây là lỗi logic/phân quyền, luật mẫu không có.', 'bad'
        elif i == 4: why, cl = 'Chỉ nuclei command-injection (nghi dương tính giả), CODE không thấy.', 'bad'
        elif i == 13: why, cl = 'CODE thấy đúng (2 công cụ); TEST không chạm vì chưa đăng nhập. Đứt ở cầu CODE→TEST.', 'warn'
        else: why, cl = 'CODE chạm đúng file nhưng sai loại lỗi (chứng chỉ TLS, timeout), không phải lỗi thật.', 'warn'
        rows2 += '<tr class="%s"><td>%d</td><td>%s</td><td>%s</td><td>%s</td></tr>' % (cl, i, e(g['route']), e(', '.join(t + ':' + r for t, r in d['lo'][:3]) or '–'), why)
    page = '''<!doctype html><html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Vết truy vết</title><style>
    body{font-family:Segoe UI,Arial,sans-serif;max-width:1020px;margin:24px auto;padding:0 16px;color:#222;line-height:1.5}h2{border-bottom:2px solid #ddd;margin-top:34px}
    table{border-collapse:collapse;width:100%%;margin:10px 0}td,th{border:1px solid #ccc;padding:5px 7px;font-size:13px}th{background:#eee}
    .trace{border:1px solid #ccc;border-radius:8px;padding:6px 14px;margin:16px 0}.ok{border-left:6px solid #27ae60}.bad{border-left:6px solid #c0392b}.warn{border-left:6px solid #e69500}
    tr.bad td{background:#fdecea}tr.warn td{background:#fff6e5}code{background:#eee;padding:1px 4px}.box{background:#f5f5f5;padding:10px 14px;border-left:5px solid #888}</style></head><body>
    <h1>Nhìn thấy vết truy vết</h1>
    <div class="box">Trang này chỉ <b>đọc</b> kết quả đã chấm, không đổi số liệu. "Bằng chứng nối" của mỗi cạnh được suy ra bằng cách so các đặc trưng (neo) của hai đầu cạnh.</div>
    <h2>1. Công cụ nào, ở pha nào, rút ra đặc trưng gì</h2>
    <p>Ô xanh càng đậm = càng nhiều phát hiện của công cụ đó có đặc trưng ấy; "–" = công cụ không cung cấp đặc trưng này. Hai công cụ chỉ nối được khi <b>cùng có một đặc trưng</b> (ví dụ CODE↔TEST cần route; BUILD↔RELEASE cần gói+CVE).</p>%s
    <h2>2. Sơ đồ: 6 pha, công cụ và cạnh nối</h2>%s
    <h2>3. Thẻ vết cụ thể (xanh = nối đúng, đỏ nét đứt = nối sai hoặc đứt)</h2>%s
    %s
    <h2>5. Cách tổng hợp sau khi chạy hết các pha</h2>
    <ol><li>Mỗi phát hiện chuẩn hóa thành một bản ghi có neo: file+dòng, route, họ CWE, gói+CVE, image, lớp điều khiển, tệp nhạy cảm.</li><li>Luật L0–L4 so neo từng cặp; cạnh nào khớp thì ghi bằng chứng.</li><li>Các cạnh gom thành cụm = một vết.</li><li>Tier 1 nếu vết qua ≥2 pha; Tier 2 nếu ≥2 công cụ cùng pha; Tier 3 nếu chỉ một công cụ.</li></ol>
    <p>Tổng: %d phát hiện, %d cạnh, Tier 1/2/3 = %s.</p></body></html>''' % (matrix, flow, ''.join(cards), ('<h2>4. 15 thử thách: vết đứt ở đâu</h2><table><tr><th>#</th><th>Route</th><th>Công cụ chạm</th><th>Đứt vì</th></tr>%s</table>' % rows2) if C else '<h2>4. Vết đứt</h2><p>Không có đáp án chuẩn nên không đánh giá vết đứt (người dùng MCP thường không có đáp án).</p>', R['tong_phat_hien'], sum(R['so_canh'].values()), '/'.join(str(R['tier_theo_phat_hien'].get(k, 0)) for k in ('1', '2', '3')))
    open(OUT, 'w', encoding='utf-8').write(page); return {'so_the_vet': len(cards), 'tep': OUT, 'co_phan_vet_dut': bool(C)}
