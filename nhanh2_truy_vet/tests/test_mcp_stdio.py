# -*- coding: utf-8 -*-
"""Kiểm thử hồi quy + hợp đồng, gọi server QUA GIAO THỨC MCP (stdio) như một client thật.
Chạy: python tests/test_mcp_stdio.py   (không cần Docker)"""
import asyncio, hashlib, json, os, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE); B23 = os.path.dirname(ROOT)
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
KQ = []


def kt(ten, ok, ghi=''):
    KQ.append((ten, ok, ghi)); print(('PASS ' if ok else 'FAIL ') + ten + (' - ' + str(ghi) if ghi else ''))


async def goi(S, ten, **a):
    r = await S.call_tool(ten, a)
    if r.isError: return {'__loi__': r.content[0].text if r.content else ''}
    return json.loads(r.content[0].text) if r.content else {}


async def chay_tv(S, **a):
    r = await goi(S, 'truy_vet', **a)
    if '__loi__' in r or 'job_id' not in r: return r
    for _ in range(600):
        st = await goi(S, 'trang_thai_job', job_id=r['job_id'])
        if st.get('trang_thai') == 'xong': return st['ket_qua']
        await asyncio.sleep(1)
    return {'loi': 'quá hạn chờ'}


async def main():
    env = dict(os.environ); env['VSECOPS_ALLOWED_ROOTS'] = B23 + os.pathsep + tempfile.gettempdir()
    p = StdioServerParameters(command=sys.executable, args=[os.path.join(ROOT, 'server.py')], env=env)
    tmp = tempfile.mkdtemp(); out = os.path.join(tmp, 'tv.json')
    async with stdio_client(p) as (r, w):
        async with ClientSession(r, w) as S:
            await S.initialize()
            tools = {t.name for t in (await S.list_tools()).tools}
            kt('T1 đủ 7 công cụ', tools >= {'phien_ban', 'kiem_tra_moi_truong', 'chay_quet_tinh', 'trang_thai_job', 'truy_vet', 'xem_vet', 'bao_cao_vet', 'xep_hang_loi'}, sorted(tools))
            v = await goi(S, 'phien_ban')
            goc = hashlib.sha256(open(os.path.join(B23, 'b23_3_truy_vet.py'), 'rb').read()).hexdigest()[:16]
            kt('T2 bản gốc đã chấm bước 23 còn nguyên (sha256)', v.get('sha256_ban_goc_da_cham_b23') == goc, goc)
            tv = await chay_tv(S, quet_tho_dir=os.path.join(B23, 'quet_tho'), ra_file=out, rang_buoc_dich_vu=False, route_map=os.path.join(HERE, 'route_map_crapi.json'))
            ref = json.load(open(os.path.join(B23, 'truy_vet_day_du_6_pha.json'), encoding='utf-8'))
            kt('T3 hồi quy: tổng phát hiện', tv.get('tong_phat_hien') == ref['tong_phat_hien'], tv.get('tong_phat_hien'))
            kt('T4 hồi quy: số cạnh theo luật', tv.get('so_canh') == ref['so_canh'], tv.get('so_canh'))
            kt('T5 hồi quy: tier', {str(k): v for k, v in tv.get('tier_theo_phat_hien', {}).items()} == {str(k): v for k, v in ref['tier_theo_phat_hien'].items()}, tv.get('tier_theo_phat_hien'))
            new = json.load(open(out, encoding='utf-8'))
            kt('T6 hồi quy: tập cạnh y hệt', sorted((e['a'], e['b'], e['luat']) for e in new['canh']) == sorted((e['a'], e['b'], e['luat']) for e in ref['canh']))
            kt('T7 hồi quy: tái lập (chạy 2 lần cùng kết quả)', True if (await chay_tv(S, quet_tho_dir=os.path.join(B23, 'quet_tho'), ra_file=out + '2.json', rang_buoc_dich_vu=False, route_map=os.path.join(HERE, 'route_map_crapi.json'))).get('so_canh') == tv['so_canh'] else False)
            t12 = await chay_tv(S, quet_tho_dir=os.path.join(B23, 'quet_tho'), ra_file=out + '_v12.json', route_map=os.path.join(HERE, 'route_map_crapi.json'))
            n12 = json.load(open(out + '_v12.json', encoding='utf-8'))
            E11 = {(e['a'], e['b'], e['luat']) for e in new['canh']}; E12 = {(e['a'], e['b'], e['luat']) for e in n12['canh']}
            kt('T17 v1.2 (mặc định): tập cạnh là TẬP CON của v1.1, chỉ mất cạnh L2/L3, L0/L1/L4 giữ nguyên', E12 <= E11 and all(e[2] in ('L2', 'L3') for e in E11 - E12) and {e for e in E11 if e[2] in ('L0', 'L1', 'L4')} == {e for e in E12 if e[2] in ('L0', 'L1', 'L4')}, (t12.get('so_canh'), len(E11 - E12)))
            FI = {f['finding_id']: f for f in n12['phat_hien']}
            kt('T18 v1.2: mọi cạnh L2/L3 còn lại đều có dịch vụ chung', all(set(FI[e[0]]['svc']) & set(FI[e[1]]['svc']) for e in E12 if e[2] in ('L2', 'L3')), 'L2/L3 còn %d/%d' % (sum(1 for e in E12 if e[2] in ('L2', 'L3')), sum(1 for e in E11 if e[2] in ('L2', 'L3'))))
            x = await goi(S, 'xem_vet', ket_qua_file=out, tier=2)
            kt('T8 xem_vet tier 2 trả vết có bằng chứng', x.get('tong_cum_khop', 0) >= 1 and x['cum'][0]['canh'][0]['bang_chung'], x.get('cum', [{}])[0].get('canh'))
            x = await goi(S, 'xem_vet', ket_qua_file=out, tier=1, limit=1000)
            kt('T9 phân trang: limit bị chặn ≤ 50', len(x.get('cum', [])) <= 50, len(x.get('cum', [])))
            h = await goi(S, 'bao_cao_vet', ket_qua_file=out, ra_html=os.path.join(tmp, 'b.html'))
            kt('T10 bao_cao_vet sinh HTML', os.path.exists(os.path.join(tmp, 'b.html')) and h.get('so_the_vet', 0) >= 3, h)
            xh = await goi(S, 'xep_hang_loi', ket_qua_file=out, top=10, ra_html=os.path.join(tmp, 'xh.html'))
            xh2 = await goi(S, 'xep_hang_loi', ket_qua_file=out, top=10)
            kt('T16 xep_hang_loi: có sev, thứ tự ổn định (2 lần giống nhau), mức nặng giảm dần ở top', xh.get('so_nhom', 0) > 100 and xh['top'] == xh2['top'] and all(a >= b for a, b in zip([{'Critical': 5, 'High': 4, 'Medium': 3, 'Low': 2, 'Info': 1}[x['muc_nang']] for x in xh['top']], [{'Critical': 5, 'High': 4, 'Medium': 3, 'Low': 2, 'Info': 1}[x['muc_nang']] for x in xh['top']][1:])) and os.path.exists(os.path.join(tmp, 'xh.html')), xh.get('so_nhom'))
            xl = await goi(S, 'xep_hang_loi', ket_qua_file=out, top=5, theo_loai=True, ra_html=os.path.join(tmp, 'xl.html'))
            lo = xl.get('loai', {})
            kt('T19 xep_hang_loi theo_loai: các loại cộng lại đúng tổng số nhóm, hạng trong loại tăng dần từ 1, giữ thứ tự bảng chung, có HTML', bool(lo) and sum(v['so_nhom'] for v in lo.values()) == xl['so_nhom'] == xh['so_nhom'] and all([t['hang_trong_loai'] for t in v['top']] == list(range(1, len(v['top']) + 1)) and [t['hang_chung'] for t in v['top']] == sorted(t['hang_chung'] for t in v['top']) for v in lo.values()) and os.path.exists(os.path.join(tmp, 'xl.html')), {k: v['so_nhom'] for k, v in lo.items()})
            # an toàn / lỗi
            e1 = await goi(S, 'truy_vet', quet_tho_dir='/etc', ra_file=os.path.join(tmp, 'z.json'))
            kt('T11 chặn đường dẫn ngoài vùng cho phép', '__loi__' in e1 and 'ngoài vùng' in e1['__loi__'], str(e1)[:80])
            em = os.path.join(tmp, 'rong'); os.makedirs(em)
            e2 = await chay_tv(S, quet_tho_dir=em, ra_file=os.path.join(tmp, 'e.json'))
            kt('T12 thư mục rỗng: không đổ vỡ, báo thiếu công cụ', e2.get('tong_phat_hien') == 0 and len(e2.get('cong_cu_thieu', [])) >= 5, e2.get('cong_cu_thieu'))
            bad = os.path.join(tmp, 'hong'); os.makedirs(bad); open(os.path.join(bad, 'bandit.json'), 'w').write('{không phải json')
            e3 = await chay_tv(S, quet_tho_dir=bad, ra_file=os.path.join(tmp, 'h.json'))
            kt('T13 tệp JSON hỏng: báo lỗi rõ, không treo', 'loi' in e3 or '__loi__' in e3, str(e3)[:100])
            d = await goi(S, 'chay_quet_tinh', repo_path=B23, ra_dir=os.path.join(tmp, 'q'), images=['crapi/crapi-web:latest'])
            j = await goi(S, 'truy_vet', quet_tho_dir=os.path.join(B23, 'quet_tho'), ra_file=os.path.join(tmp, 'n.json'), route_map=os.path.join(HERE, 'route_map_crapi.json'))
            kt('T15 truy_vet trả job_id NGAY (không chờ tính xong)', 'job_id' in j and not os.path.exists(os.path.join(tmp, 'n.json.meta.json')), j.get('job_id'))
            kt('T14 chay_quet_tinh mặc định chỉ lập kế hoạch (không chạy)', d.get('che_do', '').startswith('ke_hoach') and d.get('so_buoc', 0) >= 5 and not os.path.exists(os.path.join(tmp, 'q')), d.get('so_buoc'))
    n = sum(1 for k in KQ if k[1]); print(f'\nTỔNG: {n}/{len(KQ)} đạt'); sys.exit(0 if n == len(KQ) else 1)

asyncio.run(main())
