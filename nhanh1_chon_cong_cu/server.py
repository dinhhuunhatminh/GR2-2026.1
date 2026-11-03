# -*- coding: utf-8 -*-
"""Máy chủ MCP: chọn công cụ bảo mật DevOps có dấu vết (nhánh 1 – bản v8 bước 21, 18 công cụ trên 6 pha DevOps).

Lớp vỏ mỏng: kiểm tra đầu vào, gọi nguyên hàm chon() trong lib/chon_v6.py, trả kết quả + tóm tắt.
Chạy: python server.py   (giao tiếp MCP qua stdio)
"""
import json, math, os, sys, time
from typing import Optional
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'lib'))
import chon_v6 as C                   # noqa: E402  (v8: 19/10/2026, bước 21+22 – 18 công cụ + HCL)
from hcl import MoHinhHCL             # noqa: E402  (bước 22, giữ để đối chiếu)
from hcl_b28 import MoHinhHCLb28      # noqa: E402  (bước 28: HCL đúng bản chất – mặc định)
import pha as PHA                     # noqa: E402
import suy_dien as SD                 # noqa: E402
from mcp.server.fastmcp import FastMCP  # noqa: E402

_CASES_V7 = json.load(open(os.path.join(C.D, 'table_gop_v7.json'), encoding='utf-8'))
MH_HCL = MoHinhHCL(_CASES_V7)
MH_BAYES = C.MoHinh(_CASES_V7)
MH_HCL28 = MoHinhHCLb28()
MH = MH_HCL28  # Mặc định: bảng bước 33b (v11, tệp bang_hcl_b33b.json); 'hcl_v8' và 'bayes' để đối chiếu
MO_HINH_MAP = {'hcl': MH_HCL28, 'hcl_v8': MH_HCL, 'bayes': MH_BAYES}
CHKN = json.load(open(os.path.join(C.D, 'cau_hinh_khuyen_nghi.json'), encoding='utf-8'))
NGUON_XS = 'xác suất bắt lỗi (bảng bước 33b, v11): p = (k + κ·μ)/(m + κ) theo ô (ngôn ngữ, công cụ, họ lỗi); k/m đo bằng quét TOÀN REPO 1.020 commit vá thật (994 ca, 2.145 cặp), nhãn y_ham = cảnh báo nằm trong hàm bị vá và khớp CWE; μ(L,t,h) ước lượng từ không gian Two-Stage Calibrated Joint HMLC 3 trục (CVSS/Severity + Phản hồi công cụ + CWE) có co cụm Bayes 2 tầng về tỷ lệ nền công cụ r0(t), κ = 10 (giảm Brier -0.00254, giảm Log-loss -0.01324, tăng AUC +0.0749 có ý nghĩa thống kê 95% so với A0); họ lỗi/ngôn ngữ lấy từ 8.155 ca lỗ hổng (table_gop_v7.json)'
DO_PHU_THAT = ('Lưu ý độ phủ: trên lỗ hổng THẬT của ứng dụng mã nguồn mở (bước 15, 1152 ca), mỗi công cụ quét mã chỉ bắt khoảng 0,4–11% lỗ hổng '
               '(Go ~0,4%, Java ~1%, PHP ~4%, Python 3–9%, JS/TS 3–11%). V nhỏ là bình thường; phần lớn rủi ro cần quét động (Nuclei/ZAP ở pha Test), '
               'kiểm thư viện & container image (OSV-Scanner/Grype/Dockle ở pha Build/Release), kiểm toán cấu hình & runtime (KICS/Trivy/Checkov/Docker Bench ở pha Deploy/Operate) và review thủ công – nhất là phân quyền, xác thực, CSRF, logic nghiệp vụ.')
TEN_MUC = {'it_nhieu': 'ít nhiễu', 'can_bang': 'cân bằng', 'bao_phu_toi_da': 'bao phủ tối đa'}
BANG = json.load(open(os.path.join(C.D, 'bang_chuc_nang_ho_loi.json'), encoding='utf-8'))
DO4 = json.load(open(os.path.join(C.D, 'do_phat_hien_buoc4.json'), encoding='utf-8'))
CHUC_NANG = {
    'dang_nhap': 'Đăng nhập / xác thực (form đăng nhập, SSO/OAuth, MFA, API key)',
    'tai_khoan': 'Quản lý tài khoản (đăng ký, quên/đặt lại mật khẩu, đổi email)',
    'phien_token': 'Phiên / token / JWT (cookie phiên, refresh token, token CSRF)',
    'upload': 'Tải tệp lên từ client',
    'tep': 'Đọc/ghi/tải tệp theo đường dẫn (phục vụ tệp, tải xuống, giải nén)',
    'csdl': 'Truy vấn CSDL / tìm kiếm / lọc dữ liệu',
    'html': 'Hiển thị nội dung người dùng / HTML (template, markdown, bình luận)',
    'api': 'API web (REST, GraphQL, gRPC, WebSocket)',
    'phan_quyen': 'Phân quyền / vai trò (admin, ACL, tách tenant, quyền sở hữu)',
    'url_ngoai': 'Gọi URL ra ngoài / webhook / proxy',
    'du_lieu': 'Xử lý dữ liệu đầu vào phức tạp (XML, YAML, giải tuần tự hóa, ảnh)',
    'thanh_toan': 'Thanh toán (ghi nhận, hiện chưa có dữ liệu rủi ro riêng – bị bỏ qua khi tính)',
}
TEP_SO = ['dockerfile', 'terraform', 'cloudformation', 'k8s', 'gh_actions', 'docker_compose']

mcp = FastMCP('chon-cong-cu-bao-mat', instructions=(
    'Máy chủ chọn công cụ bảo mật DevOps (18 công cụ trên 6 pha CODE, BUILD, TEST, RELEASE, DEPLOY, OPERATE) cho một dự án, có dấu vết giải thích. '
    'Trình tự: (1) gọi huong_dan_mo_ta_du_an để biết cần hỏi gì; (2) hỏi người dùng; '
    '(3) gọi chon_cong_cu với dữ liệu có cấu trúc; (4) trình bày tom_tat, khoảng trống và lý do từng công cụ. '
    'Không tự bịa số liệu: mọi con số lấy từ kết quả trả về.'))


@mcp.tool()
def huong_dan_mo_ta_du_an() -> dict:
    """Trả về các trường cần hỏi người dùng để mô tả dự án, mã chức năng hợp lệ, ngôn ngữ và loại tệp được hỗ trợ."""
    return {
        'truong': {
            'ngon_ngu': 'dict ngôn ngữ → dung lượng mã (KB) hoặc null nếu không biết. Hỗ trợ: ' + ', '.join(C.LANGS),
            'chuc_nang': 'danh sách mã chức năng (xem chuc_nang_hop_le); không biết thì để trống',
            'tep': f'dict: số tệp cấu hình theo loại ({", ".join(TEP_SO)}) và "lockfile": danh sách tên lockfile ([] = khách xác nhận KHÔNG có lockfile; khách chưa nói thì bỏ hẳn khóa lockfile)',
            'ngan_sach_giay': 'thời gian tối đa cho cả bộ công cụ trong pipeline (giây)',
            'bat_buoc': 'công cụ buộc phải có (tên trong danh_muc_cong_cu)',
            'cam': 'công cụ không được dùng',
            'moi_truong_chay': 'true nếu có bản ứng dụng chạy thử (URL) để quét động (Nuclei/ZAP)',
            'so_goi': 'số gói phụ thuộc nếu biết (tùy chọn)',
            'tong_tep': 'tổng số tệp trong repo nếu biết (tùy chọn)',
            'chuc_nang_suy_ra': 'chức năng BẠN tự suy từ lời khách (khách không nói thẳng) – tách khỏi chuc_nang để server gắn nhãn và thử điểm nhạy',
            'framework': 'tên framework khách nhắc, chép nguyên văn (ví dụ Django, Laravel, Express)',
            'thu_vien': 'tên thư viện/công nghệ/dịch vụ khách nhắc, chép nguyên văn (ví dụ Postgres, MoMo, đăng nhập Google, multer)',
            'loai_du_an': 'ung_dung / thu_vien – chỉ điền khi khách nói rõ; để trống thì server suy',
        },
        'quy_tac_cho_tro_ly': [
            'Chỉ điền giá trị khách đã nói. Chức năng bạn tự suy thì đưa vào chuc_nang_suy_ra, không trộn vào chuc_nang. Tên framework/thư viện/dịch vụ khách nhắc thì chép vào framework/thu_vien để server tự suy. Lockfile, Dockerfile, docker-compose, CI, môi trường chạy thử, ngân sách mà khách không nói thì để trống (server sẽ báo điểm nhạy và câu cần hỏi); không đoán theo thông lệ của ngôn ngữ. Trình bày cho khách phần điểm nhạy và các câu cần hỏi lại.',
            'Khi trình bày kết quả, nêu đủ: (1) công cụ theo pha DevOps kèm điểm mạnh/yếu, (2) mức bao phủ V, độ phát hiện phi mã nguồn D và tổng cảnh báo sai dự kiến, (3) khoảng trống lớn nhất kể cả nhóm "khac" (không phân loại được), (4) các giả định và giá trị mặc định đã dùng, (5) ba phương án (ít nhiễu / cân bằng / bao phủ tối đa) và cái giá của từng phương án (bao phủ thêm bao nhiêu, cảnh báo sai thêm bao nhiêu); hỏi khách chịu được bao nhiêu cảnh báo sai nếu họ chưa nói.',
            'Chỉ nêu con số có trong kết quả của công cụ. Nhận xét ngoài dữ liệu phải ghi rõ là ý kiến riêng.'],
        'chuc_nang_hop_le': CHUC_NANG,
        'lockfile_hop_le': sorted(C.LOCK_OK),
        'thu_tu_hoi_goi_y': ['ngôn ngữ + kích thước', 'chức năng chính', 'lockfile / Dockerfile / docker-compose / IaC / CI', 'ngân sách thời gian',
                             'công cụ bắt buộc / cấm', 'có môi trường chạy thử không'],
    }


@mcp.tool()
def danh_muc_cong_cu() -> dict:
    """Danh mục 18 công cụ: pha DevOps, phạm vi áp dụng, cách ước lượng thời gian, độ chính xác cảnh báo và độ phát hiện thực nghiệm."""
    out = {}
    for t, v in C.CAT.items():
        out[t] = {'pha': v['pha'], 'dau_vao': v['dau_vao'], 'pham_vi': v['pham_vi'],
                  'thoi_gian': v['thoi_gian'].get('cach_dung_trong_bo_chon'),
                  'ty_le_canh_bao_dung_mau': v['canh_bao'].get('ty_le_dung_mau'), 'wilson95': v['canh_bao'].get('wilson95'),
                  'nguon_xac_suat_bat_loi': v['nguon_xac_suat_bat_loi'], 'do_phat_hien_buoc4': DO4.get(t)}
    return {'cong_cu': out, 'tong_so_cong_cu': len(out), 'ghi_chu': DO4['_ghi_chu']}


def _kiem_tra(ngon_ngu, chuc_nang, tep, ngan_sach_giay, bat_buoc, cam):
    loi, canh_bao = [], []
    if not isinstance(ngan_sach_giay, (int, float)) or isinstance(ngan_sach_giay, bool) or not math.isfinite(ngan_sach_giay) or ngan_sach_giay <= 0:
        loi.append(f'ngan_sach_giay phải là số > 0 (nhận: {ngan_sach_giay!r})')
    sai_cn = [x for x in chuc_nang if x not in CHUC_NANG]
    if sai_cn: loi.append(f'chức năng không hợp lệ: {sai_cn}. Mã hợp lệ: {list(CHUC_NANG)}')
    for ten, ds in (('bat_buoc', bat_buoc), ('cam', cam)):
        sai = [x for x in ds if x not in C.CAT]
        if sai: loi.append(f'{ten}: công cụ không có trong danh mục: {sai}. Có: {list(C.CAT)}')
    if set(bat_buoc) & set(cam): loi.append(f'công cụ vừa bắt buộc vừa cấm: {sorted(set(bat_buoc) & set(cam))}')
    for L, kb in ngon_ngu.items():
        if kb is not None and (not isinstance(kb, (int, float)) or isinstance(kb, bool) or not math.isfinite(kb) or kb < 0): loi.append(f'dung lượng mã của {L} phải là số ≥ 0 hoặc null')
    la = [L for L in ngon_ngu if L not in C.LANGS]
    if la: canh_bao.append(f'không có công cụ quét mã nguồn cho: {la} (vẫn chọn được công cụ bí mật/thư viện/cấu hình)')
    sai_tep = [k for k in tep if k not in TEP_SO + ['lockfile']]
    if 'lockfile' in tep and not (isinstance(tep['lockfile'], list) and all(isinstance(x, str) for x in tep['lockfile'])):
        loi.append('tep.lockfile phải là danh sách tên tệp, ví dụ ["composer.lock"]'); tep = {**tep, 'lockfile': []}
    sai_so = [k for k in TEP_SO if k in tep and (not isinstance(tep[k], int) or isinstance(tep[k], bool) or tep[k] < 0)]
    if sai_so: loi.append(f'số tệp phải là số nguyên ≥ 0: {sai_so}')
    if sai_tep: loi.append(f'loại tệp không hợp lệ: {sai_tep}. Hợp lệ: {TEP_SO + ["lockfile"]}')
    lf_la = [x for x in tep.get('lockfile', []) if x not in C.LOCK_OK]
    if lf_la: canh_bao.append(f'lockfile không được OSV-Scanner/Grype hỗ trợ (bỏ qua): {lf_la}')
    if not ngon_ngu and not any(tep.get(k) for k in tep): loi.append('mô tả quá ít: cần ít nhất một ngôn ngữ hoặc một tệp cấu hình/lockfile')
    return loi, canh_bao


def _dong_phuong_an(rs, muc):
    d = ['Ba phương án (λ = mức đánh đổi bao phủ lấy cảnh báo sai của công cụ quét mã; ' + NGUON_XS + '):']
    gap = {}
    for ten, x in rs.items():
        lab = TEN_MUC[ten] + (' [đang dùng]' if ten == muc else '')
        if x['khong_kha_thi']: d.append(f'- {lab}: không khả thi'); continue
        k = tuple(sorted(x['chon']))
        if k in gap: d.append(f'- {lab}: giống phương án {gap[k]}'); continue
        gap[k] = TEN_MUC[ten]; tg = x['trace']['tong']
        d.append(f"- {lab} (λ={C.MUC_NHIEU[ten]}): {', '.join(x['chon'])} | V={tg['V']}, D={tg['D_bi_mat_cau_hinh']}, cảnh báo sai ~{tg['canh_bao_sai_du_kien']}, ~{tg['thoi_gian_du_doan_s']} s")
    return d


def _dong_nhan(nhan, dn, hoi, gc):
    TEN = {'khach_noi': 'khách nói', 'suy_ra': 'suy ra theo quy tắc', 'suy_ra_tro_ly': 'trợ lý tự suy', 'mac_dinh': 'giá trị mặc định', 'bo_trong': 'để trống (khách chưa nói)'}
    nhom = {}
    for k, v in nhan.items(): nhom.setdefault(v['nguon'], []).append(k + (f" ({v['quy_tac']})" if v.get('quy_tac') else ''))
    d = ['Nguồn của từng thông tin đầu vào: ' + '; '.join(f"{TEN[n]}: {', '.join(x)}" for n, x in nhom.items())]
    if dn: d.append('Điểm nhạy (giả định nào sai thì bộ công cụ đổi): ' + '; '.join(f"nếu {x['neu']} → thêm {x['them'] or '-'}, bớt {x['bot'] or '-'}" for x in dn))
    else: d.append('Điểm nhạy: đổi các giả định đã thử không làm đổi bộ công cụ.')
    if hoi: d.append('Cần hỏi lại khách: ' + ' | '.join(hoi))
    for g in gc: d.append('Ghi chú suy diễn: ' + g)
    return d


def _tom_tat(r, du_an, rs=None, muc='can_bang', nhan=None, dn=None, hoi=None, gc=None):
    t = r['trace']
    if r['khong_kha_thi']:
        return 'Không khả thi: ' + '; '.join(x['noi_dung'] for x in t['canh_bao'] if x['ma'] == 'khong_kha_thi')
    tg = t['tong']
    dong = [f"Chọn {len(r['chon'])} công cụ, dự kiến {tg['thoi_gian_du_doan_s']} s (đã nhân hệ số an toàn {t['tham_so']['he_so_an_toan']}) / ngân sách {du_an['ngan_sach']} s; "
            f"mức bao phủ rủi ro mã nguồn V={tg['V']}; độ phát hiện phi mã nguồn D={tg['D_bi_mat_cau_hinh']}; cảnh báo sai dự kiến tổng ~{tg['canh_bao_sai_du_kien']}. Theo pha DevOps (dấu + là số đo tốt, dấu - là hạn chế; phân loại +/- là của bộ công cụ, số liệu có nguồn trong dau_vet):"]
    ph = PHA.theo_pha(r['chon'], t, C.CAT, DO4, tuple(du_an['ngon_ngu']))
    da_in = {}
    for p, v in ph.items():
        if isinstance(v, str): dong.append(f"* {p}: {v}"); continue
        dong.append(f"* {p}:")
        for it in v:
            if it['cong_cu'] in da_in:
                dong.append(f"  - {it['cong_cu']}: (đã mô tả ở pha {da_in[it['cong_cu']]}; chỉ chạy 1 lần)"); continue
            da_in[it['cong_cu']] = p
            dong.append(f"  - {it['cong_cu']}: {it.get('vai_tro') or ''}; ~{it['thoi_gian_du_doan_s']} s, cảnh báo sai ~{it['canh_bao_sai_du_kien']}"
                        + (f" ({it['ghi_chu_pha']})" if 'ghi_chu_pha' in it else ''))
            for m in it['diem_manh']: dong.append('      + ' + m['noi_dung'])
            for y in it['diem_yeu']: dong.append('      - ' + y['noi_dung'])
    cn = PHA.chuc_nang_hay_gap_loi(du_an['chuc_nang'], BANG, t.get('khoang_trong', []))
    if cn: dong.append('Chức năng khai báo và họ lỗi hay gặp (nguồn: ' + PHA.NGUON_BANG + '):'); dong.extend(PHA.dong_chuc_nang(cn))
    kt = [k for k in t.get('khoang_trong', []) if k['rui_ro_con_lai'] >= 0.05][:6]
    if kt: dong.append('Khoảng trống rủi ro còn lại (kể cả nhóm "khac" = không phân loại được): ' + '; '.join(f"{k['ho']} ({PHA.pc(k['rui_ro_con_lai'])}, {k['goi_y']}" + (f"; ước lượng {PHA.pc(k['ty_le_ngoai_tam_sast_k3'])} ca kiểu này có bản vá chạm ≥4 tệp/thiết kế (nhãn K3, ngoài tầm SAST theo dòng)" if 'ty_le_ngoai_tam_sast_k3' in k else '') + ')' for k in kt))
    for x in t['canh_bao']: dong.append('Lưu ý: ' + x['noi_dung'])
    dong.append(DO_PHU_THAT)
    ck = [f"{c}: {CHKN[c]['lenh']}" + (f" – {CHKN[c]['loc']}" if 'loc' in CHKN[c] else '') for c in r['chon'] if c in CHKN]
    if ck: dong.append('Cấu hình khuyến nghị cho công cụ đã chọn (' + CHKN['chung_quet_ma'] + '): ' + ' | '.join(ck))
    if rs: dong = _dong_phuong_an(rs, muc) + [f'Chi tiết phương án {TEN_MUC[muc]}:'] + dong
    if nhan is not None: dong += _dong_nhan(nhan, dn or [], hoi or [], gc or [])
    return '\n'.join(dong)


def _o_it_mau(chon, du_an, mh):
    """Luồng F2: ô (ngôn ngữ, công cụ, họ lỗi) có trọng số rủi ro > 0 nhưng < 5 mẫu đo → ước lượng chủ yếu mượn từ ca tương tự."""
    if not hasattr(mh, 'thong_tin'): return []
    w, _ = C.trong_so(du_an, mh); out = []
    for L, wL in w.items():
        for h, wh in wL.items():
            if wh <= 0: continue
            for tl in chon:
                if tl not in C.SAST or L not in C.AP_LANG.get(tl, set()): continue
                info = mh.thong_tin(L, tl, h)
                if info and info['it_mau']:
                    out.append({'ngon_ngu': L, 'cong_cu': tl, 'ho_loi': h, 'trong_so': round(wh, 4), 'so_mau': info['m'], 'p': round(mh.pt(L, tl, h), 4),
                                'nguon_uoc_luong': info['nguon'], 'ho_lang_gieng': [g for g, _ in info['ho_lang_gieng']], 'do_tin_cay': 'thấp'})
    return sorted(out, key=lambda x: -x['trong_so'])


def _dong_bo_sung(ot, cn_thieu):
    d = []
    if ot:
        d.append(f"Ô ít mẫu (< 5 cặp đo, độ tin cậy thấp – xác suất gần với tỷ lệ bắt chung của công cụ): " + '; '.join(
            f"{x['ngon_ngu']}/{x['cong_cu']}/{x['ho_loi']} ({x['so_mau']} mẫu, p={x['p']}, giống: {', '.join(x['ho_lang_gieng'])})" for x in ot[:6]))
    if cn_thieu:
        d.append('Chức năng chưa có dữ liệu rủi ro nên KHÔNG được tính vào V: ' + ', '.join(cn_thieu) + ' – coi là khoảng trống, cần review thủ công (logic thanh toán, kiểm tra số tiền, chống gửi lại).')
    return ('\n' + '\n'.join(d)) if d else ''


LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'log_goi_tool.jsonl')
def _ghi_log(thamso):
    if os.environ.get('MCP_KHONG_GHI_LOG'): return
    try:
        with open(LOG, 'a', encoding='utf-8') as f:
            f.write(json.dumps({'luc': time.strftime('%Y-%m-%d %H:%M:%S'), 'tham_so': thamso}, ensure_ascii=False) + '\n')
    except Exception:
        pass


@mcp.tool()
def chon_cong_cu(ngan_sach_giay: Optional[float] = None, ngon_ngu: Optional[dict] = None, chuc_nang: Optional[list] = None, tep: Optional[dict] = None,
                 bat_buoc: Optional[list] = None, cam: Optional[list] = None, moi_truong_chay: Optional[bool] = None,
                 so_goi: Optional[int] = None, tong_tep: Optional[int] = None, muc_nhieu: str = 'can_bang',
                 framework: Optional[list] = None, thu_vien: Optional[list] = None, chuc_nang_suy_ra: Optional[list] = None,
                 loai_du_an: Optional[str] = None, mo_hinh_xac_suat: str = 'hcl') -> dict:
    """Chọn bộ công cụ bảo mật (từ danh mục 18 công cụ trên 6 pha DevOps) cho dự án trong ngân sách thời gian, kèm dấu vết lý do chọn/loại từng công cụ và khoảng trống rủi ro.

    Trả 3 phương án: it_nhieu / can_bang (mặc định) / bao_phu_toi_da; muc_nhieu chọn phương án trình bày chi tiết.
    Tham số mo_hinh_xac_suat: 'hcl' (mặc định, HCL bước 28), 'hcl_v8' (bước 22) hoặc 'bayes' (Beta-Binomial phẳng).
    Đầu vào: chuc_nang = chức năng khách NÓI THẲNG; chuc_nang_suy_ra = chức năng bạn tự suy từ lời khách (tách riêng);
    framework, thu_vien = tên framework/thư viện/công nghệ/dịch vụ khách nhắc, chép nguyên văn (server tự suy ngôn ngữ, chức năng theo bảng quy tắc);
    trường khách không nói thì để trống (KHÔNG đoán lockfile, Dockerfile, docker_compose, moi_truong_chay, ngân sách). Server gắn nhãn nguồn cho từng trường và báo điểm nhạy.

    Ví dụ: ngon_ngu={"php": 300}, chuc_nang=["dang_nhap","upload"], tep={"lockfile":["composer.lock"],"dockerfile":1,"docker_compose":1}, ngan_sach_giay=120
    """
    _ghi_log({'ngan_sach_giay': ngan_sach_giay, 'ngon_ngu': ngon_ngu, 'chuc_nang': chuc_nang, 'chuc_nang_suy_ra': chuc_nang_suy_ra, 'framework': framework,
              'thu_vien': thu_vien, 'tep': tep, 'bat_buoc': bat_buoc, 'cam': cam, 'moi_truong_chay': moi_truong_chay, 'so_goi': so_goi,
              'tong_tep': tong_tep, 'muc_nhieu': muc_nhieu, 'loai_du_an': loai_du_an, 'mo_hinh_xac_suat': mo_hinh_xac_suat})
    sai_kieu = []   # kiểm kiểu trước khi suy diễn (luồng F7; sửa sau kiểm độc lập bước 28)
    if ngon_ngu is not None and not isinstance(ngon_ngu, dict): sai_kieu.append(f'ngon_ngu phải là dict ngôn ngữ → KB, ví dụ {{"python": 300}} (nhận: {type(ngon_ngu).__name__})')
    for ten, v in (('chuc_nang', chuc_nang), ('chuc_nang_suy_ra', chuc_nang_suy_ra), ('bat_buoc', bat_buoc), ('cam', cam), ('framework', framework), ('thu_vien', thu_vien)):
        if v is not None and not isinstance(v, list): sai_kieu.append(f'{ten} phải là danh sách, ví dụ ["csdl"] (nhận: {type(v).__name__})')
    if tep is not None and not isinstance(tep, dict): sai_kieu.append(f'tep phải là dict (nhận: {type(tep).__name__})')
    if sai_kieu: return {'loi': sai_kieu, 'goi_y': 'Gọi huong_dan_mo_ta_du_an để xem định dạng hợp lệ.'}
    try:
        du_an, nhan, hoi, gc = SD.suy_dien({'ngon_ngu': ngon_ngu, 'chuc_nang': chuc_nang, 'chuc_nang_suy_ra': chuc_nang_suy_ra, 'framework': framework,
                                            'thu_vien': thu_vien, 'tep': tep, 'ngan_sach': ngan_sach_giay, 'bat_buoc': bat_buoc, 'cam': cam,
                                            'moi_truong_chay': moi_truong_chay, 'so_goi': so_goi, 'tong_tep': tong_tep, 'loai_du_an': loai_du_an}, C.LANGS, C.CO_VUA_KB)
        if ngan_sach_giay is None:
            return {'can_hoi_lai': hoi, 'nhan_dau_vao': nhan, 'ghi_chu_suy_dien': gc, 'loi': ['thiếu ngân sách thời gian – hỏi khách, không tự đặt']}
        loi, cb = _kiem_tra(du_an['ngon_ngu'], du_an['chuc_nang'], du_an['tep'], ngan_sach_giay, du_an['bat_buoc'], du_an['cam'])
        if muc_nhieu not in C.MUC_NHIEU: loi = loi + [f'muc_nhieu không hợp lệ: {muc_nhieu}. Chọn một trong {list(C.MUC_NHIEU)}']
        if mo_hinh_xac_suat not in MO_HINH_MAP: loi = loi + [f'mo_hinh_xac_suat không hợp lệ: {mo_hinh_xac_suat}. Chọn một trong {list(MO_HINH_MAP)}']
        if loi: return {'loi': loi, 'can_hoi_lai': hoi, 'nhan_dau_vao': nhan, 'goi_y': 'Gọi huong_dan_mo_ta_du_an để xem giá trị hợp lệ.'}
        mh_use = MO_HINH_MAP[mo_hinh_xac_suat]
        chuc_nang = du_an['chuc_nang']
        t0 = time.perf_counter(); rs = C.chon_3_phuong_an(du_an, mh_use); ms = round((time.perf_counter() - t0) * 1000, 1)
        r = rs[muc_nhieu]; t = r['trace']
        ot = [] if r['khong_kha_thi'] else _o_it_mau(r['chon'], du_an, mh_use)
        cn_thieu = [x for x in (du_an.get('chuc_nang') or []) if x == 'thanh_toan']
        rong = ''
        if r['khong_kha_thi'] and du_an.get('bat_buoc'):   # luồng F4: nêu tên công cụ gây xung đột
            tgb = {x: round(C.du_doan_tg(x, du_an, 1.3)[0], 1) for x in du_an['bat_buoc'] if x in C.CAT}
            rong = f"Xung đột: công cụ bắt buộc {', '.join(f'{x} (~{v} s)' for x, v in tgb.items())} cần tổng {round(sum(tgb.values()), 1)} s > ngân sách {ngan_sach_giay} s. Tăng ngân sách hoặc bỏ yêu cầu bắt buộc.\n"
        if not r['khong_kha_thi'] and not r['chon']:   # luồng F3: không công cụ nào vừa ngân sách
            tgs = sorted((C.du_doan_tg(x, du_an, 1.3)[0], x) for x in C.CAT if C.ap_dung(x, du_an)[0] and x != 'syft')
            rong = (f"KHÔNG chọn được công cụ nào: ngân sách {ngan_sach_giay} s nhỏ hơn thời gian của công cụ rẻ nhất áp dụng được "
                    f"({tgs[0][1]} ~{round(tgs[0][0], 1)} s, đã × 1.3). Các dòng 'chưa có công cụ' theo pha bên dưới là do ngân sách, không phải do danh mục.\n") if tgs else ''
        dn = [] if r['khong_kha_thi'] else SD.diem_nhay(du_an, nhan, lambda d: C.chon(json.loads(json.dumps(d)), mh_use, lam=C.MUC_NHIEU[muc_nhieu])['chon'])
        hoi = SD.cau_hoi_tu_diem_nhay(dn, hoi)
        pa = {ten: (None if x['khong_kha_thi'] else {'chon': x['chon'], 'lam': C.MUC_NHIEU[ten], 'V': x['trace']['tong']['V'], 'D_bi_mat_cau_hinh': x['trace']['tong']['D_bi_mat_cau_hinh'], 'canh_bao_sai_du_kien': x['trace']['tong']['canh_bao_sai_du_kien'], 'thoi_gian_du_doan_s': x['trace']['tong']['thoi_gian_du_doan_s']}) for ten, x in rs.items()}
        return {'chon': r['chon'], 'kha_thi': not r['khong_kha_thi'], 'muc_nhieu': muc_nhieu, 'mo_hinh_xac_suat': mo_hinh_xac_suat, 'phuong_an': pa, 'nguon_xac_suat': t['nguon']['xac_suat'], 'tom_tat': rong + _tom_tat(r, du_an, rs, muc_nhieu, nhan, dn, hoi, gc) + _dong_bo_sung(ot, cn_thieu), 'nhan_dau_vao': nhan, 'diem_nhay': dn, 'can_hoi_lai': hoi, 'ghi_chu_suy_dien': gc,
                'canh_bao_dau_vao': cb, 'canh_bao': t['canh_bao'], 'khoang_trong': t.get('khoang_trong', []),
                'chuc_nang_hay_gap_loi': PHA.chuc_nang_hay_gap_loi(chuc_nang, BANG, t.get('khoang_trong', [])),
                'theo_pha_devops': (PHA.theo_pha(r['chon'], t, C.CAT, DO4, tuple(du_an['ngon_ngu'])) if not r['khong_kha_thi'] else None),
                'dau_vet': t, 'thoi_gian_tinh_ms': ms,
                'cau_hinh_khuyen_nghi': {c: CHKN[c] for c in r['chon'] if c in CHKN}, 'luu_y_do_phu': DO_PHU_THAT, 'phien_ban_bo_chon': 11, 'bang_xac_suat': 'hcl_b33b (1.020 commit, 2.145 cặp y_ham, Two-Stage Calibrated Joint HMLC 3 trục κ=10)',
                'o_it_mau': ot, 'chuc_nang_chua_co_du_lieu': cn_thieu}
    except Exception as e:
        return {'loi': [f'lỗi nội bộ: {type(e).__name__}: {e}'], 'goi_y': 'Báo lại đầu vào này để sửa.'}


@mcp.prompt()
def phong_van_du_an() -> str:
    """Kịch bản hỏi người dùng để mô tả dự án trước khi chọn công cụ."""
    return ('Hãy giúp tôi chọn công cụ bảo mật cho dự án. Trước tiên gọi huong_dan_mo_ta_du_an. Sau đó hỏi tôi lần lượt, mỗi lần một câu ngắn: '
            '1) ngôn ngữ và kích thước mã; 2) các chức năng chính (đối chiếu với mã chức năng hợp lệ, hỏi lại nếu không chắc); '
            '3) có lockfile, Dockerfile, docker-compose, Terraform/CloudFormation/K8s, GitHub Actions không; 4) ngân sách thời gian quét trong pipeline; '
            '5) công cụ bắt buộc hoặc bị cấm; 6) có bản chạy thử để quét động không. '
            'Rồi gọi chon_cong_cu và trình bày: công cụ được chọn theo 6 pha DevOps + lý do, công cụ bị loại đáng chú ý + lý do, khoảng trống cần review thủ công.')


if __name__ == '__main__':
    mcp.run()
