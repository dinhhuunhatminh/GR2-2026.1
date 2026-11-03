# -*- coding: utf-8 -*-
"""Máy chủ MCP nhánh 2 (v1): chạy công cụ quét TĨNH bằng Docker, truy vết xuyên pha, xem vết, sinh báo cáo HTML.
Lớp vỏ mỏng: logic truy vết là truy_vet_core.py (bản sao nguyên văn của b23_3_truy_vet.py đã chấm ở bước 23, kiểm bằng sha256).
v1.6 (29/10/2026): thêm lõi truy vết v2 (đồ thị tài sản, lib/truy_vet_v2.py) chạy SONG SONG với lõi v1 trên cùng tập phát hiện; lõi v1 nay đọc thêm CodeQL SARIF (v1.4c, luật nối không đổi).
Chạy: python server.py  (MCP qua stdio). An toàn: chỉ đọc/ghi trong VSECOPS_ALLOWED_ROOTS; chạy quét thật cần xac_nhan=True."""
import hashlib, json, os, subprocess, sys, tempfile, threading, time, uuid
HERE = os.path.dirname(os.path.abspath(__file__)); LIB = os.path.join(HERE, 'lib')
sys.path.insert(0, LIB)
import quet_tinh as QT      # noqa: E402
import quet_dong as QD      # noqa: E402
import bao_cao_vet as BC    # noqa: E402
import bao_cao_v2 as BC2    # noqa: E402
import xep_hang as XH       # noqa: E402
import xep_hang_v3 as XH3   # noqa: E402
import bao_cao_v3 as BC3    # noqa: E402
from mcp.server.fastmcp import FastMCP  # noqa: E402

VERSION = 'mcp_truy_vet_v3.2 (Bước 35, 11/2026; lõi đồ thị v3.1b không đổi; thêm bao_cao_v3 và xep_hang_loi_v3 cho đầu ra truy_vet_v3; các tool khác giữ như mcp_truy_vet_v3.1b)'
BO_CONG_CU = json.load(open(os.path.join(HERE, 'bo_cong_cu_co_dinh.json'), encoding='utf-8')) if os.path.exists(os.path.join(HERE, 'bo_cong_cu_co_dinh.json')) else {}
ROOTS = [os.path.realpath(p) for p in os.environ.get('VSECOPS_ALLOWED_ROOTS', os.path.realpath(os.path.join(HERE, '..', '..', '..'))).split(os.pathsep) if p]
TIMEOUT_MAC_DINH = 900  # giây/công cụ - Claude đề xuất, chưa đo
JOBS = {}
LOG = os.path.join(HERE, 'log_goi_tool.jsonl')
mcp = FastMCP('truy-vet-nhanh2', instructions=(
    'Truy vết lỗ hổng xuyên 6 pha DevOps. Quét động (giai đoạn 2): chay_ung_dung(len, cần xác nhận) -> chay_quet_dong (kế hoạch, rồi xac_nhan) -> truy_vet -> chay_ung_dung(xuong). Trình tự quét tĩnh: kiem_tra_moi_truong -> chay_quet_tinh (mặc định dry_run: chỉ cho xem kế hoạch; chạy thật cần xac_nhan=True và sự đồng ý của người dùng) '
    '-> trang_thai_job -> [tao_route_map] -> truy_vet(loi="ca_hai", repo_path=...) -> xem_vet / bao_cao_vet / bao_cao_so_sanh. '
    'Lõi v2 (đồ thị tài sản) gắn nhãn từng cặp ghép: cung_loi (cùng chỗ + cùng loại lỗi, nên dùng để kết luận), cung_tai_san / chua_ro_ho (chỉ là gợi ý). Chưa có quét động (giai đoạn 2): cạnh L1 (mã<->DAST) sẽ bằng 0, hãy nói rõ với người dùng. '
    'Với kết quả của truy_vet_v3 hãy dùng bao_cao_v3 (báo cáo HTML) và xep_hang_loi_v3 (xếp hạng); bao_cao_vet và xep_hang_loi chỉ dành cho kết quả của truy_vet (v1/v2). '
    'Không tự bịa số liệu; không báo "độ chính xác" vì cần đáp án chuẩn mà người dùng thường không có.'))


def _log(ten, **kw):
    try:
        open(LOG, 'a', encoding='utf-8').write(json.dumps({'t': time.strftime('%Y-%m-%dT%H:%M:%S'), 'tool': ten, **kw}, ensure_ascii=False) + '\n')
    except Exception:
        pass


def _ok(p, phai_ton_tai=True):
    rp = os.path.realpath(p)
    if not any(rp == r or rp.startswith(r + os.sep) for r in ROOTS):
        raise ValueError(f'Đường dẫn ngoài vùng cho phép: {p}. Vùng cho phép: {ROOTS} (đặt biến môi trường VSECOPS_ALLOWED_ROOTS để thêm).')
    if phai_ton_tai and not os.path.exists(rp): raise ValueError(f'Không thấy: {p}')
    return rp


def _sha(p):
    return hashlib.sha256(open(p, 'rb').read()).hexdigest()[:16] if os.path.exists(p) else None


@mcp.tool()
def phien_ban() -> dict:
    """Phiên bản máy chủ, dấu vân tay (sha256) của mã truy vết và thư viện họ lỗi, bộ công cụ hỗ trợ, vùng đường dẫn cho phép."""
    return {'phien_ban': VERSION, 'sha256_truy_vet_core': _sha(os.path.join(LIB, 'truy_vet_core.py')), 'sha256_ban_goc_da_cham_b23': _sha(os.path.join(LIB, 'truy_vet_core_goc_b23.py')), 'sha256_v1_1_chua_rang_buoc_dich_vu': _sha(os.path.join(LIB, 'truy_vet_core_v11.py')), 'sha256_v1_3_truoc_ho_nuclei': _sha(os.path.join(LIB, 'truy_vet_core_v13.py')), 'sha256_fam2': _sha(os.path.join(LIB, 'fam2.py')),
            'sha256_truy_vet_v2': _sha(os.path.join(LIB, 'truy_vet_v2.py')), 'sha256_truy_vet_v3': _sha(os.path.join(LIB, 'truy_vet_v3.py')), 'sha256_v1_4_truoc_codeql': _sha(os.path.join(LIB, 'truy_vet_core_v14.py')), 'tree_sitter': _co_tree_sitter() or 'thiếu: pip install tree-sitter-language-pack',
            'luat_v2': 'V1 mã<->DAST qua route map + đồ thị gọi hàm; V2 bí mật repo->Dockerfile COPY->image->container; V3 thư viện lockfile<->image (cùng dịch vụ); V4 IaC/Dockerfile<->image<->container; nhãn cung_loi/cung_tai_san/chua_ro_ho',
            'cong_cu_quet_tinh_ho_tro': QT.CONG_CU_HO_TRO, 'chua_ho_tro': QT.CHUA_HO_TRO, 'phien_ban_cong_cu': QT.IMG, 'vung_cho_phep': ROOTS,
            'luat': 'L0 (cùng file, khác công cụ), L1 (mã<->DAST theo route+họ lỗi), L2 (tệp nhạy cảm), L3 (cùng CVE+gói BUILD<->RELEASE), L4 (IaC<->docker_bench)',
            'gioi_han_da_biet': ['v2: route map tự động chỉ có Express và kiểu crAPI (Spring/Django/Go/Flask); khung khác cần route_map tay', 'v2: kiểm độc lập Juice Shop: cặp cung_loi đúng 11/12, cặp cung_tai_san/chua_ro_ho chỉ ~25-32% đúng', 'L2/L3 chưa phân biệt dịch vụ (crAPI: L2 đúng 3/6, L3 90/98)', 'L1 cần route_map và quét động có đăng nhập', 'chưa có quét động (giai đoạn 2)']}


@mcp.tool()
def kiem_tra_moi_truong(images: list[str] | None = None) -> dict:
    """Kiểm Docker và git có chạy không, image công cụ nào chưa có."""
    return QT.kiem_tra_moi_truong(images)


@mcp.tool()
def chay_quet_tinh(repo_path: str, ra_dir: str, cong_cu: list[str] | None = None, images: list[str] | None = None, xac_nhan: bool = False,
                   timeout_moi_cong_cu_giay: int = TIMEOUT_MAC_DINH, rules_dir: str | None = None, kics_paths: list[str] | None = None) -> dict:
    """Lập kế hoạch (mặc định) hoặc chạy nền các công cụ quét tĩnh bằng Docker.
    xac_nhan=False: chỉ trả kế hoạch và lệnh, KHÔNG chạy gì. xac_nhan=True: chạy nền, trả job_id (hỏi tiến độ bằng trang_thai_job).
    images: danh sách image (vd ["crapi/crapi-web:latest"]) cho grype-image/dockle (pha RELEASE).
    kics_paths: đường dẫn (tương đối repo) để GIỚI HẠN phạm vi kics, vd ["deploy/docker", "services/web/Dockerfile"]; bỏ trống = quét toàn repo (nhiều cảnh báo hơn)."""
    repo = _ok(repo_path); out = _ok(ra_dir, phai_ton_tai=False)
    if rules_dir: rules_dir = _ok(rules_dir, phai_ton_tai=False)
    steps, notes = QT.ke_hoach(repo, out, cong_cu, images, rules_dir, kics_paths)
    if not xac_nhan:
        _log('chay_quet_tinh', che_do='ke_hoach', repo=repo)
        return {'che_do': 'ke_hoach (chưa chạy gì)', 'so_buoc': len(steps), 'ghi_chu': notes, 'buoc': [{'id': s['id'], 'mo_ta': s['mo_ta'], 'lenh': ' '.join(s['lenh'])} for s in steps],
                'muon_chay_that': 'hỏi người dùng đồng ý, rồi gọi lại với xac_nhan=True'}
    os.makedirs(out, exist_ok=True)
    jid = uuid.uuid4().hex[:8]; J = {'id': jid, 'trang_thai': 'dang_chay', 'bat_dau': time.time(), 'tong': len(steps), 'xong': 0, 'ket_qua': [], 'ghi_chu': notes, 'ra_dir': out}
    JOBS[jid] = J

    def run():
        for s in steps:
            r = QT.chay_buoc(s, out, timeout_moi_cong_cu_giay); J['ket_qua'].append(r); J['xong'] += 1
        J['trang_thai'] = 'xong'; J['giay'] = round(time.time() - J['bat_dau'], 1)
        try: json.dump(J, open(os.path.join(out, f'job_{jid}.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
        except Exception: pass
    threading.Thread(target=run, daemon=True).start()
    _log('chay_quet_tinh', che_do='chay_that', job=jid, repo=repo)
    return {'job_id': jid, 'so_buoc': len(steps), 'ghi_chu': notes}


@mcp.tool()
def chay_ung_dung(compose_file: str, hanh_dong: str = 'trang_thai', xac_nhan: bool = False) -> dict:
    """Bật/tắt ứng dụng thử nghiệm bằng docker compose. hanh_dong: 'trang_thai' (xem container đang chạy, không cần xác nhận), 'len' (up -d), 'xuong' (down).
    'len'/'xuong' mặc định chỉ lập kế hoạch; xac_nhan=True mới chạy nền (trả job_id, hỏi trang_thai_job)."""
    f = _ok(compose_file)
    if hanh_dong not in ('trang_thai', 'len', 'xuong'): raise ValueError("hanh_dong phải là 'trang_thai', 'len' hoặc 'xuong'")
    base = ['docker', 'compose', '-f', f]
    if hanh_dong == 'trang_thai':
        p = subprocess.run(base + ['ps', '--format', 'table {{.Name}}\t{{.Status}}\t{{.Ports}}'], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=50)
        return {'ma_thoat': p.returncode, 'container': p.stdout[-3000:], 'loi': p.stderr[-400:]}
    lenh = base + (['--compatibility', 'up', '-d'] if hanh_dong == 'len' else ['down'])
    step = {'id': 'compose_' + hanh_dong, 'cong_cu': 'docker compose', 'mo_ta': hanh_dong, 'lenh': lenh, 'tep_ra': [], 'ma_chap_nhan': [0], 'ghi_stdout': None}
    if not xac_nhan: return {'che_do': 'ke_hoach (chưa chạy gì)', 'lenh': ' '.join(lenh), 'muon_chay_that': 'hỏi người dùng đồng ý, rồi gọi lại với xac_nhan=True'}
    jid = uuid.uuid4().hex[:8]; J = {'id': jid, 'trang_thai': 'dang_chay', 'bat_dau': time.time(), 'tong': 1, 'xong': 0, 'ket_qua': []}; JOBS[jid] = J

    def run():
        J['ket_qua'].append(QT.chay_buoc(step, os.path.dirname(f), 1800)); J['xong'] = 1; J['trang_thai'] = 'xong'; J['giay'] = round(time.time() - J['bat_dau'], 1)
    threading.Thread(target=run, daemon=True).start(); _log('chay_ung_dung', hanh_dong=hanh_dong, job=jid, compose=f)
    return {'job_id': jid, 'ghi_chu': 'đang chạy nền (kéo image có thể mất vài phút); hỏi trang_thai_job'}


@mcp.tool()
def chay_quet_dong(ra_dir: str, openapi_spec: str | None = None, ung_dung: str = 'crapi', muc_tieu_mang: str = 'http://crapi-web', muc_tieu_host: str = 'http://localhost:8888', mang_docker: str = 'docker_default',
                   cong_cu: list[str] | None = None, xac_nhan: bool = False, timeout_moi_cong_cu_giay: int = TIMEOUT_MAC_DINH, bat_zap: bool = False, zap_timeout_giay: int = QD.ZAP_GIAY_MAC_DINH) -> dict:
    """(v1.4: ZAP chủ động MẶC ĐỊNH TẮT; bat_zap=True mới chạy, có giới hạn zap_timeout_giay, quá giờ thì xóa container.) Quét ĐỘNG có đăng nhập (nuclei, ZAP, docker_bench) vào ứng dụng ĐANG CHẠY. Mục tiêu phải nằm trong VSECOPS_ALLOWED_TARGETS (mặc định crapi-web, localhost).
    muc_tieu_mang: địa chỉ ứng dụng nhìn từ trong mạng Docker; muc_tieu_host: địa chỉ nhìn từ máy chủ MCP (để đăng ký/đăng nhập lấy token).
    Mặc định chỉ lập kế hoạch; xac_nhan=True mới chạy nền. Token đăng nhập chỉ ở bộ nhớ, bị xóa khỏi kết quả."""
    out = _ok(ra_dir, phai_ton_tai=False)
    hs = QD.UD.HOSO.get(ung_dung)
    if ung_dung != 'crapi' and not hs: return {'loi': f'ứng dụng "{ung_dung}" chưa hỗ trợ', 'ho_tro': ['crapi'] + sorted(QD.UD.HOSO)}
    if hs:
        if muc_tieu_mang == 'http://crapi-web': muc_tieu_mang = hs['net']
        if muc_tieu_host == 'http://localhost:8888': muc_tieu_host = hs['host']
        if mang_docker == 'docker_default': mang_docker = hs['mang']
    zap_bat = bat_zap or bool(cong_cu and 'zap' in cong_cu)
    if (not hs or (hs['zap'] == 'api' and zap_bat)) and not openapi_spec: return {'loi': 'thiếu openapi_spec (crAPI luôn cần; VAmPI chỉ cần khi bật ZAP) - đặc tả OpenAPI dạng JSON'}
    spec = _ok(openapi_spec) if openapi_spec else None
    net = QD.kiem_tra_muc_tieu(muc_tieu_mang); host = QD.kiem_tra_muc_tieu(muc_tieu_host)
    steps = QD.ke_hoach_dong(out, spec, net, mang_docker, cong_cu, ung_dung, bat_zap=bat_zap, zap_giay=zap_timeout_giay)
    if not steps: return {'loi': 'không có công cụ động hợp lệ', 'ho_tro': QD.CONG_CU_DONG}
    if not xac_nhan:
        _log('chay_quet_dong', che_do='ke_hoach')
        return {'che_do': 'ke_hoach (chưa chạy gì)', 'truoc_khi_quet': [f'kiểm ứng dụng sống tại {host}', 'đăng ký + đăng nhập tài khoản thử, lấy token (token không hiển thị, không ghi log)', 'ghi danh sách URL và bản đặc tả cho ZAP vào _dong/'],
                'buoc': [{'id': s['id'], 'mo_ta': s['mo_ta'], 'lenh': ' '.join(s['lenh'])} for s in steps], 'sau_khi_quet': 'xóa token khỏi mọi tệp kết quả', 'zap': ('BẬT, giới hạn %d giây' % zap_timeout_giay) if zap_bat else 'TẮT (mặc định từ v1.4); muốn bật: bat_zap=True',
                'muon_chay_that': 'hỏi người dùng đồng ý (và chắc chắn ứng dụng thử đang chạy), rồi gọi lại với xac_nhan=True'}
    os.makedirs(os.path.join(out, '_dong'), exist_ok=True)
    jid = uuid.uuid4().hex[:8]; J = {'id': jid, 'trang_thai': 'dang_chay', 'bat_dau': time.time(), 'tong': len(steps) + 2, 'xong': 0, 'ket_qua': [], 'ghi_chu': []}; JOBS[jid] = J

    def run():
        token = None
        try:
            ok, loi = QD.kiem_song(host)
            J['ket_qua'].append({'id': 'kiem_song', 'cong_cu': '-', 'trang_thai': 'ok' if ok else 'loi', 'stderr_cuoi': loi}); J['xong'] += 1
            if not ok: J['trang_thai'] = 'xong'; return
            try:
                token, email = QD.lay_token(host) if not hs else QD.UD.lay_xac_thuc(ung_dung, host); J['ket_qua'].append({'id': 'lay_token', 'cong_cu': '-', 'trang_thai': 'ok', 'tai_khoan_thu': email}); J['xong'] += 1
            except Exception as e:
                J['ket_qua'].append({'id': 'lay_token', 'cong_cu': '-', 'trang_thai': 'loi', 'stderr_cuoi': str(e)[:200]}); J['trang_thai'] = 'xong'; return
            open(os.path.join(out, '_dong', 'urls.txt'), 'w', encoding='utf-8').write('\n'.join(QD.UD.urls(ung_dung, net) if hs else QD.sinh_urls(spec, net)))
            if spec: QD.ghi_spec_cho_zap(spec, net, os.path.join(out, '_dong', 'spec_zap.json'))
            for st in steps:
                r = QT.chay_buoc({**st, 'lenh': QD.thay_token(st['lenh'], token)}, out, timeout_moi_cong_cu_giay)
                r['stderr_cuoi'] = QD.che_token(r.get('stderr_cuoi'), token)
                for a, b in st.get('doi_ten', []):
                    try:
                        if os.path.exists(a): os.replace(a, b)
                    except Exception as e: r['loi_doi_ten'] = str(e)[:100]
                J['ket_qua'].append(r); J['xong'] += 1
        except Exception as e:
            J['ket_qua'].append({'id': 'ngoai_le', 'trang_thai': 'loi', 'stderr_cuoi': QD.che_token(str(e)[:300], token)})
        finally:
            if token: J['da_xoa_token_o_tep'] = QD.xoa_token_trong_tep(out, token) + sum(QD.xoa_token_trong_tep(out, x) for x in QD.UD.bi_mat_phu(token))
            J['trang_thai'] = 'xong'; J['giay'] = round(time.time() - J['bat_dau'], 1)
    threading.Thread(target=run, daemon=True).start(); _log('chay_quet_dong', che_do='chay_that', job=jid)
    return {'job_id': jid, 'so_buoc': len(steps) + 2}


@mcp.tool()
def trang_thai_job(job_id: str) -> dict:
    """Tiến độ và kết quả của một job: quét tĩnh (từng bước ok/loi/het_gio, mã thoát, đoạn cuối stderr) hoặc truy vết (khi xong trả bản tóm tắt)."""
    J = JOBS.get(job_id)
    if not J: return {'loi': 'không thấy job (máy chủ đã khởi động lại?)'}
    if J.get('loai') in ('truy_vet', 'route_map'):
        r = {'job_id': job_id, 'loai': J['loai'], 'trang_thai': J['trang_thai'], 'giay': J.get('giay')}
        if J['trang_thai'] == 'xong': r['ket_qua'] = J['ket_qua']
        return r
    return {'job_id': job_id, 'trang_thai': J['trang_thai'], 'tien_do': f"{J['xong']}/{J['tong']}", 'bo_loi': [r for r in J['ket_qua'] if r['trang_thai'] != 'ok'], 'so_ok': sum(1 for r in J['ket_qua'] if r['trang_thai'] == 'ok'), 'giay': J.get('giay')}


def _co_tree_sitter():
    # v1.6a: chỉ tìm gói, KHÔNG import (import/tải parser lần đầu trên Windows có thể lâu, làm treo phien_ban)
    import importlib.util
    try: return importlib.util.find_spec('tree_sitter_language_pack') is not None
    except Exception: return False


def _chay_v2(v1_out, repo, q, rm, ra, mot_dich_vu, cum, compose, deploy):
    if not _co_tree_sitter(): return {'loi': 'Lõi v2 cần thư viện tree-sitter-language-pack. Chạy trong cmd: "%s" -m pip install tree-sitter-language-pack rồi khởi động lại Claude Desktop.' % sys.executable}
    cmd = [sys.executable, '-I', os.path.join(LIB, 'truy_vet_v2.py'), '--v1', v1_out, '--repo', repo, '--quet', q, '--route-map', rm, '--ra', ra, '--cum', cum]
    if mot_dich_vu: cmd += ['--mot-dich-vu', mot_dich_vu]
    if compose is not None: cmd += ['--compose'] + list(compose)
    if deploy: cmd += ['--deploy', deploy]
    p = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=1800, stdin=subprocess.DEVNULL)
    if p.returncode != 0: return {'loi': 'lõi v2 lỗi', 'chi_tiet_stderr': p.stderr[-800:]}
    R = json.load(open(ra, encoding='utf-8'))
    json.dump({'phien_ban': VERSION, 'loi_truy_vet': R['phien_ban'], 'sha256_truy_vet_v2': _sha(os.path.join(LIB, 'truy_vet_v2.py')), 'repo': repo, 'quet_tho': q, 'route_map': rm, 'cum': cum, 'luc': time.strftime('%Y-%m-%dT%H:%M:%S')}, open(ra + '.meta.json', 'w'), indent=1)
    loi = [e for e in R['canh'] if e['nhan'] == 'cung_loi' and e['luat'] != 'L0']
    return {'ket_qua_file': ra, 'phien_ban_loi': R['phien_ban'], 'so_canh': R['so_canh'], 'canh_theo_nhan': R['canh_theo_nhan'], 'so_cum_nhieu_phat_hien': len(R['cum_list']), 'tier_theo_phat_hien': R['tier_theo_phat_hien'],
            'so_endpoint_route_map': R['so_endpoint'], 'so_chuoi_bi_mat_vao_image': len(R['lan_truyen_bi_mat']), 'so_cap_cung_loi_xuyen_pha': len(loi),
            'vi_du_cung_loi': [{'luat': e['luat'], 'a': e['a'], 'b': e['b'], 'bang_chung': e['bang_chung'][:4]} for e in loi[:5]]}


def _truy_vet_chay(q, out, rm, warn, dich_vu=True, mot_dich_vu=None, ho_nuclei=True):
    p = subprocess.run([sys.executable, '-I', os.path.join(LIB, 'truy_vet_core.py'), q, rm, out, '--lib', LIB] + ([] if dich_vu else ['--khong-dich-vu']) + (['--mot-dich-vu', mot_dich_vu] if mot_dich_vu else []) + ([] if ho_nuclei else ['--khong-ho-nuclei']), capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=1800, stdin=subprocess.DEVNULL)
    if p.returncode != 0:
        cuoi = [l for l in p.stderr.strip().splitlines() if l.strip()][-1:]
        return {'loi': 'Không đọc được kết quả thô (tệp JSON hỏng hoặc sai định dạng?). Dòng lỗi cuối: ' + (cuoi[0] if cuoi else '?'), 'chi_tiet_stderr': p.stderr[-600:]}
    R = json.load(open(out, encoding='utf-8'))
    json.dump({'phien_ban': VERSION, 'sha256_truy_vet_core': _sha(os.path.join(LIB, 'truy_vet_core.py')), 'rang_buoc_dich_vu': dich_vu, 'ho_tu_nhan_nuclei': ho_nuclei, 'mot_dich_vu': mot_dich_vu, 'quet_tho': q, 'luc': time.strftime('%Y-%m-%dT%H:%M:%S')}, open(out + '.meta.json', 'w'), indent=1)
    dong = {c for c in R['theo_cong_cu']}
    if not (dong & {'zap', 'nuclei'}): warn.append('không có kết quả quét động (TEST) -> không có vết CODE→TEST')
    elif R['so_canh'].get('L1', 0) == 0: warn.append('có quét động nhưng L1 = 0: kiểm quét có đăng nhập chưa và route_map đã đủ chưa')
    return {'ket_qua_file': out, 'tong_phat_hien': R['tong_phat_hien'], 'theo_cong_cu': R['theo_cong_cu'], 'cong_cu_thieu': R['cong_cu_thieu'], 'so_canh': R['so_canh'], 'so_cum': R['so_cum'],
            'tier_theo_phat_hien': R['tier_theo_phat_hien'], 'canh_bao': warn,
            'rang_buoc_dich_vu': dich_vu,
            'luu_y': 'Tier 1 phần lớn từ L3 (thư viện) — không phải lỗi logic. ' + ('L2/L3 đã có ràng buộc cùng dịch vụ (v1.2); thiếu thông tin dịch vụ thì KHÔNG nối.' if dich_vu else 'Ràng buộc dịch vụ TẮT (hành vi v1.1): cạnh L2/L3 có thể nối nhầm dịch vụ.')}


@mcp.tool()
def truy_vet(quet_tho_dir: str, ra_file: str, route_map: str | None = None, rang_buoc_dich_vu: bool = True, mot_dich_vu: str | None = None, ho_tu_nhan_nuclei: bool = True,
             loi: str = 'v1', repo_path: str | None = None, cum_v2: str = 'chat', compose: list[str] | None = None, deploy_file: str | None = None) -> dict:
    """(v1.6) loi: 'v1' (luật L0-L4, như cũ), 'v2' hoặc 'ca_hai'. v2/ca_hai cần repo_path (mã nguồn đã quét); lõi v2 dùng chính tập phát hiện của v1 rồi dựng mối quan hệ từ repo
    (route map, gọi hàm, Dockerfile COPY, compose) và gắn nhãn từng cặp: cung_loi / cung_tai_san / chua_ro_ho. Kết quả v2 ghi vào <ra_file bỏ .json>_v2.json. cum_v2: 'chat' (chỉ gộp cụm theo cặp cung_loi, mặc định) hoặc 'rong'.
    compose (tùy chọn): đường dẫn tương đối repo của các tệp docker compose (bỏ trống = tự tìm); deploy_file: tệp k8s/compose phụ.
    CHẠY NỀN: chuẩn hóa kết quả thô trong quet_tho_dir, nối theo luật L0-L4, gán Tier 1/2/3, ghi JSON đầy đủ vào ra_file. Trả NGAY một job_id; hỏi trang_thai_job(job_id) để lấy bản tóm tắt khi xong (thường 1-3 phút với ~5.000 phát hiện).
    route_map (tùy chọn): JSON route->mã nguồn; không có thì L1 (mã<->DAST) không hoạt động.
    mot_dich_vu (v1.3, tùy chọn): tên dịch vụ cho ứng dụng MỘT dịch vụ chính (DVWA, NodeGoat, VAmPI); mã/route/image dựng từ repo đều thuộc dịch vụ đó. Bỏ trống = cách của crAPI.
    ho_tu_nhan_nuclei (mặc định True, v1.4): cảnh báo nuclei KHÔNG có CWE được suy họ lỗi từ nhãn (sqli, xss, redirect...) theo bảng cố định để L1 hoạt động; False = hành vi v1.3 (để so sánh). Xem PHIEU_L1_HO_TU_NHAN_NUCLEI.md.
    rang_buoc_dich_vu (mặc định True, v1.2): L2/L3 chỉ nối khi cùng dịch vụ; False = hành vi v1.1 (để so sánh)."""
    q = _ok(quet_tho_dir); out = _ok(ra_file, phai_ton_tai=False); warn = []
    if loi not in ('v1', 'v2', 'ca_hai'): raise ValueError("loi phải là 'v1', 'v2' hoặc 'ca_hai'")
    if cum_v2 not in ('chat', 'rong'): raise ValueError("cum_v2 phải là 'chat' hoặc 'rong'")
    repo = None
    if loi != 'v1':
        if not repo_path: raise ValueError('loi v2/ca_hai cần repo_path (thư mục mã nguồn đã quét)')
        repo = _ok(repo_path)
    dep = _ok(deploy_file) if deploy_file else None
    out2 = (out[:-5] if out.lower().endswith('.json') else out) + '_v2.json'
    os.makedirs(os.path.dirname(out), exist_ok=True)   # v1.6b
    if route_map: rm = _ok(route_map)
    else:
        rm = os.path.join(tempfile.gettempdir(), 'route_map_rong_%s.json' % uuid.uuid4().hex[:6]); open(rm, 'w').write('[]')
        warn.append('không có route_map -> L1 (mã<->DAST) không thể nối')
    jid = uuid.uuid4().hex[:8]; J = {'id': jid, 'loai': 'truy_vet', 'trang_thai': 'dang_chay', 'bat_dau': time.time()}; JOBS[jid] = J

    def run():
        try:
            r1 = _truy_vet_chay(q, out, rm, warn, rang_buoc_dich_vu, mot_dich_vu, ho_tu_nhan_nuclei)
            if loi == 'v1' or 'loi' in r1: J['ket_qua'] = r1
            else:
                r2 = _chay_v2(out, repo, q, rm, out2, mot_dich_vu, cum_v2, compose, dep)
                if loi == 'v2': J['ket_qua'] = {'v2': r2, 'ghi_chu': 'v1 vẫn chạy (v2 dùng tập phát hiện của v1), tệp v1: ' + out}
                else:
                    xp1 = sum(v for k, v in r1['so_canh'].items() if k != 'L0')
                    J['ket_qua'] = {'v1': r1, 'v2': r2, 'so_sanh': None if 'loi' in r2 else {
                        'cap_xuyen_pha_v1': xp1, 'cap_xuyen_pha_v2': sum(v for k, v in r2['so_canh'].items() if k != 'L0'), 'cap_cung_loi_xuyen_pha_v2': r2['so_cap_cung_loi_xuyen_pha'],
                        'cum_v1': r1['so_cum'], 'cum_nhieu_phat_hien_v2': r2['so_cum_nhieu_phat_hien'],
                        'doc_the_nao': 'v1 không phân biệt cặp chắc/không chắc; v2 chỉ nên kết luận bằng cặp cung_loi. Gọi bao_cao_so_sanh(ket_qua_v1, ket_qua_v2, ra_html) để xem từng cặp kèm bằng chứng.'}}
        except Exception as e: J['ket_qua'] = {'loi': 'ngoại lệ: ' + str(e)[:300]}
        J['giay'] = round(time.time() - J['bat_dau'], 1); J['trang_thai'] = 'xong'
    threading.Thread(target=run, daemon=True).start()
    _log('truy_vet', job=jid, quet_tho=q)
    return {'job_id': jid, 'ra_file': out, 'ra_file_v2': out2 if loi != 'v1' else None, 'loi': loi, 'ghi_chu': 'đang chạy nền; hỏi trang_thai_job(job_id) sau vài chục giây'}


@mcp.tool()
def tao_route_map(repo_path: str, ra_file: str, khung: str = 'express', tep_vao: str | None = None, ten_dich_vu: str | None = None) -> dict:
    """(v1.6) Tự trích route map (endpoint -> hàm xử lý: tệp, dòng) từ mã nguồn, cho truy_vet (L1 của v1 và V1 của v2).
    khung: 'express' (Node/Express, tự tìm server.ts/app.js...; tep_vao để chỉ định) hoặc 'crapi' (repo nhiều dịch vụ services/*: Spring, Django, Go net/http/mux, Flask).
    Khung khác chưa hỗ trợ: báo người dùng, KHÔNG tự viết route map bằng tay rồi coi như kết quả công cụ."""
    repo = _ok(repo_path); out = _ok(ra_file, phai_ton_tai=False)
    if not _co_tree_sitter(): return {'loi': 'cần tree-sitter-language-pack: "%s" -m pip install tree-sitter-language-pack, rồi khởi động lại Claude Desktop' % sys.executable}
    if khung == 'express': cmd = [os.path.join(LIB, 'route_express.py'), repo, out, tep_vao or ''] + ([ten_dich_vu] if ten_dich_vu else [])
    elif khung == 'crapi': cmd = [os.path.join(LIB, 'route_crapi.py'), repo, out]
    else: return {'loi': f'khung "{khung}" chưa hỗ trợ', 'ho_tro': ['express', 'crapi']}
    jid = uuid.uuid4().hex[:8]; J = {'id': jid, 'loai': 'route_map', 'trang_thai': 'dang_chay', 'bat_dau': time.time()}; JOBS[jid] = J

    os.makedirs(os.path.dirname(out), exist_ok=True)   # v1.6b: tự tạo thư mục ra
    def run():   # v1.6a: chạy nền (lần đầu tree-sitter tải parser có thể > 60 giây)
        try:
            if os.path.exists(out): os.replace(out, out + '.cu')
            p = subprocess.run([sys.executable, '-I'] + cmd, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=900, stdin=subprocess.DEVNULL)
            if p.returncode != 0 or not os.path.exists(out): J['ket_qua'] = {'loi': 'trích route lỗi', 'chi_tiet_stderr': p.stderr[-600:]}
            else:
                rm = json.load(open(out, encoding='utf-8')); _log('tao_route_map', repo=repo, khung=khung, so=len(rm))
                J['ket_qua'] = {'ra_file': out, 'so_route': len(rm), 'vi_du': rm[:5], 'stdout_cuoi': p.stdout[-300:],
                                'luu_y': 'Kiểm vài route trong vi_du với mã nguồn trước khi dùng. Đã biết: mẫu regex có lookahead (?!...) có thể bị mất.' if khung == 'express' else ''}
        except Exception as e: J['ket_qua'] = {'loi': 'ngoại lệ: ' + str(e)[:300]}
        J['giay'] = round(time.time() - J['bat_dau'], 1); J['trang_thai'] = 'xong'
    threading.Thread(target=run, daemon=True).start()
    return {'job_id': jid, 'ra_file': out, 'ghi_chu': 'chạy nền; hỏi trang_thai_job(job_id)'}


@mcp.tool()
def bao_cao_so_sanh(ket_qua_v1: str, ket_qua_v2: str, ra_html: str, toi_da: int = 60) -> dict:
    """(v1.6) Báo cáo HTML (nền sáng) so sánh truy vết v1 và v2 trên cùng tập phát hiện: tóm tắt số cặp ghép, các cặp 'cùng lỗi' xuyên pha kèm chuỗi bằng chứng,
    chuỗi bí mật repo->image->container, và danh sách cặp 'cùng chỗ' (gợi ý). Không chấm đúng/sai vì cần đáp án."""
    os.makedirs(os.path.dirname(os.path.realpath(ra_html)), exist_ok=True)   # v1.6b
    r = BC2.sinh(_ok(ket_qua_v1), _ok(ket_qua_v2), _ok(ra_html, phai_ton_tai=False), max(1, min(toi_da, 300))); _log('bao_cao_so_sanh', html=r['html']); return r


@mcp.tool()
def xem_vet(ket_qua_file: str, tier: int | None = None, luat: str | None = None, cong_cu: str | None = None, offset: int = 0, limit: int = 15, nhan: str | None = None) -> dict:
    """(v1.6: đọc được cả tệp kết quả v2 – luật V1..V4, lọc thêm theo nhan: cung_loi / cung_tai_san / chua_ro_ho; bằng chứng v2 là chuỗi mối quan hệ lấy từ repo.) Liệt kê các cụm (vết) đã nối, kèm bằng chứng nối của từng cạnh. Lọc theo tier (1/2), luật (L0..L4) hoặc công cụ. Phân trang bằng offset/limit (tối đa 50)."""
    R = json.load(open(_ok(ket_qua_file), encoding='utf-8')); F = {f['finding_id']: f for f in R['phat_hien']}; limit = max(1, min(limit, 50))
    FE = ['file_path', 'url_route', 'package_name', 'cve_id', 'container_target', 'cis_control_class', 'sens_file']

    def bc(a, b):
        o = [f'{k}={a["anchors"][k]}' for k in FE if a['anchors'].get(k) and a['anchors'].get(k) == b['anchors'].get(k)]
        if a['family'] == b['family'] and a['family'] != 'khac': o.append('ho=' + a['family'])
        return o
    cum = {}; ver_s = str(R.get('phien_ban', '')); la_v2 = ver_s.startswith(('2', '3'))
    for e in R['canh']:
        if luat and e['luat'] != luat: continue
        if nhan and e.get('nhan') != nhan: continue
        a, b = F[e['a']], F[e['b']]; k = a['cum'] if not la_v2 or a['cum'] == b['cum'] else f"{a['cum']}~{b['cum']}"
        c = cum.setdefault(k, {'cum': k, 'tier': min(a['tier'], b['tier']), 'canh': []}); c['canh'].append({'luat': e['luat'], **({'nhan': e['nhan']} if la_v2 else {}), 'a': [a['phase'], a['tool'], a['raw_rule_id'].split('.')[-1]], 'b': [b['phase'], b['tool'], b['raw_rule_id'].split('.')[-1]], 'bang_chung': e['bang_chung'] if la_v2 else bc(a, b)})
    L = [c for c in cum.values() if (tier is None or c['tier'] == tier) and (not cong_cu or any(cong_cu in (x['a'][1], x['b'][1]) for x in c['canh']))]
    L.sort(key=lambda c: (c['tier'], c['cum']))
    for c in L: c['so_canh'] = len(c['canh']); c['canh'] = c['canh'][:4]
    return {'ban': f'v{ver_s}' if la_v2 else 'v1', 'tong_cum_khop': len(L), 'offset': offset, 'cum': L[offset:offset + limit], 'con_nua': offset + limit < len(L)}


@mcp.tool()
def bao_cao_vet(ket_qua_file: str, ra_html: str) -> dict:
    """Sinh báo cáo HTML dễ đọc (ma trận công cụ×đặc trưng, sơ đồ 6 pha, thẻ vết). Không có phần chấm đúng/sai vì cần đáp án chuẩn."""
    r = BC.sinh(_ok(ket_qua_file), _ok(ra_html, phai_ton_tai=False)); return r


@mcp.tool()
def xep_hang_loi(ket_qua_file: str, top: int = 30, ra_html: str | None = None, theo_loai: bool = False) -> dict:
    """Xếp hạng lỗi bằng QUY TẮC cố định (không dùng AI): mức nặng do công cụ báo → tier (tin cậy) → được quét động xác nhận → ổn định. Gom lỗi giống nhau thành nhóm.
    Trả top nhóm đầu và thống kê; ra_html (tùy chọn) ghi báo cáo dễ đọc. Công thức do Claude đề xuất, ghi trong PHIEU_BUOC23.md."""
    R = json.load(open(_ok(ket_qua_file), encoding='utf-8'))
    if R['phat_hien'] and 'sev' not in R['phat_hien'][0]: return {'loi': 'tệp truy vết cũ, chưa có trường mức nặng (sev). Hãy chạy lại truy_vet bằng bản v1.1.'}
    L = XH.xep_hang(R); top = max(1, min(top, 100))
    if theo_loai:
        D = XH.xep_hang_theo_loai(L)
        if ra_html: XH.html_theo_loai(D, _ok(ra_html, phai_ton_tai=False), len(R['phat_hien']), top=max(top, 15))
        return {'so_phat_hien': len(R['phat_hien']), 'so_nhom': len(L), 'che_do': 'theo_loai',
                'loai': {k: {'ten': XH.LOAI_TEN[k], 'so_nhom': len(ds), 'top': [{'hang_trong_loai': g['hang_trong_loai'], 'hang_chung': g['hang'], 'muc_nang': g['sev'], 'loi': XH.mo_ta_ngan(g), 'o_dau': str(g['vi_tri'])[:80], 'so_muc_gop': g['n'], 'tier': g['tier'], 'xac_nhan_dong': g['xac_nhan_dong']} for g in ds[:top]]} for k, ds in D.items()},
                'luu_y': 'Mỗi loại xếp riêng bằng cùng quy tắc; không so mức nặng giữa các loại. Bảng chung (theo_loai=False) vẫn là bản gốc.', 'html': ra_html}
    if ra_html: XH.html_bao_cao(L, _ok(ra_html, phai_ton_tai=False), len(R['phat_hien']), top=max(top, 40))
    return {'so_phat_hien': len(R['phat_hien']), 'so_nhom': len(L), 'nhom_theo_muc_nang': {s: sum(1 for g in L if g['sev'] == s) for s in XH.RANK},
            'top': [{'hang': g['hang'], 'muc_nang': g['sev'], 'loi': XH.mo_ta_ngan(g), 'o_dau': str(g['vi_tri'])[:80], 'so_muc_gop': g['n'], 'cong_cu': g['cong_cu'], 'tier': g['tier'], 'xac_nhan_dong': g['xac_nhan_dong']} for g in L[:top]],
            'luu_y': 'Thứ tự do quy tắc, không do AI. Danh sách trộn lỗi thư viện (CVE) với lỗi mã/cấu hình/ứng dụng chạy nên lỗi thư viện mức Critical thường đứng trên.', 'html': ra_html}


@mcp.tool()
def truy_vet_v3(ket_qua_v1: str, repo_path: str, quet_tho_dir: str, route_map: str, ra_file: str, nhieu_dich_vu: bool = False, ten_dich_vu: str = 'app',
                compose: list[str] | None = None, deploy_file: str | None = None) -> dict:
    """(v3.0, Bước 34) Dựng đồ thị nguồn gốc tài sản v3.0 trên tập phát hiện do truy_vet (lõi v1) đã tạo (ket_qua_v1). Cần tree-sitter-language-pack.
    Khác v2.1: bỏ thư mục codefixes/test/frontend; chỉ nối lời gọi module có thật; phát hiện hàm Hub (>3 endpoint) và không bắc cầu qua Hub; gom cụm 2 bước (lõi = cạnh cung_loi, cung_tai_san/chua_ro_ho chỉ là vệ tinh);
    cạnh V1_intra; V4 (KICS/Dockle/Docker Bench) mở rộng; mỗi phát hiện mã có muc_phoi_nhiem_tinh M1..M4 (HEURISTIC, chưa có đáp án chuẩn) và da_lam_sach (sanitizer_hint, chỉ là gợi ý, không phải kết luận đã vá).
    route_map: JSON do tao_route_map tạo (Express: dùng bản v3 có trường regex để giữ (?!/quarantine))."""
    for p_ in (ket_qua_v1, repo_path, quet_tho_dir, route_map):
        _ok(p_)
    _ok(ra_file, phai_ton_tai=False)   # v3.1b: chặn ghi ra ngoài vùng cho phép
    if deploy_file: _ok(deploy_file)
    if not _co_tree_sitter(): return {'loi': 'Cần tree-sitter-language-pack: "%s" -m pip install tree-sitter-language-pack' % sys.executable}
    cfg = {'ten': ten_dich_vu, 'repo': repo_path, 'quet': quet_tho_dir, 'rmap': route_map, 'v14': ket_qua_v1, 'multi': nhieu_dich_vu, 'svc': ten_dich_vu, 'compose': compose or [], 'deploy': deploy_file, 'ra': ra_file}
    cf = ra_file + '.cauhinh.json'; os.makedirs(os.path.dirname(os.path.abspath(ra_file)), exist_ok=True); json.dump(cfg, open(cf, 'w', encoding='utf-8'), ensure_ascii=False)
    env = dict(os.environ, B34_DATA=LIB)
    p = subprocess.run([sys.executable, '-I', os.path.join(LIB, 'truy_vet_v3.py'), '--cau-hinh', cf], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=1800, stdin=subprocess.DEVNULL, env=env)
    if p.returncode != 0: return {'loi': 'lõi v3 lỗi', 'chi_tiet_stderr': p.stderr[-800:]}
    R = json.load(open(ra_file, encoding='utf-8'))
    _log('truy_vet_v3', ra=ra_file)
    return {'ket_qua_file': ra_file, 'phien_ban_loi': R['phien_ban'], 'so_canh': R['so_canh'], 'canh_theo_nhan': R['canh_theo_nhan'], 'so_cum': R['so_cum'], 'tier_theo_phat_hien': R['tier_theo_phat_hien'],
            'muc_phoi_nhiem_tinh': R['muc_phoi_nhiem_tinh'], 'ham_hub': R['ham_hub'][:10], 'da_lam_sach': R['da_lam_sach'], 'canh_v1_bi_loai': R['so_canh_v1_loai'],
            'luu_y': 'Nhãn M1-M4 và da_lam_sach là heuristic tĩnh; không thay cho kết luận khai thác được.'}


@mcp.tool()
def bao_cao_v3(ket_qua_file: str, ra_html: str, quet_tho_dir: str | None = None, ten_ung_dung: str | None = None) -> dict:
    """(Bước 35) Báo cáo HTML MỘT TỆP, xem ngoại tuyến, cho KẾT QUẢ CỦA truy_vet_v3 (bao_cao_vet không đọc được tệp này). Gồm: tóm tắt, phát hiện theo pha/công cụ, thẻ truy vết cho từng cụm xuyên pha kèm bằng chứng nguyên văn,
    bảng toàn bộ phát hiện (tìm/lọc), cạnh bị loại, hàm Hub và phần giới hạn. Sinh bằng quy tắc cố định, không dùng AI. quet_tho_dir (tùy chọn): để tra tên cảnh báo ZAP từ tệp quét thô; không có thì chỉ hiện mã luật."""
    kq = _ok(ket_qua_file); out = _ok(ra_html, phai_ton_tai=False)
    q = _ok(quet_tho_dir) if quet_tho_dir else None
    r = BC3.sinh(kq, out, q, ten_ung_dung); _log('bao_cao_v3', ra=ra_html); return r


@mcp.tool()
def xep_hang_loi_v3(ket_qua_file: str, top: int = 30, theo_loai: bool = False) -> dict:
    """(Bước 35) Xếp hạng lỗi cho KẾT QUẢ CỦA truy_vet_v3 bằng QUY TẮC cố định (không dùng AI). Dùng đúng công thức của xep_hang_loi (mức nặng, tier, xác nhận động), rồi đẩy xuống cuối các nhóm mà mọi phát hiện đều là M4 (mã không đóng gói/mã chết).
    Quy tắc M4-xuống-cuối là đề xuất của Claude, chưa có đáp án chuẩn; M4 là heuristic. Không xóa nhóm nào."""
    R = json.load(open(_ok(ket_qua_file), encoding='utf-8'))
    if not R.get('phat_hien') or 'muc_phoi_nhiem_tinh' not in R: return {'loi': 'tệp không phải đầu ra truy_vet_v3 (thiếu muc_phoi_nhiem_tinh). Dùng xep_hang_loi cho đầu ra v1/v2.'}
    L, n_m4 = XH3.xep_hang_v3(R); top = max(1, min(top, 100))
    if theo_loai:
        D = XH.xep_hang_theo_loai(L)
        return {'so_phat_hien': len(R['phat_hien']), 'so_nhom': len(L), 'so_nhom_chi_m4_xuong_cuoi': n_m4, 'che_do': 'theo_loai',
                'loai': {k: {'ten': XH.LOAI_TEN[k], 'so_nhom': len(ds), 'top': [{'hang_trong_loai': g['hang_trong_loai'], 'hang_chung': g['hang'], 'hang_goc': g['hang_goc'], 'muc_nang': g['sev'], 'loi': XH.mo_ta_ngan(g), 'o_dau': str(g['vi_tri'])[:80], 'so_muc_gop': g['n'], 'tier': g['tier'], 'xac_nhan_dong': g['xac_nhan_dong'], 'chi_m4': g['chi_m4'], 'o_dau_goc': str(g['vi_tri_goc'])[:80], 'thanh_phan_m': g['thanh_phan_m']} for g in ds[:top]]} for k, ds in D.items()},
                'luu_y': 'Quy tắc cố định, không do AI. Nhóm chỉ gồm mã M4 (heuristic) nằm cuối.'}
    return {'so_phat_hien': len(R['phat_hien']), 'so_nhom': len(L), 'so_nhom_chi_m4_xuong_cuoi': n_m4, 'nhom_theo_muc_nang': {s: sum(1 for g in L if g['sev'] == s) for s in XH.RANK},
            'top': [{'hang': g['hang'], 'hang_goc': g['hang_goc'], 'muc_nang': g['sev'], 'loi': XH.mo_ta_ngan(g), 'o_dau': str(g['vi_tri'])[:80], 'so_muc_gop': g['n'], 'cong_cu': g['cong_cu'], 'tier': g['tier'], 'xac_nhan_dong': g['xac_nhan_dong'], 'chi_m4': g['chi_m4'], 'o_dau_goc': str(g['vi_tri_goc'])[:80], 'thanh_phan_m': g['thanh_phan_m']} for g in L[:top]],
            'luu_y': 'Thứ tự do quy tắc, không do AI (công thức Bước 23) cộng quy tắc M4-xuống-cuối (đề xuất của Claude, Bước 35). Lỗi thư viện mức Critical, nếu có, thường đứng trên.'}


if __name__ == '__main__':
    mcp.run()
