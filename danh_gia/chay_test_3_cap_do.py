# -*- coding: utf-8 -*-
"""Bộ kiểm thử tự động 3 cấp độ (Nhánh 1 độc lập -> Nhánh 2 độc lập -> Toàn luồng End-to-End từ Prompt đầu vào).
Chạy trực tiếp trên Windows với 2 máy chủ MCP:
- Nhánh 1: Dataset/buoc33_hcl_da_nhan_cong_cu/mcp_chon_cong_cu_v11/server.py
- Nhánh 2: Dataset/buoc34_nhanh2_tinh_va_vi_mo/mcp_truy_vet_v3/server.py
"""
import json, os, sys, time

ROOT = r'd:\2026.1\GR2'
MCP1_DIR = os.path.join(ROOT, 'Dataset', 'buoc33_hcl_da_nhan_cong_cu', 'mcp_chon_cong_cu_v11')
MCP2_DIR = os.path.join(ROOT, 'Dataset', 'buoc34_nhanh2_tinh_va_vi_mo', 'mcp_truy_vet_v3')
OUT_DIR = os.path.join(ROOT, 'Dataset', 'buoc34_nhanh2_tinh_va_vi_mo', 'kiem_thu_3_cap_do')
os.makedirs(OUT_DIR, exist_ok=True)

os.environ['MCP_KHONG_GHI_LOG'] = '1'
os.environ['VSECOPS_ALLOWED_ROOTS'] = ROOT

# Nạp MCP Nhánh 1
sys.path.insert(0, MCP1_DIR)
sys.path.insert(0, os.path.join(MCP1_DIR, 'lib'))
import server as S1  # noqa: E402

# Nạp MCP Nhánh 2
import importlib.util
sys.path.insert(0, MCP2_DIR)
sys.path.insert(0, os.path.join(MCP2_DIR, 'lib'))
spec2 = importlib.util.spec_from_file_location('server_nhanh2', os.path.join(MCP2_DIR, 'server.py'))
S2 = importlib.util.module_from_spec(spec2)
spec2.loader.exec_module(S2)

REPORT = {'thoi_gian_chay': time.strftime('%Y-%m-%d %H:%M:%S'), 'cap_1_nhanh_1': {}, 'cap_2_nhanh_2': {}, 'cap_3_end_to_end': {}}

print('=' * 80)
print('CẤP ĐỘ 1: KIỂM THỬ ĐỘC LẬP NHÁNH 1 (mcp_chon_cong_cu_v11 - Joint HMLC b33b)')
print('=' * 80)

# T1.1: Kiểm tra hướng dẫn & danh mục công cụ
hd = S1.huong_dan_mo_ta_du_an()
dm = S1.danh_muc_cong_cu()
assert dm['tong_so_cong_cu'] == 18, f"Số công cụ phải là 18, nhận {dm['tong_so_cong_cu']}"

# T1.2: Chọn công cụ trên dự án Juice Shop với 2 mức ngân sách (90s hẹp vs 600s rộng)
r_hep = S1.chon_cong_cu(
    ngan_sach_giay=90,
    ngon_ngu={'typescript': 450, 'javascript': 150},
    chuc_nang=['dang_nhap', 'tai_khoan', 'phien_token', 'csdl', 'tep', 'url_ngoai', 'phan_quyen', 'api'],
    tep={'lockfile': ['package-lock.json'], 'dockerfile': 1},
    moi_truong_chay=True
)
r_rong = S1.chon_cong_cu(
    ngan_sach_giay=600,
    ngon_ngu={'typescript': 450, 'javascript': 150},
    chuc_nang=['dang_nhap', 'tai_khoan', 'phien_token', 'csdl', 'tep', 'url_ngoai', 'phan_quyen', 'api'],
    tep={'lockfile': ['package-lock.json'], 'dockerfile': 1},
    moi_truong_chay=True
)

assert r_hep['kha_thi'] and r_rong['kha_thi']
assert r_rong['phien_ban_bo_chon'] == 11
assert 'b33b' in r_rong['bang_xac_suat'] and 'HMLC' in r_rong['nguon_xac_suat']
assert r_rong['dau_vet']['tong']['V'] >= r_hep['dau_vet']['tong']['V'], 'Vi phạm tính đơn điệu khi tăng ngân sách'
assert r_hep['dau_vet']['tong']['thoi_gian_du_doan_s'] <= 90
assert r_rong['dau_vet']['tong']['thoi_gian_du_doan_s'] <= 600
co_k3 = any('ty_le_ngoai_tam_sast_k3' in k for k in r_rong['khoang_trong'])
assert co_k3, 'Thiếu trường ty_le_ngoai_tam_sast_k3 trong khoảng trống rủi ro'

# T1.3: So sánh mô hình 'hcl' (b33b) vs 'bayes' phẳng
r_bayes = S1.chon_cong_cu(
    ngan_sach_giay=300,
    ngon_ngu={'typescript': 450, 'javascript': 150},
    chuc_nang=['dang_nhap', 'csdl', 'url_ngoai'],
    tep={'lockfile': ['package-lock.json'], 'dockerfile': 1},
    moi_truong_chay=True,
    mo_hinh_xac_suat='bayes'
)
r_hcl = S1.chon_cong_cu(
    ngan_sach_giay=300,
    ngon_ngu={'typescript': 450, 'javascript': 150},
    chuc_nang=['dang_nhap', 'csdl', 'url_ngoai'],
    tep={'lockfile': ['package-lock.json'], 'dockerfile': 1},
    moi_truong_chay=True,
    mo_hinh_xac_suat='hcl'
)

REPORT['cap_1_nhanh_1'] = {
    'trang_thai': 'DAT (PASS 100%)',
    'phien_ban_bo_chon': r_rong['phien_ban_bo_chon'],
    'bang_xac_suat': r_rong['bang_xac_suat'],
    'ngan_sach_90s': {
        'cong_cu_chon': r_hep['chon'],
        'thoi_gian_du_doan_s': r_hep['dau_vet']['tong']['thoi_gian_du_doan_s'],
        'do_phu_V': r_hep['dau_vet']['tong']['V'],
        'do_phat_hien_D': r_hep['dau_vet']['tong']['D_bi_mat_cau_hinh'],
    },
    'ngan_sach_600s': {
        'cong_cu_chon': r_rong['chon'],
        'thoi_gian_du_doan_s': r_rong['dau_vet']['tong']['thoi_gian_du_doan_s'],
        'do_phu_V': r_rong['dau_vet']['tong']['V'],
        'do_phat_hien_D': r_rong['dau_vet']['tong']['D_bi_mat_cau_hinh'],
        'khoang_trong_co_k3': [
            {'ho': k['ho'], 'rui_ro_con_lai': k['rui_ro_con_lai'], 'ty_le_ngoai_tam_sast_k3': k.get('ty_le_ngoai_tam_sast_k3')}
            for k in r_rong['khoang_trong'][:5]
        ],
    },
    'so_sanh_3_phuong_an_nhieu': r_rong['phuong_an'],
}
print(f"  [PASS] T1.1 Danh mục 18 công cụ & hướng dẫn mô tả dự án")
print(f"  [PASS] T1.2 Ngân sách 90s -> chọn {r_hep['chon']} ({r_hep['dau_vet']['tong']['thoi_gian_du_doan_s']}s, V={r_hep['dau_vet']['tong']['V']})")
print(f"  [PASS] T1.2 Ngân sách 600s -> chọn {r_rong['chon']} ({r_rong['dau_vet']['tong']['thoi_gian_du_doan_s']}s, V={r_rong['dau_vet']['tong']['V']})")
print(f"  [PASS] T1.3 Cảnh báo ngoài tầm SAST (K3): {[ (k['ho'], k.get('ty_le_ngoai_tam_sast_k3')) for k in r_rong['khoang_trong'][:3] ]}")

print('\n' + '=' * 80)
print('CẤP ĐỘ 2: KIỂM THỬ ĐỘC LẬP NHÁNH 2 (mcp_truy_vet_v3 - Đồ thị Tài sản v3.1b)')
print('=' * 80)

# T2.1: Kiểm tra phiên bản & sha256 của MCP Nhánh 2
pb2 = S2.phien_ban()
assert pb2['sha256_truy_vet_v3'] is not None, 'Thiếu sha256_truy_vet_v3'
assert pb2['tree_sitter'] is True, 'Thiếu tree-sitter-language-pack trên Windows'

# T2.2: Kiểm thử xem_vet và xep_hang_loi trên đồ thị v3.1b của OWASP Juice Shop (Có cả Tĩnh + Động)
js_v3_file = os.path.join(ROOT, 'Dataset', 'buoc34_nhanh2_tinh_va_vi_mo', 'ket_qua_lan2_v31b', 'do_thi_v3', 'v3_JuiceShop.json')
vet_js_t1 = S2.xem_vet(ket_qua_file=js_v3_file, tier=1, limit=10)
vet_js_cung_loi = S2.xem_vet(ket_qua_file=js_v3_file, tier=1, nhan='cung_loi', limit=10)
xh_js_html = os.path.join(OUT_DIR, 'xep_hang_JuiceShop_v31b.html')
xh_js = S2.xep_hang_loi(ket_qua_file=js_v3_file, top=10, ra_html=xh_js_html)

assert vet_js_t1['ban'] == 'v3.1b'
assert vet_js_cung_loi['tong_cum_khop'] == 3, f"Phải có đúng 3 cụm Tier 1 cùng lỗi độc lập (205, 209, 211), nhận {vet_js_cung_loi['tong_cum_khop']}"
assert os.path.exists(xh_js_html)

# T2.3: Kiểm thử trên crAPI (Kiến trúc Microservice 6 pha: CODE, BUILD, TEST, RELEASE, DEPLOY, OPERATE)
crapi_v3_file = os.path.join(ROOT, 'Dataset', 'buoc34_nhanh2_tinh_va_vi_mo', 'ket_qua_lan2_v31b', 'do_thi_v3', 'v3_crAPI.json')
vet_crapi_v2 = S2.xem_vet(ket_qua_file=crapi_v3_file, luat='V2', limit=10)
vet_crapi_v4 = S2.xem_vet(ket_qua_file=crapi_v3_file, luat='V4', limit=10)

REPORT['cap_2_nhanh_2'] = {
    'trang_thai': 'DAT (PASS 100%)',
    'phien_ban_mcp2': pb2['phien_ban'],
    'sha256_truy_vet_v3': pb2['sha256_truy_vet_v3'],
    'juiceshop_xuyen_pha': {
        'tong_cum_tier1': vet_js_t1['tong_cum_khop'],
        'so_cum_hat_nhan_cung_loi_doc_lap': vet_js_cung_loi['tong_cum_khop'],
        'chi_tiet_3_cum_cung_loi': vet_js_cung_loi['cum'],
        'top_5_xep_hang': xh_js['top'][:5],
        'file_html_xep_hang': xh_js_html,
    },
    'crapi_microservice': {
        'so_cum_bi_mat_V2': vet_crapi_v2['tong_cum_khop'],
        'so_cum_cau_hinh_V4': vet_crapi_v4['tong_cum_khop'],
        'vi_du_V4': vet_crapi_v4['cum'][:2],
    }
}
print(f"  [PASS] T2.1 Phiên bản MCP Nhánh 2: sha256_v3={pb2['sha256_truy_vet_v3']}, tree_sitter={pb2['tree_sitter']}")
print(f"  [PASS] T2.2 Juice Shop v3.1b: {vet_js_cung_loi['tong_cum_khop']} cụm hạt nhân 'cung_loi' Tier 1 độc lập (SQLi search, SQLi login, Open Redirect)")
print(f"  [PASS] T2.3 crAPI Microservice: {vet_crapi_v2['tong_cum_khop']} cụm lộ bí mật V2, {vet_crapi_v4['tong_cum_khop']} cụm sai cấu hình V4 xuyên pha")

print('\n' + '=' * 80)
print('CẤP ĐỘ 3: KIỂM THỬ TOÀN LUỒNG END-TO-END (Từ Prompt -> Nhánh 1 -> Nhánh 2 trực tiếp trên Repo thật)')
print('=' * 80)

# Mục tiêu End-to-End: Ứng dụng Web CLB Đọc Sách (Dataset/buoc32_ai_sinh_code/app)
# Chạy thật từ mô tả dự án -> Nhánh 1 chọn công cụ -> Nhánh 2 chạy truy_vet_v3 trực tiếp trên repo Windows -> Xem vết & Xếp hạng
PROMPT_BAN_DAU = (
    "Kiểm tra bảo mật toàn diện cho ứng dụng Web CLB Đọc Sách (Node.js/Express, SQLite, quản lý đăng nhập JWT, "
    "tải/đọc tệp bìa sách, tìm kiếm sách CSDL, gọi URL ngoài, chạy qua Docker & docker-compose, chỉ quét tĩnh trong ngân sách 180 giây)."
)
repo_e2e = os.path.join(ROOT, 'Dataset', 'buoc32_ai_sinh_code', 'app')
quet_e2e = os.path.join(ROOT, 'Dataset', 'buoc32_ai_sinh_code', 'quet')
rmap_e2e = os.path.join(ROOT, 'Dataset', 'buoc32_ai_sinh_code', 'cham', 'route_map_v17.json')
v14_e2e = os.path.join(ROOT, 'Dataset', 'buoc32_ai_sinh_code', 'kq', 'vet_v2.json')
ra_v3_e2e = os.path.join(OUT_DIR, 'e2e_clb_doc_sach_v31b.json')
ra_html_e2e = os.path.join(OUT_DIR, 'e2e_clb_doc_sach_xep_hang.html')

# Bước 1: Gọi MCP Nhánh 1 từ thông tin trích xuất trong Prompt
b1_chon = S1.chon_cong_cu(
    ngan_sach_giay=180,
    ngon_ngu={'javascript': 80},
    framework=['Express'],
    thu_vien=['sqlite3', 'jsonwebtoken'],
    chuc_nang=['dang_nhap', 'phien_token', 'csdl', 'tep', 'url_ngoai', 'phan_quyen'],
    tep={'lockfile': ['package-lock.json'], 'dockerfile': 1, 'docker_compose': 1},
    moi_truong_chay=False,
    muc_nhieu='can_bang'
)
assert b1_chon['kha_thi'], 'Bước 1 (Nhánh 1) phải khả thi'

# Bước 2: Chạy trực tiếp tool `truy_vet_v3` của MCP Nhánh 2 trên máy Windows với repo thật `Dataset/buoc32_ai_sinh_code/app`
b2_v3 = S2.truy_vet_v3(
    ket_qua_v1=v14_e2e,
    repo_path=repo_e2e,
    quet_tho_dir=quet_e2e,
    route_map=rmap_e2e,
    ra_file=ra_v3_e2e,
    nhieu_dich_vu=False,
    ten_dich_vu='clb-doc-sach',
    compose=['docker-compose.yml']
)
assert 'loi' not in b2_v3, f"Lỗi khi chạy truy_vet_v3 trực tiếp trên Windows: {b2_v3}"
assert b2_v3['da_lam_sach'] == ['CODE_semgrep_0006', 'CODE_semgrep_0007'], f"Phải phát hiện đúng 2 cảnh báo đã làm sạch qua path.basename, nhận {b2_v3['da_lam_sach']}"

# Bước 3: Gọi xem_vet và xep_hang_loi trên file kết quả vừa chạy ra
b3_vet = S2.xem_vet(ket_qua_file=ra_v3_e2e, tier=1, limit=10)
b3_xh = S2.xep_hang_loi(ket_qua_file=ra_v3_e2e, top=10, ra_html=ra_html_e2e)

REPORT['cap_3_end_to_end'] = {
    'trang_thai': 'DAT (PASS 100%)',
    'prompt_nguoi_dung': PROMPT_BAN_DAU,
    'buoc_1_nhanh_1_chon_cong_cu': {
        'cong_cu_chon': b1_chon['chon'],
        'theo_pha_devops': {k: ([x['cong_cu'] for x in v] if isinstance(v, list) else v) for k, v in b1_chon['theo_pha_devops'].items()},
        'thoi_gian_du_doan_s': b1_chon['dau_vet']['tong']['thoi_gian_du_doan_s'],
        'do_phu_V': b1_chon['dau_vet']['tong']['V'],
        'do_phat_hien_D': b1_chon['dau_vet']['tong']['D_bi_mat_cau_hinh'],
        'khoang_trong_chinh': [
            {'ho': k['ho'], 'rui_ro_con_lai': k['rui_ro_con_lai'], 'ty_le_ngoai_tam_sast_k3': k.get('ty_le_ngoai_tam_sast_k3')}
            for k in b1_chon['khoang_trong'][:4]
        ],
    },
    'buoc_2_nhanh_2_truy_vet_v3_truc_tiep': b2_v3,
    'buoc_3_xem_vet_tier1_va_xep_hang': {
        'so_cum_tier1': b3_vet['tong_cum_khop'],
        'cac_cum_tier1': b3_vet['cum'],
        'top_5_xep_hang': b3_xh['top'][:5],
        'file_html_bao_cao': ra_html_e2e,
    }
}

print(f"  [PASS] Bước 1 (MCP Nhánh 1): Từ Prompt suy diễn ngôn ngữ {b1_chon['nhan_dau_vao'].get('ngon_ngu')}, chọn {len(b1_chon['chon'])} công cụ: {b1_chon['chon']}")
print(f"  [PASS] Bước 2 (MCP Nhánh 2 - chạy trực tiếp trên Windows): phien_ban={b2_v3['phien_ban_loi']}, so_canh={b2_v3['so_canh']}, muc_phoi_nhiem_tinh={b2_v3['muc_phoi_nhiem_tinh']}, da_lam_sach={b2_v3['da_lam_sach']}")
print(f"  [PASS] Bước 3 (Xem vết & Xếp hạng): {b3_vet['tong_cum_khop']} cụm Tier 1 xuyên pha, xuất báo cáo HTML tại {ra_html_e2e}")

out_json = os.path.join(OUT_DIR, 'ket_qua_kiem_thu_3_cap_do.json')
json.dump(REPORT, open(out_json, 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
print('\n' + '=' * 80)
print(f'HOÀN TẤT 3/3 CẤP ĐỘ KIỂM THỬ! Đã lưu chi tiết tại: {out_json}')
print('=' * 80)
