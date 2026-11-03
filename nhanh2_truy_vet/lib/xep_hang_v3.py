# -*- coding: utf-8 -*-
"""Bước 35: xếp hạng lỗi cho đầu ra truy_vet_v3. Dùng NGUYÊN công thức xep_hang.py (không sửa), rồi chia 2 phần, giữ thứ tự tương đối:
phần trên = nhóm có ít nhất một phát hiện KHÔNG thuộc M4_UNPACKAGED_DEAD (hoặc không có mức phơi nhiễm, như phát hiện ZAP); phần dưới = nhóm mà MỌI phát hiện đều là M4.
Quy tắc "M4 xuống cuối" là ĐỀ XUẤT của Claude (PHIEU_BUOC35.md, giả định A2), chưa có đáp án chuẩn. Không xóa nhóm nào. Không dùng AI."""
import collections
import xep_hang as XH

M4 = 'M4_UNPACKAGED_DEAD'


def xep_hang_v3(R):
    L = XH.xep_hang(R)                                   # thứ tự gốc (công thức Bước 23)
    muc = {f['finding_id']: f.get('muc_phoi_nhiem_tinh') for f in R['phat_hien']}
    for g in L:
        g['hang_goc'] = g['hang']
        g['chi_m4'] = bool(g['thanh_vien']) and all(muc.get(i) == M4 for i in g['thanh_vien'])
    F = {f['finding_id']: f for f in R['phat_hien']}
    for g in L:
        # Sửa SAU KHI THẤY KẾT QUẢ (Bước 35, lần chạy 1, H8iv): một nhóm có thể gồm cả mã chết (M4) lẫn mã chạy thật; vị trí hiển thị của nhóm cũ là thành viên đầu tiên nên có thể là mã chết.
        # Không đổi thứ tự, không đổi số nhóm: chỉ hiển thị vị trí của thành viên đầu tiên KHÔNG thuộc M4 và thêm thành phần M.
        g['vi_tri_goc'] = g['vi_tri']
        g['thanh_phan_m'] = dict(sorted(collections.Counter((muc.get(i) or '-').split('_')[0] for i in g['thanh_vien']).items()))
        for i in g['thanh_vien']:
            if muc.get(i) != M4:
                x = F[i]['anchors']; g['vi_tri'] = (x.get('file_path') or x.get('url_route') or x.get('package_name') or x.get('container_target') or ''); break
    tren = [g for g in L if not g['chi_m4']]; duoi = [g for g in L if g['chi_m4']]
    L2 = tren + duoi
    for i, g in enumerate(L2, 1): g['hang'] = i
    return L2, len(duoi)
