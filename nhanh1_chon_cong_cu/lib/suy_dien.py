# -*- coding: utf-8 -*-
"""Tầng suy diễn đầu vào (bước 7, PHIEU_SUY_DIEN; cập nhật v8 bước 21). Mỗi trường có nhãn nguồn: khach_noi / suy_ra (mã quy tắc) /
suy_ra_tro_ly / mac_dinh / bo_trong. Điểm nhạy: chạy lại bộ chọn với giá trị thay thế cho trường không phải khach_noi."""
import json, os
QT = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data', 'quy_tac_suy_dien.json'), encoding='utf-8'))
LOCK_THEO_NN = {'javascript': 'package-lock.json', 'typescript': 'package-lock.json', 'python': 'requirements.txt', 'java': 'pom.xml', 'go': 'go.mod', 'php': 'composer.lock'}
TEP_HOI = ('dockerfile', 'docker_compose', 'gh_actions')
def _chuan(x): return ' '.join(str(x).lower().strip().split())
def tim_framework(ten):
    t = _chuan(ten)
    for k, v in QT['R1_framework'].items():
        if t == k or t in v['bi_danh']: return k, v
    return None, None
def tim_cong_nghe(ten):
    t = _chuan(ten)
    return [cn for cn, v in QT['R2_cong_nghe'].items() if t in v['ten']]

def suy_dien(vao, LANGS, CO_VUA_KB):
    """vao: dict các tham số thô từ trợ lý. Trả (du_an, nhan, cau_hoi, ghi_chu)."""
    nhan, hoi, gc = {}, [], []
    nn = dict(vao.get('ngon_ngu') or {})
    for L in nn: nhan[f'ngon_ngu.{L}'] = {'nguon': 'khach_noi', 'gia_tri': L}
    fws = vao.get('framework') or []
    if isinstance(fws, str): fws = [fws]
    loai_tu_fw = None
    for f in fws:
        k, v = tim_framework(f)
        if not k: gc.append(f'framework "{f}" không có trong bảng quy tắc – không suy gì từ nó'); continue
        loai_tu_fw = v['loai']
        ho_tro = [L for L in v['ngon_ngu'] if L in LANGS]
        if not ho_tro: gc.append(f'{f}: ngôn ngữ {v["ngon_ngu"]} ngoài danh mục công cụ (R1:{k})'); continue
        if any(L in nn for L in v['ngon_ngu']): continue
        if len(ho_tro) == 1 and not nn:
            nn[ho_tro[0]] = None; nhan[f'ngon_ngu.{ho_tro[0]}'] = {'nguon': 'suy_ra', 'quy_tac': f'R1:{k}', 'gia_tri': ho_tro[0]}
        else:
            hoi.append(f'{f} có thể viết bằng {" hoặc ".join(v["ngon_ngu"])} – dự án dùng ngôn ngữ nào?')
    for L, kb in nn.items():
        nhan[f'kb.{L}'] = {'nguon': 'khach_noi', 'gia_tri': kb} if kb is not None else {'nguon': 'mac_dinh', 'gia_tri': CO_VUA_KB, 'ly_do': 'không biết dung lượng mã'}
        if kb is None: hoi.append(f'Mã {L} khoảng bao nhiêu KB/MB? (đang dùng mặc định {CO_VUA_KB} KB)')
    cn = list(vao.get('chuc_nang') or [])
    for c in cn: nhan[f'chuc_nang.{c}'] = {'nguon': 'khach_noi'}
    for c in vao.get('chuc_nang_suy_ra') or []:
        if c not in cn: cn.append(c); nhan[f'chuc_nang.{c}'] = {'nguon': 'suy_ra_tro_ly'}
    khong_ro = []
    for t in vao.get('thu_vien') or []:
        ms = tim_cong_nghe(t)
        if not ms: khong_ro.append(t)
        for c in ms:
            if c not in cn: cn.append(c); nhan[f'chuc_nang.{c}'] = {'nguon': 'suy_ra', 'quy_tac': f'R2:{_chuan(t)}'}
    if khong_ro: gc.append('tên công nghệ chưa có trong bảng quy tắc (không suy gì): ' + ', '.join(khong_ro))
    tep = dict(vao.get('tep') or {})
    for k in tep: nhan[f'tep.{k}'] = {'nguon': 'khach_noi', 'gia_tri': tep[k]}
    if tep.get('lockfile') is None:   # v10: lockfile=[] nghĩa là khách xác nhận KHÔNG có; chỉ hỏi khi bỏ trống
        gy = []
        for f in fws:
            k, v = tim_framework(f)
            if k: gy += [x for x in v['lockfile_thuong_gap'] if x not in gy]
        for L in nn:
            if L in LOCK_THEO_NN and LOCK_THEO_NN[L] not in gy: gy.append(LOCK_THEO_NN[L])
        nhan['tep.lockfile'] = {'nguon': 'bo_trong', 'goi_y': gy}
        if gy: hoi.append('Repo có lockfile/manifest ghim phiên bản không (ví dụ ' + ', '.join(gy[:3]) + ')?')
    for k in TEP_HOI:
        if k not in tep: nhan[f'tep.{k}'] = {'nguon': 'bo_trong'}
    mt = vao.get('moi_truong_chay')
    nhan['moi_truong_chay'] = {'nguon': 'khach_noi', 'gia_tri': bool(mt)} if mt is not None else {'nguon': 'bo_trong', 'gia_tri': False}
    ld = vao.get('loai_du_an')
    if ld: nhan['loai_du_an'] = {'nguon': 'khach_noi', 'gia_tri': ld}
    elif loai_tu_fw: nhan['loai_du_an'] = {'nguon': 'suy_ra', 'quy_tac': 'R3', 'gia_tri': loai_tu_fw}
    else: nhan['loai_du_an'] = {'nguon': 'mac_dinh', 'gia_tri': 'khong_ro'}
    nhan['ngan_sach'] = {'nguon': 'khach_noi', 'gia_tri': vao['ngan_sach']} if vao.get('ngan_sach') is not None else {'nguon': 'bo_trong'}
    for k in ('bat_buoc', 'cam'):
        nhan[k] = {'nguon': 'khach_noi', 'gia_tri': vao[k]} if vao.get(k) else {'nguon': 'bo_trong', 'gia_tri': []}
    if not nn and not any(v for v in tep.values()):
        hoi[:0] = ['Dự án viết bằng ngôn ngữ/framework nào, mã khoảng bao nhiêu KB/MB?', 'Các chức năng chính là gì (đăng nhập, tài khoản, upload, CSDL, API, thanh toán…)?',
                   'Repo có lockfile, Dockerfile, docker-compose, Terraform/Kubernetes, GitHub Actions không?']
    if vao.get('ngan_sach') is None: hoi.insert(0, 'Ngân sách thời gian tối đa cho bước quét bảo mật trong pipeline là bao nhiêu (giây/phút)? – bắt buộc, không tự đặt.')
    du_an = {'ngon_ngu': nn, 'chuc_nang': cn, 'tep': tep, 'ngan_sach': vao.get('ngan_sach'), 'bat_buoc': vao.get('bat_buoc') or [], 'cam': vao.get('cam') or []}
    if mt: du_an['moi_truong_chay'] = True
    for k in ('so_goi', 'tong_tep'):
        if vao.get(k): du_an[k] = vao[k]
    return du_an, nhan, hoi, gc

def diem_nhay(du_an, nhan, chay):
    """chay(du_an) -> danh sách công cụ. Thử giá trị thay thế cho mỗi trường không phải khach_noi."""
    goc = sorted(chay(du_an)); out = []
    def thu(ten, mo_ta, d2):
        moi = sorted(chay(d2))
        if moi != goc: out.append({'truong': ten, 'gia_dinh_hien_tai': nhan.get(ten, {}).get('nguon'), 'neu': mo_ta, 'them': sorted(set(moi) - set(goc)), 'bot': sorted(set(goc) - set(moi))})
    cp = lambda: json.loads(json.dumps(du_an))
    for k, v in nhan.items():
        if k.startswith('chuc_nang.') and v['nguon'] in ('suy_ra', 'suy_ra_tro_ly'):
            c = k.split('.', 1)[1]; d = cp(); d['chuc_nang'] = [x for x in d['chuc_nang'] if x != c]; thu(k, f'dự án KHÔNG có chức năng {c}', d)
        if k.startswith('kb.') and v['nguon'] == 'mac_dinh':
            L = k.split('.', 1)[1]
            for h, mt in ((0.5, 'nhỏ bằng nửa'), (2, 'lớn gấp đôi')):
                d = cp(); d['ngon_ngu'][L] = v['gia_tri'] * h; thu(k, f'mã {L} {mt} giá trị mặc định ({v["gia_tri"] * h:g} KB)', d)
    v = nhan.get('tep.lockfile')
    if v and v['nguon'] == 'bo_trong' and v.get('goi_y'):
        d = cp(); d['tep']['lockfile'] = [v['goi_y'][0]]; thu('tep.lockfile', f'repo CÓ lockfile ({v["goi_y"][0]})', d)
    for k in TEP_HOI:
        if nhan.get(f'tep.{k}', {}).get('nguon') == 'bo_trong':
            d = cp(); d['tep'][k] = 1; thu(f'tep.{k}', f'repo CÓ {k}', d)
    if nhan.get('moi_truong_chay', {}).get('nguon') == 'bo_trong':
        d = cp(); d['moi_truong_chay'] = True; thu('moi_truong_chay', 'CÓ bản chạy thử (URL) để quét động', d)
    return out


CAU_HOI_NHAY = {
    'tep.lockfile': None,
    'tep.dockerfile': 'Repo có Dockerfile không (để quét Dockerfile + container image ở pha Release)?',
    'tep.docker_compose': 'Repo có tệp docker-compose.yml không (để quét triển khai & runtime container ở pha Deploy/Operate)?',
    'tep.gh_actions': 'Repo có workflow GitHub Actions không?',
    'moi_truong_chay': 'Có bản chạy thử (URL staging) để quét động (Nuclei/ZAP ở pha Test) không?',
}
def cau_hoi_tu_diem_nhay(dn, hoi):
    """Thêm câu hỏi cho trường để trống mà điểm nhạy cho thấy sẽ làm đổi bộ công cụ."""
    for x in dn:
        q = CAU_HOI_NHAY.get(x['truong'])
        if q and q not in hoi: hoi.append(q)
    return hoi
