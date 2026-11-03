# -*- coding: utf-8 -*-
"""Nhóm công cụ đã chọn theo pha DevOps + hồ sơ ưu/nhược. Không đổi thuật toán chọn.
Con số lấy lúc chạy từ catalog + do_phat_hien_buoc4; câu định tính gắn nguồn."""
CAC_PHA = ['PLAN', 'CODE', 'BUILD', 'TEST', 'RELEASE', 'DEPLOY', 'OPERATE', 'MONITOR']
MAP = {'Code': 'CODE', 'Build': 'BUILD', 'Test': 'TEST', 'Release': 'RELEASE', 'Deploy': 'DEPLOY', 'Operate': 'OPERATE'}


import math, re
def pc(x): return f'{math.floor(x * 100 + 0.5 + 1e-9)}%'


def _dung_mau(CAT, t):
    cb = CAT[t]['canh_bao']; r = cb.get('ty_le_dung_mau')
    if r is None: return None
    w = cb.get('wilson95')
    kr = cb.get('khong_ro') or 0
    return (f"khoảng {pc(r)} cảnh báo là đúng (tính trên {cb['mau'] - kr} cảnh báo có đáp án" + (f", bỏ {kr} cảnh báo không rõ đúng/sai" if kr else '')
            + f"; Wilson95 {pc(w[0])}–{pc(w[1])})")


def ho_so(t, CAT, DO4, langs=()):
    """Trả (manh, yeu): mỗi phần tử là (câu, nguồn)."""
    d = DO4.get(t, {}); manh, yeu = [], []
    dm = _dung_mau(CAT, t)
    if dm: yeu.append((f'Độ chính xác của cảnh báo: {dm}.', 'catalog.canh_bao'))
    JS = bool({'javascript', 'typescript'} & set(langs))
    if t in ('semgrep', 'codeql'):
        j, p, js = d['OWASP_Benchmark_Java'], d['OWASP_Benchmark_Python'], d['Juice_Shop_27_dong_loi']
        do = []
        if 'java' in langs:
            if t == 'semgrep':
                manh.append((f"Java: bắt đúng {pc(j['bat_dung'])} lỗi trên OWASP Benchmark.", 'do_phat_hien.semgrep.Java'))
                do.append(f"Java báo nhầm {pc(j['bao_nham'])}")
            else:
                do.append(f"Java không build: chỉ bắt {pc(j['bat_dung'])} (Youden {j['Youden_TB']})")
        if 'python' in langs:
            do.append(f"Python chỉ bắt {pc(p['bat_dung'])} (báo nhầm {p['bao_nham']:.1%})")
        if JS:
            (manh if t == 'codeql' else yeu).append((f"Juice Shop (ứng dụng JavaScript): bắt {js} dòng lỗi" + (' – nhiều hơn semgrep trên cùng bộ [diễn giải: xếp vào điểm mạnh vì so với semgrep]' if t == 'codeql' else '') + '.', f'do_phat_hien.{t}.Juice_Shop'))
        if not (set(langs) & {'java', 'python', 'javascript', 'typescript'}):
            do.append(f"ngôn ngữ của dự án ({', '.join(langs) or 'không rõ'}) chưa có số đo trực tiếp ở bước 4; xác suất trong bộ chọn ước từ bộ 7003 ca + 1152 CVE ứng dụng")
        if do: yeu.append(('; '.join(do) + '.', f'do_phat_hien.{t}'))
        if t == 'codeql':
            yeu.append(('Thời gian quét lâu hơn semgrep (khoảng p10–p90 trong catalog).' + (' Go cần build nên codeql không chạy được trên phần Go.' if 'go' in langs else ''), 'catalog.dau_vao + thoi_gian'))
    elif t == 'bandit':
        p = d['OWASP_Benchmark_Python']
        manh.append((f"Báo nhầm trên Python {p['bao_nham']:.1%} (semgrep 13.6%, codeql 20.1% trên cùng bộ); thời gian quét p10–p90 {CAT[t]['thoi_gian']['khoang_p10_p90_s'][0]}–{CAT[t]['thoi_gian']['khoang_p10_p90_s'][1]} s.", 'do_phat_hien.bandit + catalog.thoi_gian'))
        yeu.append((f"Chỉ quét Python; chỉ bắt {pc(p['bat_dung'])} lỗi trên OWASP Benchmark Python; với cấu hình khuyến nghị (bỏ B101 và mã test) khối lượng ~{CAT[t]['canh_bao']['khoi_luong_trung_vi']} cảnh báo/1000 dòng.", 'do_phat_hien.bandit + catalog.canh_bao (bước 13)'))
    elif t == 'njsscan':
        yeu.append((f"Trên Juice Shop bắt {d['Juice_Shop_27_dong_loi']} dòng lỗi; cận trên thời gian chưa có công thức đạt chuẩn nên dùng p90 (ước lượng thô).", 'do_phat_hien.njsscan + catalog.thoi_gian'))
    elif t in ('eslint_security', 'eslint_mo_rong'):
        yeu.append((f"KHÔNG quét tệp .ts (Juice Shop {d['Juice_Shop_27_dong_loi']} là do cả 27 dòng lỗi nằm trong tệp .ts – không áp dụng, không phải bằng chứng bắt kém); chưa có số đo trên ứng dụng JS thật; " + ('nhiều luật phong cách nên ồn.' if t == 'eslint_mo_rong' else 'phạm vi: mẫu nguy hiểm JS.'), 'do_phat_hien + catalog.dau_vao'))
        manh.append((f"Thời gian quét p10–p90 {CAT[t]['thoi_gian']['khoang_p10_p90_s'][0]}–{CAT[t]['thoi_gian']['khoang_p10_p90_s'][1]} s.", 'catalog.thoi_gian'))
    elif t == 'gitleaks':
        b = d['bi_mat_E4']
        manh.append((f"Bí mật: bắt {b['bat']} (Wilson95 {pc(b['ci'][0])}–{pc(b['ci'][1])}), báo nhầm mồi nhử {b['bao_nham_moi_nhu']}; thời gian quét p10–p90 {CAT[t]['thoi_gian']['khoang_p10_p90_s'][0]}–{CAT[t]['thoi_gian']['khoang_p10_p90_s'][1]} s.", 'do_phat_hien.gitleaks'))
        yeu.append(('Quét cây tệp hiện tại, không quét lịch sử git (bí mật đã xóa khỏi tệp nhưng còn trong lịch sử sẽ không thấy).', 'catalog.dau_vao'))
        yeu.append(('Lưu ý: tỷ lệ "cảnh báo đúng" (bước 1, mẫu 20 cảnh báo) và tỷ lệ bắt bí mật 43/48 (bước 4a) đo trên hai bộ khác nhau; chưa đối chiếu được với nhau.', 'catalog.canh_bao vs do_phat_hien.gitleaks'))
    elif t == 'osv-scanner':
        sca = d.get('SCA_91_du_an_npm', {})
        if sca:
            manh.append((f"Thư viện phụ thuộc (SCA): bắt {sca['bat']} lỗ hổng trên 91 dự án npm (Wilson95 {pc(sca['ci'][0])}–{pc(sca['ci'][1])}), báo nhầm dự án sạch {sca['bao_nham_du_an_sach']}; thời gian p10–p90 {CAT[t]['thoi_gian']['khoang_p10_p90_s'][0]}–{CAT[t]['thoi_gian']['khoang_p10_p90_s'][1]} s.", 'do_phat_hien.osv-scanner + catalog.thoi_gian'))
        else:
            manh.append((f"Thời gian quét p10–p90 {CAT[t]['thoi_gian']['khoang_p10_p90_s'][0]}–{CAT[t]['thoi_gian']['khoang_p10_p90_s'][1]} s.", 'catalog.thoi_gian'))
        yeu.append(('Chỉ quét lockfile/manifest có phiên bản ở pha Build (không quét các gói hệ điều hành bên trong container image ở pha Release).', 'catalog.dau_vao'))
    elif t == 'syft':
        yeu.append(('Chỉ liệt kê SBOM, không đưa ra cảnh báo lỗ hổng.', 'catalog.pham_vi'))
    elif t == 'trivy':
        b, c = d['bi_mat_E4'], d['cau_hinh_E5_cham_chat']
        manh.append((f"Bí mật {b['bat']} và cấu hình E5 {c['bat']}; Terraform {c['theo_loai']['terraform']}, K8s {c['theo_loai']['k8s']}, CloudFormation {c['theo_loai']['cloudformation']}.", 'do_phat_hien.trivy'))
        yeu.append((f"GitHub Actions {c['theo_loai']['gh_actions']}; Dockerfile {c['theo_loai']['dockerfile']}; KHÔNG đọc docker-compose.", 'do_phat_hien.trivy + catalog.dau_vao'))
    elif t == 'checkov':
        c = d['cau_hinh_E5_cham_chat']
        manh.append((f"Cấu hình hạ tầng: bắt {c['bat']} (Wilson95 {pc(c['ci'][0])}–{pc(c['ci'][1])}); Terraform {c['theo_loai']['terraform']}; là công cụ duy nhất trong danh mục bắt được lỗi GitHub Actions ({c['theo_loai']['gh_actions']}).", 'do_phat_hien.checkov'))
        yeu.append(('KHÔNG đọc docker-compose; bỏ sót k8s_hostpath và df_secret_env; 4/20 cảnh báo trong mẫu đo không rõ đúng/sai.', 'do_phat_hien.checkov + catalog.dau_vao'))
    elif t == 'hadolint':
        c = d['cau_hinh_E5_cham_chat']
        yeu.append((f"Chỉ Dockerfile; bắt {c['bat']} lỗi cấu hình E5; phần lớn luật là thực hành tốt, không phải bảo mật.", 'do_phat_hien.hadolint + catalog.pham_vi'))
    elif t == 'kics':
        c, dc, rb = d['cau_hinh_E5_cham_chat'], d['docker_compose_13_bien_the'], d['Release_B_24_ca_Dockerfile']
        manh.append((f"Cấu hình IaC (E5 chấm chặt): bắt {c['bat']} (Wilson95 {pc(c['ci'][0])}–{pc(c['ci'][1])}) – bắt đủ Terraform {c['theo_loai']['terraform']}, K8s {c['theo_loai']['k8s']}, CloudFormation {c['theo_loai']['cloudformation']} và Dockerfile {c['theo_loai']['dockerfile']} (trên Release_B bắt {rb['bat_ca']} ca = {rb['bat_lop']} lớp); hỗ trợ docker-compose bắt {dc['bat']} biến thể (Wilson95 {pc(dc['ci'][0])}–{pc(dc['ci'][1])}, 0 báo nhầm trên base cứng hóa).", 'do_phat_hien.kics'))
        yeu.append((f"GitHub Actions bắt {c['theo_loai']['gh_actions']}; quét tĩnh nên không thấy tệp nhạy cảm nằm trong tầng container image đã build (env_file, ssh_key) hoặc trạng thái giới hạn tài nguyên lúc chạy.", 'do_phat_hien.kics'))
    elif t == 'grype':
        sca, ra = d['SCA_91_du_an_npm'], d['Release_A_13_image_CVE']
        manh.append((f"Bao phủ cả pha Build (lockfile: bắt {sca['bat']} CVE trên 91 dự án npm, Wilson95 {pc(sca['ci'][0])}–{pc(sca['ci'][1])}, 0/10 báo nhầm) và pha Release (container image: bắt {ra['bat']} CVE trên 13 Node image, quét được {ra['so_goi_os_quet_duoc']} gói OS Debian/image, nhanh hơn Trivy image scan: trung vị {ra['thoi_gian_trung_vi_s']}s vs 16.8s).", 'do_phat_hien.grype'))
        yeu.append(('Chỉ phát hiện CVE đã biết của gói phần mềm/OS, không kiểm tra cấu hình CIS hay bí mật rò rỉ trong các tầng image.', 'catalog.pham_vi'))
    elif t == 'dockle':
        rb = d['Release_B_24_ca_container_image']
        manh.append((f"Kiểm tra trực tiếp container image đã đóng gói ở pha Release: bắt {rb['bat_ca']} ca ({rb['bat_lop']} lớp, Wilson95 {pc(rb['ci'][0])}–{pc(rb['ci'][1])}); bắt độc quyền 2 lớp nguy hiểm nằm trong tầng image ({', '.join(rb['bat_doc_quyen_trong_image'])}) mà các công cụ quét Dockerfile tĩnh đều bỏ sót.", 'do_phat_hien.dockle'))
        yeu.append((f"Cần container image đã được build; trung bình {rb['canh_bao_image_sach_tb']} cảnh báo trên mỗi image sạch.", 'do_phat_hien.dockle'))
    elif t == 'docker_bench':
        dp = d['Deploy_Operate_13_container_runtime']
        manh.append((f"Công cụ pha Operate kiểm toán trực tiếp container đang chạy theo CIS Docker Benchmark: bắt {dp['bat']} biến thể lỗi (Wilson95 {pc(dp['ci'][0])}–{pc(dp['ci'][1])}); bắt được lỗi vận hành ({', '.join(dp['bat_doc_quyen_runtime_so_voi_kics'])}) mà công cụ quét tĩnh KICS bỏ sót (kết hợp KICS + Docker Bench đạt 11/13).", 'do_phat_hien.docker_bench'))
        yeu.append((f"Thời gian chạy ~{dp['thoi_gian_s']} s (gồm khởi tạo container kiểm thử); sinh {dp['canh_bao_base_cung_hoa']} cảnh báo trên cấu hình base cứng hóa.", 'do_phat_hien.docker_bench + catalog.thoi_gian'))
    elif t == 'nuclei':
        nc = d['gr2_vulnapp_10_lop_3_lan']['ket_hop_dast_exposures']
        manh.append((f"Quét động (pha Test) nhanh và ổn định (3 lần đo: {', '.join(str(x)+'s' for x in nc['thoi_gian_3_lan_s'])}, trung vị {nc['trung_vi_s']}s): bắt {nc['bat']} lớp lỗ hổng trên gr2-vulnapp (Wilson95 {pc(nc['ci'][0])}–{pc(nc['ci'][1])}: {', '.join(nc['lop_bat_duoc'])}) với {nc['bao_nham_safe_route']} báo nhầm trên 9 route an toàn; bắt được lộ tệp /.env (exposed_file) mà ZAP bỏ sót.", 'do_phat_hien.nuclei'))
        yeu.append(('Không tự phát hiện thiếu header bảo mật, cờ cookie, CORS hoặc SQLi phức tạp như ZAP full scan (hợp Nuclei + ZAP đạt 10/10 lớp trên gr2-vulnapp).', 'do_phat_hien.nuclei + do_phat_hien.zap'))
    elif t == 'zap':
        z, tg = d['Juice_Shop_19_lo_hong_khong_dang_nhap'], d['thoi_gian_phut']
        gv = d.get('gr2_vulnapp_10_lop', {}).get('zap_full', {})
        manh.append((f"Quét động toàn diện (pha Test): trên gr2-vulnapp bắt {gv.get('bat', '9/10')} lớp lỗ hổng (bao gồm SQLi, thiếu header, cookie, CORS, lộ stacktrace mà Nuclei không bắt).", 'do_phat_hien.zap'))
        yeu.append((f"Trên Juice Shop chưa đăng nhập bắt chặt {z['chat']} lỗ hổng (Wilson95 {pc(z['ci'][0])}–{pc(z['ci'][1])}); bỏ sót lộ tệp /.env (exposed_file) trên gr2-vulnapp. Thời gian lâu ({tg['min_max'][0]}–{tg['min_max'][1]} phút, cận trên 900s) nên không vừa ngân sách pipeline ngắn (khi đó Nuclei ~64s sẽ thay thế).", 'do_phat_hien.zap + catalog.thoi_gian'))
    return manh, yeu


def theo_pha(chon, trace, CAT, DO4, langs=()):
    """Nhóm công cụ đã chọn theo 8 pha DevOps."""
    pha = {p: [] for p in CAC_PHA}
    for t in chon:
        rec = trace['cong_cu'][t]; cat = CAT[t]
        ps = [MAP[x.strip()] for x in cat['pha'].split('/')]
        manh, yeu = ho_so(t, CAT, DO4, langs)
        item = {'cong_cu': t, 'vai_tro': '; '.join(x for x in re.split(r';\s*', rec.get('vai_tro') or '') if x), 'dau_vao': cat['dau_vao'], 'pham_vi': cat['pham_vi'],
                'thoi_gian_du_doan_s': rec['thoi_gian_du_doan_s'], 'canh_bao_sai_du_kien': rec['canh_bao_sai_du_kien'],
                'diem_manh': [{'noi_dung': a, 'nguon': b} for a, b in manh],
                'diem_yeu': [{'noi_dung': a, 'nguon': b} for a, b in yeu]}
        if rec.get('ghi_chu') and not (t == 'codeql' and 'java' in langs): item['diem_yeu'].append({'noi_dung': rec['ghi_chu'], 'nguon': 'chon.py ghi_chu'})
        if len(ps) > 1: item['ghi_chu_pha'] = f"khai báo thuộc {' và '.join(ps)}; chỉ chạy 1 lần, hiện ở cả hai pha"
        for p in ps: pha[p].append(item)
    return {p: (v if v else 'chưa có công cụ nào trong danh mục cho pha này') for p, v in pha.items()}


NGUON_BANG = '2300 thông báo lỗ hổng công khai (CVE/GHSA) – bước 2; có thể lệch so với lỗi của dự án thực tế'
NGUONG_MONG = 100  # chức năng có n < 100 thông báo bị coi là dữ liệu mỏng


def chuc_nang_hay_gap_loi(chuc_nang, BANG, khoang_trong):
    kt = {k['ho']: k['rui_ro_con_lai'] for k in khoang_trong}
    out = []
    for f in chuc_nang:
        b = BANG['chuc_nang'].get(f)
        if not b: continue
        ho = [h for h in b['ho'] if h['noi_bat']]
        item = {'chuc_nang': f, 'so_thong_bao': b['n'], 'nguon': NGUON_BANG,
                'ho_noi_bat': [{'ho': h['ho'], 'ty_le': h['p'], 'wilson95': h['ci'], 'so_ca': h['k'],
                                'rui_ro_con_lai_toan_du_an': kt.get(h['ho'])} for h in ho],
                'ho_khac': next(({'ty_le': h['p'], 'wilson95': h['ci']} for h in b['ho'] if h['ho'] == 'khac'), None)}
        if b['n'] < NGUONG_MONG: item['canh_bao'] = f"dữ liệu mỏng (chỉ {b['n']} thông báo) – khoảng tin cậy rộng, chỉ tham khảo"
        out.append(item)
    return out


def dong_chuc_nang(items):
    d = []
    for it in items:
        hs = '; '.join(f"{h['ho']} {pc(h['ty_le'])} (Wilson95 {pc(h['wilson95'][0])}–{pc(h['wilson95'][1])})"
                       + (f", còn hở {pc(h['rui_ro_con_lai_toan_du_an'])} toàn dự án" if h['rui_ro_con_lai_toan_du_an'] else '') for h in it['ho_noi_bat'])
        k = it['ho_khac']
        d.append(f"- {it['chuc_nang']} (n={it['so_thong_bao']}): hay gặp {hs or 'không có họ nào nổi bật'}"
                 + (f"; ngoài ra {pc(k['ty_le'])} không phân loại được (\"khac\")" if k else '')
                 + (f" [{it['canh_bao']}]" if 'canh_bao' in it else ''))
    return d
