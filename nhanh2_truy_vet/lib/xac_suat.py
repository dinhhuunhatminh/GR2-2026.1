# Bản rút gọn của buoc5_mcp/.../lib/xac_suat.py: CHỈ bảng CWE->họ lỗi (dòng 7-12 của bản gốc, nguyên văn), bỏ numpy/mô hình xác suất không dùng ở nhánh 2.
CWE2FAM = {'sqli': ['CWE-89'], 'cmd': ['CWE-77', 'CWE-78', 'CWE-88', 'CWE-74'], 'xss': ['CWE-79', 'CWE-80', 'CWE-116', 'CWE-184'],
 'path': ['CWE-22', 'CWE-23', 'CWE-73'], 'ssrf': ['CWE-918'], 'eval': ['CWE-94', 'CWE-95'], 'weak_hash': ['CWE-327', 'CWE-328', 'CWE-916'],
 'insecure_random': ['CWE-330', 'CWE-338', 'CWE-331'], 'open_redirect': ['CWE-601'], 'jwt_secret': ['CWE-347', 'CWE-345', 'CWE-798', 'CWE-259', 'CWE-321'],
 'cors': ['CWE-346', 'CWE-942'], 'regex': ['CWE-1333', 'CWE-400', 'CWE-185', 'CWE-770'], 'prototype': ['CWE-1321', 'CWE-471', 'CWE-915'],
 'validation': ['CWE-20', 'CWE-1286'], 'info_exposure': ['CWE-200', 'CWE-209', 'CWE-532', 'CWE-522'], 'access_control': ['CWE-862', 'CWE-863', 'CWE-284', 'CWE-285', 'CWE-306', 'CWE-639']}
C2F = {c: f for f, cs in CWE2FAM.items() for c in cs}
