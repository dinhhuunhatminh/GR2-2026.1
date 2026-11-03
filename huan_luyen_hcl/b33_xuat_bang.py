"""Bước 33.4 – bảng xác suất v11. Quy tắc đặt trước (như GD6 Bước 29): dùng A1 chỉ khi cận trên khoảng 95% của (Brier A1 − Brier A0) ≤ 0; ngược lại dùng A0, κ = giá trị A0 chọn nhiều nhất.
Kết quả H4 (b33_h4.json): cận trên +0,00039 > 0 → bảng dùng A0, κ=10. Thêm ngoai_tam_sast = P(K3 | L, h) (co về tỷ lệ K3 của ngôn ngữ, κ=10)."""
import sys, json, collections
sys.path.insert(0, '/home/claude/b33/ma')
import b33_dac_trung_va_nhan as D
H4 = json.load(open('/home/claude/b33/ket_qua/b33_h4.json'))
assert H4['hieu_so_voi_A0']['A1_b33|brier'][2] > 0
old = json.load(open('/home/claude/b29/v11/data/bang_hcl_b28.json'))
pairs = [(int(D.PC[p]), D.TOOLS[D.PT[p]], int(D.Y_HAM[p])) for p in range(D.NP) if D.Y_HAM[p] >= 0]
lang = [t['lang'] for t in D.T]; S = collections.defaultdict(lambda: [0, 0]); rate = collections.defaultdict(lambda: [0, 0])
for i, t, y in pairs:
    S[(lang[i], t, D.FAM[i])][0] += y; S[(lang[i], t, D.FAM[i])][1] += 1; rate[t][0] += y; rate[t][1] += 1
kap = old['kappa']; bad = 0; n = 0
for L, d in old['p'].items():
    for t, d2 in d.items():
        for h, v in d2.items():
            k, m = S.get((L, t, h), (0, 0)); new = round((k + kap * rate[t][0] / max(rate[t][1], 1)) / (m + kap), 6); n += 1; bad += abs(new - v) > 1e-6
print('o so sanh', n, 'lech', bad, 'kappa', kap)
K3 = [m['K'] == 'K3' for m in D.MD]; lr = {}; cell = collections.defaultdict(list)
for i in range(D.n): cell[(lang[i], D.FAM[i])].append(K3[i])
for L in D.LANGS: lr[L] = sum(K3[i] for i in range(D.n) if lang[i] == L) / sum(1 for i in range(D.n) if lang[i] == L)
nt = {}
for (L, h), v in cell.items(): nt.setdefault(L, {})[h] = {'p': round((sum(v) + 10 * lr[L]) / (len(v) + 10), 4), 'n': len(v)}
old['ngoai_tam_sast'] = {'dinh_nghia': 'P(K3 | ngon ngu, ho loi): ty le ban va cham >=4 tep hoac thiet ke (nhan K3), co ve ty le K3 cua ngon ngu, kappa=10. Khong do truc tiep phan ngoai tam SAST.', 'bang': nt}
old['phien_ban'] = 'hcl_b33_A0'; old['ghi_chu_b33'] = 'H4 b33: A1_b33 khong tot hon A0 theo quy tac dat truoc -> p giu nhu A0 (kappa=10); chi them ngoai_tam_sast.'
json.dump(old, open('/home/claude/b29/v11/data/bang_hcl_b33.json', 'w'), ensure_ascii=False)
json.dump(old, open('/home/claude/b33/ket_qua/bang_hcl_b33.json', 'w'), ensure_ascii=False)
