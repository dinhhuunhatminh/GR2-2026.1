"""Mô hình xác suất bước 33b (Two-Stage Calibrated Joint HMLC): đọc bảng xuất sẵn data/bang_hcl_b33b.json."""
import json, os
D = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data')

class MoHinhHCLb28:
    ten = 'hcl_b33b'
    mo_ta = 'Bảng xác suất bước 33b: p = (k + κ·μ)/(m + κ), μ từ Two-Stage Calibrated Joint HMLC (co cụm Bayes 2 tầng), κ = 10'
    def __init__(self, path=os.path.join(D, 'bang_hcl_b33b.json')):
        if not os.path.exists(path):
            path = os.path.join(D, 'bang_hcl_b33.json')
        b = json.load(open(path, encoding='utf-8'))
        self.p, self.prior, self.info, self.kappa = b['p'], b['prior'], b['thong_tin_o'], b['kappa']
        self.k3 = b.get('ngoai_tam_sast', {}).get('bang', {})
    def pt(self, lang, tool, h):
        L = 'javascript' if lang == 'typescript' else lang
        return self.p.get(L, {}).get(tool, {}).get(h, 0.0)
    def lang_prior(self, lang):
        return self.prior.get('javascript' if lang == 'typescript' else lang, {})
    def thong_tin(self, lang, tool, h):
        L = 'javascript' if lang == 'typescript' else lang
        return self.info.get(f'{L}|{tool}|{h}')
    def ngoai_tam_k3(self, lang, h):
        L = 'javascript' if lang == 'typescript' else lang
        x = self.k3.get(L, {}).get(h)
        return None if x is None else x['p']
