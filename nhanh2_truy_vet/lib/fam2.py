"""Ho loi phien ban 2 = ho goc (xac_suat.CWE2FAM) + 6 ho moi tu ra soat 'khac' (CWE chiem >= 1% tong so thong bao; quy tac co dinh trong phieu)."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__))); from xac_suat import C2F as C2F_GOC
MOI = {'CWE-352': 'csrf', 'CWE-502': 'deserialization', 'CWE-287': 'xac_thuc', 'CWE-787': 'bo_nho', 'CWE-506': 'ma_doc', 'CWE-611': 'xxe'}
C2F = dict(C2F_GOC); C2F.update(MOI)
def family2(cwes):
    for c in cwes:
        if c in C2F: return C2F[c]
    return 'khac'
