import re
import sys
from pathlib import Path

path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/opt/sifen-minisender/data/artifacts/gtransp_snapshot_invoice5.xml")
s = path.read_text(encoding="utf-8", errors="replace")

m = re.search(r"<gTransp\b[\s\S]*?</gTransp>", s)
if not m:
    print(f"FAIL: no gTransp found in {path}")
    sys.exit(2)

blk = m.group(0)

def pos(tag: str) -> int:
    i = blk.find(f"<{tag}>")
    if i == -1:
        print(f"FAIL: missing <{tag}> in gTransp")
        sys.exit(3)
    return i

p_iTip = pos("iTipTrans")
p_dTip = pos("dDesTipTrans")
p_iMod = pos("iModTrans")
p_dMod = pos("dDesModTrans")
p_iResp = pos("iRespFlete")

ok = True
def req(cond: bool, msg: str):
    global ok
    if not cond:
        ok = False
        print("FAIL:", msg)

req(p_iTip < p_dTip < p_iMod, "expected order iTipTrans -> dDesTipTrans -> iModTrans")
req(p_iMod < p_dMod, "expected order iModTrans -> dDesModTrans")
req(p_dMod < p_iResp, "expected dDesModTrans before iRespFlete (per current snapshot expectation)")

if not ok:
    print("\n--- gTransp ---")
    print(blk)
    sys.exit(1)

print("OK: gTransp tag order looks correct in", str(path))
