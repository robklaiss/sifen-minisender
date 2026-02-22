import os, json, urllib.request
from pathlib import Path
import xml.etree.ElementTree as ET

def local(tag: str) -> str:
    return tag.split("}", 1)[1] if "}" in tag else tag

invoice_id = int(os.environ.get("INVOICE_ID", "0") or 0) or 5

url = f"http://127.0.0.1:8000/api/invoices/{invoice_id}/dry-run"
data = json.dumps({"persist_source_xml": True}).encode("utf-8")
req = urllib.request.Request(url, data=data, method="POST", headers={"Content-Type": "application/json"})

with urllib.request.urlopen(req, timeout=60) as r:
    out = json.loads(r.read().decode("utf-8", "replace"))
    if not out.get("ok") or not out.get("xsd_ok"):
        raise SystemExit(f"ERROR: dry-run not ok/xsd_ok: {out}")

artifacts_dir = (out.get("artifacts_dir") or "").strip()
print("artifacts_dir(container)=", artifacts_dir)

if not artifacts_dir.startswith("/data/"):
    raise SystemExit(f"ERROR: artifacts_dir unexpected (expected /data/...): {artifacts_dir}")

# Mapeo container -> host (volumen)
host_dir = Path("/opt/sifen-minisender") / "data" / artifacts_dir.removeprefix("/data/").lstrip("/")
print("artifacts_dir(host)=", host_dir)

if not host_dir.exists():
    raise SystemExit(f"ERROR: host artifacts dir not found: {host_dir}")

xml_files = sorted([p for p in host_dir.rglob("*.xml")], key=lambda p: p.stat().st_mtime, reverse=True)
if not xml_files:
    raise SystemExit("ERROR: no XML files found in artifacts_dir")

xml_path = xml_files[0]
print("xml_path=", xml_path)

root = ET.fromstring(xml_path.read_bytes())

# --- CDC / DE@Id ---
de = next((el for el in root.iter() if local(el.tag) == "DE"), None)
if de is None:
    raise SystemExit("ERROR: <DE> not found (namespaced?)")

cdc = (de.attrib.get("Id") or "").strip()
print("cdc=", cdc)

if not cdc.isdigit():
    raise SystemExit("ERROR: CDC must be numeric only")
if len(cdc) != 44:
    raise SystemExit(f"ERROR: CDC length must be 44, got {len(cdc)}")

dvid_el = next((el for el in root.iter() if local(el.tag) == "dDVId"), None)
if dvid_el is None or not (dvid_el.text or "").strip():
    raise SystemExit("ERROR: dDVId not found/empty")
dvid = (dvid_el.text or "").strip()

if dvid != cdc[-1]:
    raise SystemExit(f"ERROR: dDVId ({dvid}) != last digit of CDC ({cdc[-1]})")
print("OK: CDC length=44 and dDVId matches")

# --- QR ---
qr_el = next((el for el in root.iter() if local(el.tag) == "dCarQR"), None)
if qr_el is None or not (qr_el.text or "").strip():
    raise SystemExit("ERROR: dCarQR (QR) not found/empty")
qr = (qr_el.text or "").strip()
if len(qr) < 20:
    raise SystemExit(f"ERROR: QR too short? len={len(qr)}")
print("OK: QR present len=", len(qr))

# --- PYG invariant: NO dTotalGs ---
if any(local(el.tag) == "dTotalGs" for el in root.iter()):
    raise SystemExit("ERROR: PYG invariant violated: dTotalGs present")
print("OK: PYG invariant: no dTotalGs")

# --- gTotSub order sanity: dBaseGrav5/dBaseGrav10 MUST be BEFORE dTBasGraIVA ---
gtot = next((el for el in root.iter() if local(el.tag) == "gTotSub"), None)
if gtot is None:
    raise SystemExit("ERROR: gTotSub not found")

children = [local(ch.tag) for ch in list(gtot)]
pos = {name: i for i, name in enumerate(children)}

if "dTBasGraIVA" in pos:
    if "dBaseGrav5" in pos and pos["dTBasGraIVA"] < pos["dBaseGrav5"]:
        raise SystemExit("ERROR: gTotSub order suspicious: dTBasGraIVA appears before dBaseGrav5")
    if "dBaseGrav10" in pos and pos["dTBasGraIVA"] < pos["dBaseGrav10"]:
        raise SystemExit("ERROR: gTotSub order suspicious: dTBasGraIVA appears before dBaseGrav10")
print("OK: gTotSub order sanity")

print("✅ FULL CHECK OK")
