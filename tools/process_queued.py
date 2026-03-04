#!/usr/bin/env python3
import os
import sqlite3
import subprocess
from datetime import datetime

DB = os.getenv("SIFEN_WEBUI_DB", "/opt/sifen-minisender/data/webui.db")
ENV = os.getenv("SIFEN_ENV", "prod").strip().lower()
BATCH = int(os.getenv("BATCH", "10"))
ARTIFACTS_DIR = os.getenv("ARTIFACTS_DIR", "/opt/sifen-minisender/data/artifacts")
REPO_ROOT = os.getenv("REPO_ROOT", "/opt/sifen-minisender")
PREFLIGHT = os.getenv("PREFLIGHT", "/opt/sifen-minisender/tools/sifen_preflight.sh")

def now_iso():
    return datetime.utcnow().replace(microsecond=0).isoformat()

def preflight_ok() -> bool:
    try:
        p = subprocess.run([PREFLIGHT], capture_output=True, text=True)
        return p.returncode == 0
    except Exception:
        return False

def run_minisender_send(rel_signed: str):
    args = [
        "python3", "-m", "sifen_minisender", "send",
        "--env", ENV,
        "--artifacts-root", ARTIFACTS_DIR,
        rel_signed,
    ]
    env_used = os.environ.copy()
    if ENV == "prod":
        env_used["SIFEN_CONFIRM_PROD"] = "YES"
    p = subprocess.run(args, cwd=REPO_ROOT, env=env_used, capture_output=True, text=True)
    return p.returncode, p.stdout or "", p.stderr or ""

def parse_fields(text: str):
    import re
    out = {}
    for key in ("dCodRes", "dMsgRes", "dProtConsLote"):
        m = re.search(rf"{key}\s*[:=]\s*([0-9A-Za-z._-]+)", text)
        if m:
            out[key] = m.group(1).strip()
        m = re.search(rf"<{key}>(.*?)</{key}>", text, re.DOTALL)
        if m:
            out[key] = m.group(1).strip()
    return out

def main():
    # seguridad: si está DOWN, no hacemos nada aunque alguien lo ejecute a mano
    if not preflight_ok():
        print(f"{now_iso()} SKIP: preflight DOWN (env={ENV})")
        return 0

    con = sqlite3.connect(DB, timeout=30)
    con.row_factory = sqlite3.Row

    rows = con.execute(f"""
        SELECT id, source_xml_path, sifen_env
        FROM invoices
        WHERE status=QUEUED
          AND (sifen_env=? OR sifen_env IS NULL OR sifen_env=)
        ORDER BY queued_at ASC, id ASC
        LIMIT {BATCH}
    """, (ENV,)).fetchall()

    if not rows:
        print(f"{now_iso()} NOOP: no QUEUED (env={ENV})")
        return 0

    print(f"{now_iso()} START: env={ENV} batch={len(rows)} db={DB}")
    for r in rows:
        inv_id = int(r["id"])
        rel_signed = (r["source_xml_path"] or "").strip()

        if not rel_signed:
            msg = f"{now_iso()} | ERROR: source_xml_path vacío"
            con.execute("UPDATE invoices SET last_sifen_msg=? WHERE id=?", (msg[:900], inv_id))
            con.commit()
            print(f"{now_iso()} id={inv_id} SKIP: no source_xml_path")
            continue

        print(f"{now_iso()} id={inv_id} SEND xml={rel_signed}")
        code, out, err = run_minisender_send(rel_signed)
        fields = parse_fields(out)

        dCodRes = fields.get("dCodRes")
        dMsgRes = (fields.get("dMsgRes") or "").strip()
        prot = fields.get("dProtConsLote")

        new_status = "QUEUED"
        sent_at = None
        if dCodRes == "0300" and prot:
            new_status = "SENT"
            sent_at = now_iso()

        msg = dMsgRes
        if code != 0:
            msg = (msg + f" | minisender_exit={code} | stderr={err[-500:]}").strip()

        con.execute("""
            UPDATE invoices
            SET status=?,
                sent_at=COALESCE(sent_at,?),
                sifen_prot_cons_lote=COALESCE(sifen_prot_cons_lote,?),
                last_sifen_code=?,
                last_sifen_msg=?
            WHERE id=?
        """, (new_status, sent_at, prot, dCodRes, msg[:900], inv_id))
        con.commit()

        prot_flag = "YES" if prot else "NO"
        print(f"{now_iso()} id={inv_id} DONE status={new_status} cod={dCodRes} prot={prot_flag}")

    print(f"{now_iso()} END")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
