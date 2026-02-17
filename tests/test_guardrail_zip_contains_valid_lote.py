from pathlib import Path
import os
import zipfile
import xml.etree.ElementTree as ET

def local_tag(tag: str) -> str:
    if tag.startswith("{"):
        return tag.split("}", 1)[1]
    return tag

def find_first_by_local(root: ET.Element, name: str):
    for el in root.iter():
        if local_tag(el.tag) == name:
            return el
    return None

def pick_latest_run_dir() -> Path:
    # Permite fijar el run exacto (determinístico)
    forced = os.environ.get("SIFEN_RUN_DIR")
    if forced:
        p = Path(forced)
        if not p.exists():
            raise AssertionError(f"SIFEN_RUN_DIR no existe: {p}")
        return p

    runs = sorted(
        Path("artifacts").glob("run_*"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if not runs:
        raise AssertionError("No hay artifacts/run_* (ejecutá tools/send_sirecepde.py primero).")
    return runs[0]

def test_last_xde_zip_contains_valid_lote_xml():
    run_dir = pick_latest_run_dir()
    zip_path = run_dir / "last_xde.zip"
    assert zip_path.exists(), f"No existe: {zip_path} (ejecutá tools/send_sirecepde.py)"

    with zipfile.ZipFile(zip_path, "r") as z:
        names = z.namelist()
        assert "lote.xml" in names, f"ZIP no contiene lote.xml. names={names}"
        lote_bytes = z.read("lote.xml")

    root = ET.fromstring(lote_bytes.decode("utf-8"))
    rde = find_first_by_local(root, "rDE")
    assert rde is not None, f"No se encontró <rDE> en lote.xml dentro de {zip_path}"

    children = [local_tag(c.tag) for c in list(rde)]
    expected = ["dVerFor", "DE", "Signature", "gCamFuFD"]
    assert children == expected, (
        "Orden rDE incorrecto en lote.xml del ZIP.\n"
        f"  zip:     {zip_path}\n"
        f"  actual:  {children}\n"
        f"  esperado:{expected}"
    )

    de = next((c for c in list(rde) if local_tag(c.tag) == "DE"), None)
    assert de is not None, "<rDE> no contiene hijo directo <DE>"

    g_inside_de = any(local_tag(x.tag) == "gCamFuFD" for x in de.iter())
    assert not g_inside_de, f"gCamFuFD está dentro de <DE> (prohibido). zip={zip_path}"

    de_id = de.attrib.get("Id")
    assert de_id, f"<DE> no tiene atributo Id. zip={zip_path}"

    sig = next((c for c in list(rde) if local_tag(c.tag) == "Signature"), None)
    assert sig is not None, f"<rDE> no contiene hijo directo <Signature>. zip={zip_path}"

    ref_uri = None
    for el in sig.iter():
        if local_tag(el.tag) == "Reference":
            ref_uri = el.attrib.get("URI")
            break

    assert ref_uri == f"#{de_id}", (
        "Reference URI no coincide con DE Id (ZIP).\n"
        f"  zip:   {zip_path}\n"
        f"  DE Id: {de_id}\n"
        f"  URI:   {ref_uri}"
    )
