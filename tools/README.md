# Tools

## extract_consulta_fields.py

Extracts key fields from SIFEN **consulta** SOAP responses:

- `dFecProc`, `dCodRes`, `dMsgRes` from the SOAP XML
- `dProtAut` via regex from the raw response (works even when `xContenDE` contains partially-escaped XML)

### Usage

```bash
./tools/extract_consulta_fields.py /tmp/consulta_out.xml
```

### Output (example)

```json
{
  "dFecProc": "2026-02-28T01:15:09-03:00",
  "dCodRes": "0422",
  "dMsgRes": "CDC encontrado",
  "dProtAut": "3025496833",
  "source_file": "/tmp/consulta_out.xml"
}
```
