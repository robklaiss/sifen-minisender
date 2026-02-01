# Baseline SIFEN TEST OK (2026-02-01)

Resultado OK:
- dCodRes: 0300
- dMsgRes: Lote recibido con éxito
- dProtConsLote: 47353168697912368
- artifacts: artifacts/run_20260201_152345

Características del request aceptado:
- SOAP Body: <rEnvioLote xmlns="http://ekuatia.set.gov.py/sifen/xsd">
- xDE: Base64 ZIP (sin whitespace)
- ZIP: 1 entry "lote.xml"
- ZIP compress_type: 0 (ZIP_STORED, sin compresión)

Características del lote.xml aceptado:
- <rLoteDE xmlns="http://ekuatia.set.gov.py/sifen/xsd">
- <rDE xmlns="http://ekuatia.set.gov.py/sifen/xsd">
- NO contiene 'xsi:' (count=0)
- NO contiene 'schemaLocation' (count=0)
- DE y Signature presentes:
  - <DE Id="...">
  - <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
