# tools/cdc_dv.py
# Cálculo DV (mod 11) para el CDC (SIFEN)

from __future__ import annotations

def calc_cdc_dv(base: str) -> int:
    """
    Calcula el dígito verificador (DV) para el CDC usando Mod11 (pesos 2..11).
    Algoritmo compatible con SIFEN (SifenUtil.generateDv).
    base: string numérico SIN el DV final.
    Retorna: int 0..9
    """
    s = (base or "").strip()
    if not s.isdigit():
        raise ValueError(f"base debe ser numérica, recibido: {base!r}")

    base_max = 11
    k = 2
    total = 0

    # Caso especial documentado en SifenUtil
    if s == "88888801":
        return 5

    for ch in reversed(s):
        if k > base_max:
            k = 2
        total += int(ch) * k
        k += 1

    mod = total % 11
    return 0 if mod <= 1 else (11 - mod)


def is_cdc_valid(cdc: str) -> bool:
    """
    Valida un CDC de 44 dígitos verificando el DV.
    """
    s = (cdc or "").strip()
    if not s.isdigit() or len(s) != 44:
        return False
    base = s[:43]
    dv = int(s[43])
    return dv == calc_cdc_dv(base)


def fix_cdc(cdc: str) -> str:
    """
    Corrige el DV de un CDC de 44 dígitos y retorna el CDC corregido.
    """
    s = (cdc or "").strip()
    if not s.isdigit() or len(s) != 44:
        raise ValueError(f"CDC inválido (se esperan 44 dígitos): {cdc!r}")
    base = s[:43]
    dv = calc_cdc_dv(base)
    return base + str(dv)
