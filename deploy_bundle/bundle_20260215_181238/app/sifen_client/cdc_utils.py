"""
Utilidades para cálculo y validación de CDC (Código de Control) SIFEN.

El CDC es un número de 44 dígitos donde:
- Los primeros 43 dígitos son la base
- El último dígito es el DV (dígito verificador) calculado con módulo 11

NOTA: Este módulo delega al módulo centralizado tools.cdc_dv para mantener
compatibilidad con código existente.
"""

import sys
from pathlib import Path

# Importar módulo centralizado
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from tools.cdc_dv import calc_cdc_dv as _calc_cdc_dv_centralized, is_cdc_valid as _is_cdc_valid_centralized, fix_cdc as _fix_cdc_centralized


def calc_dv_mod11(num_str: str) -> int:
    """
    Calcula el dígito verificador (DV) usando módulo 11 con pesos 2-9.
    
    DELEGA a tools.cdc_dv.calc_cdc_dv() para mantener compatibilidad.
    
    Args:
        num_str: String numérico (típicamente 43 dígitos para CDC)
        
    Returns:
        DV calculado (0-9)
    """
    # Delegar al módulo centralizado
    return _calc_cdc_dv_centralized(num_str)


def fix_cdc(cdc44: str) -> str:
    """
    Corrige el DV de un CDC de 44 dígitos.
    
    DELEGA a tools.cdc_dv.fix_cdc() para mantener compatibilidad.
    
    Args:
        cdc44: CDC completo de 44 dígitos
        
    Returns:
        CDC corregido con DV válido
        
    Raises:
        ValueError: Si el CDC no tiene 44 dígitos o no es numérico
    """
    return _fix_cdc_centralized(cdc44)


def validate_cdc(cdc44: str) -> tuple[bool, int, int]:
    """
    Valida un CDC verificando si el DV es correcto.
    
    DELEGA a tools.cdc_dv para mantener compatibilidad.
    
    Args:
        cdc44: CDC completo de 44 dígitos
        
    Returns:
        Tupla (es_valido, dv_original, dv_calculado)
    """
    if not cdc44 or not isinstance(cdc44, str):
        return (False, -1, -1)
    
    digits = ''.join(c for c in cdc44 if c.isdigit())
    if len(digits) != 44:
        return (False, -1, -1)
    
    base43 = digits[:43]
    dv_original = int(digits[43])
    
    try:
        dv_calculado = _calc_cdc_dv_centralized(base43)
        es_valido = _is_cdc_valid_centralized(cdc44)
        return (es_valido, dv_original, dv_calculado)
    except Exception:
        return (False, dv_original, -1)
