"""
Utilidades para conversión de certificados PKCS#12 (P12/PFX) a PEM temporales

Este módulo convierte certificados P12/PFX a archivos PEM temporales (cert.pem + key.pem)
para uso con librerías que requieren formato PEM (requests, httpx, zeep) en mTLS.

El P12/PFX sigue siendo la fuente de verdad; los PEM son temporales y se crean
con permisos 600 para seguridad.

NOTA: Fallback a OpenSSL con -legacy
-------------------------------------
Algunos certificados P12 usan algoritmos legacy (pbeWithSHA1And3-KeyTripleDES-CBC)
que cryptography no soporta en OpenSSL 3.x. En estos casos, se usa un fallback
con el binario `openssl` y la opción `-legacy` para extraer el certificado y la clave.
"""
import os
import tempfile
import logging
import subprocess
import shutil
from pathlib import Path
from typing import Tuple, Optional
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)


class PKCS12Error(Exception):
    """Excepción para errores en conversión PKCS#12"""
    pass


def _find_openssl_binary() -> Optional[str]:
    """
    Encuentra el binario openssl disponible en el sistema.
    
    Prioridad:
    1. /opt/homebrew/bin/openssl (macOS Homebrew en Apple Silicon)
    2. openssl en PATH
    
    Returns:
        Ruta al binario openssl o None si no se encuentra
    """
    # Intentar Homebrew en Apple Silicon primero
    homebrew_openssl = "/opt/homebrew/bin/openssl"
    if os.path.exists(homebrew_openssl) and os.access(homebrew_openssl, os.X_OK):
        return homebrew_openssl
    
    # Buscar en PATH
    openssl_path = shutil.which("openssl")
    if openssl_path:
        return openssl_path
    
    return None


def _p12_to_pem_openssl_fallback(
    p12_path: str,
    p12_password: str,
    cert_pem_path: str,
    key_pem_path: str
) -> None:
    """
    Fallback usando OpenSSL para convertir P12 a PEM cuando cryptography falla.
    
    Usa openssl con opción -legacy para soportar algoritmos legacy como
    pbeWithSHA1And3-KeyTripleDES-CBC.
    
    Args:
        p12_path: Ruta al archivo P12
        p12_password: Contraseña del P12
        cert_pem_path: Ruta donde escribir el certificado PEM
        key_pem_path: Ruta donde escribir la clave privada PEM
        
    Raises:
        PKCS12Error: Si openssl no está disponible o falla la conversión
    """
    openssl_bin = _find_openssl_binary()
    if not openssl_bin:
        raise PKCS12Error(
            "OpenSSL no encontrado en el sistema. "
            "Instale OpenSSL (ej: brew install openssl en macOS)"
        )
    
    # Crear variable de entorno temporal para la contraseña
    # Usar un nombre único para evitar conflictos
    env_var_name = "SIFEN_P12_PASS_TMP"
    env = os.environ.copy()
    env[env_var_name] = p12_password
    
    try:
        # Extraer certificado: openssl pkcs12 -legacy -in <p12> -clcerts -nokeys -out <cert_pem> -passin env:SIFEN_P12_PASS_TMP
        cert_cmd = [
            openssl_bin,
            "pkcs12",
            "-legacy",
            "-in", p12_path,
            "-clcerts",
            "-nokeys",
            "-out", cert_pem_path,
            "-passin", f"env:{env_var_name}"
        ]
        
        cert_result = subprocess.run(
            cert_cmd,
            env=env,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if cert_result.returncode != 0:
            # Limpiar variable de entorno antes de lanzar error
            error_output = cert_result.stderr or cert_result.stdout or "Sin salida"
            # NO incluir la contraseña en el error
            raise PKCS12Error(
                f"Error al extraer certificado con OpenSSL: {error_output[:500]}"
            )
        
        # Extraer clave privada: openssl pkcs12 -legacy -in <p12> -nocerts -nodes -out <key_pem> -passin env:SIFEN_P12_PASS_TMP
        key_cmd = [
            openssl_bin,
            "pkcs12",
            "-legacy",
            "-in", p12_path,
            "-nocerts",
            "-nodes",
            "-out", key_pem_path,
            "-passin", f"env:{env_var_name}"
        ]
        
        key_result = subprocess.run(
            key_cmd,
            env=env,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if key_result.returncode != 0:
            # Limpiar archivo de certificado si se creó
            try:
                if os.path.exists(cert_pem_path):
                    os.unlink(cert_pem_path)
            except Exception:
                pass
            
            error_output = key_result.stderr or key_result.stdout or "Sin salida"
            raise PKCS12Error(
                f"Error al extraer clave privada con OpenSSL: {error_output[:500]}"
            )
        
        # Validar que los archivos generados contienen el contenido esperado
        try:
            with open(cert_pem_path, 'rb') as f:
                cert_content = f.read()
            if b"BEGIN CERTIFICATE" not in cert_content:
                raise PKCS12Error("El archivo de certificado PEM generado no contiene 'BEGIN CERTIFICATE'")
            
            with open(key_pem_path, 'rb') as f:
                key_content = f.read()
            if b"BEGIN PRIVATE KEY" not in key_content and b"BEGIN RSA PRIVATE KEY" not in key_content:
                raise PKCS12Error(
                    "El archivo de clave privada PEM generado no contiene 'BEGIN PRIVATE KEY' "
                    "ni 'BEGIN RSA PRIVATE KEY'"
                )
        except FileNotFoundError as e:
            raise PKCS12Error(f"Archivo PEM no encontrado después de conversión: {str(e)}")
        except Exception as e:
            raise PKCS12Error(f"Error al validar archivos PEM generados: {str(e)}")
        
        logger.info("Certificado P12 convertido a PEM usando OpenSSL (fallback legacy)")
        
    finally:
        # Limpiar variable de entorno (aunque Python la limpiará al terminar el proceso)
        # Es buena práctica hacerlo explícitamente
        if env_var_name in env:
            # No podemos modificar os.environ del proceso padre, pero esto es solo para
            # el subprocess, así que está bien
            pass


def p12_to_temp_pem_files(p12_path: str, p12_password: str) -> Tuple[str, str]:
    """
    Convierte un certificado PKCS#12 (P12/PFX) a dos archivos PEM temporales.
    
    Crea dos archivos temporales:
    - cert.pem: Certificado X.509 en formato PEM
    - key.pem: Clave privada en formato PEM (sin cifrar)
    
    Los archivos se crean con permisos 600 (solo lectura/escritura para el propietario).
    
    Args:
        p12_path: Ruta al archivo P12/PFX
        p12_password: Contraseña del archivo P12/PFX
        
    Returns:
        Tupla (cert_pem_path, key_pem_path) con las rutas de los archivos PEM temporales
        
    Raises:
        PKCS12Error: Si el archivo no existe, la contraseña es incorrecta,
                     o no se puede extraer cert/key
    """
    p12_file = Path(p12_path)
    
    if not p12_file.exists():
        raise PKCS12Error(f"Archivo P12 no encontrado: {p12_path}")
    
    if not p12_file.is_file():
        raise PKCS12Error(f"La ruta no es un archivo: {p12_path}")
    
    # Verificar extensión (opcional, pero útil para validación)
    ext = p12_file.suffix.lower()
    if ext not in ['.p12', '.pfx']:
        logger.warning(f"Extensión inusual para certificado PKCS#12: {ext}")
    
    try:
        # Leer archivo P12
        with open(p12_path, 'rb') as f:
            p12_data = f.read()
        
        # Cargar certificado y clave desde P12
        password_bytes = p12_password.encode('utf-8') if p12_password else None
        
        # Crear archivos temporales ANTES de intentar la conversión
        # (necesarios tanto para cryptography como para el fallback OpenSSL)
        temp_dir = tempfile.gettempdir()
        
        cert_fd, cert_path = tempfile.mkstemp(
            suffix='.pem',
            prefix='sifen_cert_',
            dir=temp_dir,
            text=False
        )
        
        key_fd, key_path = tempfile.mkstemp(
            suffix='.pem',
            prefix='sifen_key_',
            dir=temp_dir,
            text=False
        )
        
        # Cerrar los file descriptors ahora (los abriremos después si es necesario)
        os.close(cert_fd)
        os.close(key_fd)
        
        # Intentar primero con cryptography
        try:
            private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
                p12_data,
                password_bytes,
                backend=default_backend()
            )
            
            # Validar que se extrajeron cert y key
            if private_key is None:
                raise PKCS12Error("No se pudo extraer la clave privada del archivo P12")
            
            if certificate is None:
                raise PKCS12Error("No se pudo extraer el certificado del archivo P12")
            
            # Serializar certificado a PEM
            cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
            
            # Serializar clave privada a PEM (sin cifrar, para uso con requests/httpx/zeep)
            key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()  # Sin cifrado
            )
            
            # Escribir certificado
            with open(cert_path, 'wb') as cert_file:
                cert_file.write(cert_pem)
            
            # Escribir clave privada
            with open(key_path, 'wb') as key_file:
                key_file.write(key_pem)
            
            # Establecer permisos 600 (solo propietario puede leer/escribir)
            os.chmod(cert_path, 0o600)
            os.chmod(key_path, 0o600)
            
            logger.info(
                f"Certificado P12 convertido a PEM temporales (cryptography): "
                f"cert={Path(cert_path).name}, key={Path(key_path).name}"
            )
            # NO loggear paths completos ni contraseñas
            
            return (cert_path, key_path)
            
        except PKCS12Error:
            # Si ya es PKCS12Error (ej: private_key o certificate None), re-raise sin fallback
            # Limpiar archivos temporales antes
            try:
                if os.path.exists(cert_path):
                    os.unlink(cert_path)
            except Exception:
                pass
            try:
                if os.path.exists(key_path):
                    os.unlink(key_path)
            except Exception:
                pass
            raise
            
        except ValueError as e:
            # ValueError puede indicar contraseña incorrecta o algoritmo legacy no soportado
            error_msg = str(e)
            
            # Si es error de contraseña, intentar fallback primero (puede ser que openssl funcione)
            # Si es otro error de cryptography, usar fallback directamente
            logger.debug(
                f"cryptography falló con ValueError: {error_msg[:200]}. "
                f"Intentando fallback con OpenSSL -legacy..."
            )
            
            # Intentar fallback con OpenSSL
            try:
                _p12_to_pem_openssl_fallback(p12_path, p12_password, cert_path, key_path)
                
                # Establecer permisos 600
                os.chmod(cert_path, 0o600)
                os.chmod(key_path, 0o600)
                
                return (cert_path, key_path)
                
            except PKCS12Error as openssl_error:
                # Limpiar archivos temporales si el fallback falla
                try:
                    if os.path.exists(cert_path):
                        os.unlink(cert_path)
                except Exception:
                    pass
                try:
                    if os.path.exists(key_path):
                        os.unlink(key_path)
                except Exception:
                    pass
                
                # Si el fallback también falla, determinar si es error de contraseña
                if 'password' in error_msg.lower() or 'mac' in error_msg.lower() or 'bad decrypt' in error_msg.lower():
                    raise PKCS12Error(
                        "Contraseña del certificado P12 incorrecta o el archivo está corrupto. "
                        f"OpenSSL fallback también falló: {str(openssl_error)[:200]}"
                    ) from e
                else:
                    # Error de algoritmo legacy o formato
                    raise PKCS12Error(
                        f"Error al cargar certificado P12 con cryptography y OpenSSL fallback: "
                        f"cryptography: {error_msg[:200]}, OpenSSL: {str(openssl_error)[:200]}"
                    ) from e
            except Exception as openssl_error:
                # Limpiar archivos temporales si el fallback falla
                try:
                    if os.path.exists(cert_path):
                        os.unlink(cert_path)
                except Exception:
                    pass
                try:
                    if os.path.exists(key_path):
                        os.unlink(key_path)
                except Exception:
                    pass
                
                # Error inesperado en el fallback
                raise PKCS12Error(
                    f"Error inesperado en fallback OpenSSL: {str(openssl_error)[:200]}"
                ) from e
        
        except Exception as e:
            # Otro error de cryptography, intentar fallback
            logger.debug(
                f"cryptography falló con {type(e).__name__}: {str(e)[:200]}. "
                f"Intentando fallback con OpenSSL -legacy..."
            )
            
            try:
                _p12_to_pem_openssl_fallback(p12_path, p12_password, cert_path, key_path)
                
                # Establecer permisos 600
                os.chmod(cert_path, 0o600)
                os.chmod(key_path, 0o600)
                
                return (cert_path, key_path)
                
            except Exception as openssl_error:
                # Limpiar archivos temporales si el fallback falla
                try:
                    if os.path.exists(cert_path):
                        os.unlink(cert_path)
                except Exception:
                    pass
                try:
                    if os.path.exists(key_path):
                        os.unlink(key_path)
                except Exception:
                    pass
                
                raise PKCS12Error(
                    f"Error al cargar certificado P12: cryptography falló con {type(e).__name__}, "
                    f"OpenSSL fallback también falló: {str(openssl_error)[:200]}"
                ) from e
    
    except PKCS12Error:
        raise
    except Exception as e:
        raise PKCS12Error(f"Error inesperado en conversión P12 a PEM: {str(e)}") from e


def cleanup_pem_files(cert_path: str, key_path: str) -> None:
    """
    Limpia archivos PEM temporales creados por p12_to_temp_pem_files.
    
    Args:
        cert_path: Ruta al archivo cert.pem
        key_path: Ruta al archivo key.pem
    """
    for path in [cert_path, key_path]:
        if path and os.path.exists(path):
            try:
                os.unlink(path)
                logger.debug(f"Archivo PEM temporal eliminado: {Path(path).name}")
            except Exception as e:
                logger.warning(f"No se pudo eliminar archivo PEM temporal {Path(path).name}: {str(e)}")

