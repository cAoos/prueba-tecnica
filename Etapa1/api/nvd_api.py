"""
Nombre: api/nvd_api.py
Autor: Cesar Ospina Muñoz
Fecha: 2026-05-12
Descripción: Consultar la API del NIST NVD por cada CVE ID
             y devolver los campos enriquecidos que pide la prueba.

            Este módulo está compuesto por varias funciones:
                1. Consultar la API del NIST por un CVE ID
                2. Guardar la respuesta en disco (caché) para no repetir consultas
                3. Respetar el límite de peticiones por minuto del NIST

            Funciona con o sin API key:
                - Sin key:  6 peticiones por minuto  (espera 10.5s entre cada una)
                - Con key: 50 peticiones por minuto  (espera 1.5s entre cada una)
"""

import json
import os
import time
from pathlib import Path

import requests
from dotenv import load_dotenv


# Cargamos el archivo .env para leer la API key
load_dotenv()

# URL base de la API del NIST
NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Carpeta donde guardamos las respuestas ya consultadas.
CACHE_DIR = Path(__file__).parent.parent / "cache"

# Segundos de espera entre cada petición al NIST.
# Con key podemos hacer más peticiones por minuto.
ESPERA_SIN_KEY = 10.5
ESPERA_CON_KEY = 1.5

# Cuántas veces reintentamos si la API falla antes de rendirse
MAXIMOS_REINTENTOS = 3

# Segundos que esperamos entre reintento y reintento
ESPERA_ENTRE_REINTENTOS = 5


def obtener_api_key():
    """
    Lee la API key del archivo .env y la devuelve.

    El sistema funciona con o sin key:
        - Con key:  más rápido (50 req/min)
        - Sin key:  más lento  (6 req/min) pero igualmente funcional

    Return:
        str  : la API key si está configurada y activada
        None : si no hay key, el sistema sigue funcionando igual
    """

    key = os.getenv("NVD_API_KEY", "")

    # Si no hay key o tiene el valor de ejemplo del .env
    if not key or key == "pega_aqui_tu_api_key":
        print("  [NVD] Sin API key. Velocidad: 6 req/min.")
        return None

    print(f"  [NVD] API key detectada ({len(key)} caracteres). Velocidad: 50 req/min.")
    return key


# ─── Caché ────────────────────────────────────────────────────────────────────
#
# El objetivo de estas funciones es guardar en caché la respuesta del NIST
# para cada CVE ID consultado, y buscar en ese caché antes de hacer una
# nueva consulta.
#
# Esto nos ayuda a:
#   - No perder información si el script se interrumpe a mitad
#   - No repetir peticiones si corremos el script varias veces
#   - No acercarnos innecesariamente al límite de peticiones del NIST


def obtener_ruta_cache(cve_id):
    """
    Devuelve la ruta del archivo de caché para un CVE.
    Ejemplo: cache/CVE-2021-44228.json

    Return:
        Path : la ruta del archivo de caché
    """
    CACHE_DIR.mkdir(exist_ok=True)

    nombre_archivo = f"{cve_id}.json"

    return CACHE_DIR / nombre_archivo


def cargar_desde_cache(cve_id):
    """
    Busca el CVE en el caché local.

    Return:
        dict : si el CVE ya fue consultado antes
        None : si no está en caché y hay que consultar la API
    """
    ruta = obtener_ruta_cache(cve_id)

    if not ruta.exists():
        return None

    try:
        with open(ruta, "r", encoding="utf-8") as archivo:
            return json.load(archivo)
    except (json.JSONDecodeError, IOError):
        # El archivo existe pero está dañado, lo ignoramos
        return None


def guardar_en_cache(cve_id, datos):
    """
    Guarda la respuesta del NIST en disco para uso futuro.
    Si no se puede guardar, el script sigue igual — el caché
    es una optimización, no un requisito.
    """
    ruta = obtener_ruta_cache(cve_id)

    try:
        with open(ruta, "w", encoding="utf-8") as archivo:
            json.dump(datos, archivo, ensure_ascii=False, indent=2)
    except IOError as error:
        print(f"  [CACHÉ] No se pudo guardar {cve_id}: {error}")


# ─── Petición a la API ────────────────────────────────────────────────────────

def llamar_api_nvd(cve_id, api_key):
    """
    Hace la petición HTTP al NIST para un CVE específico.

    Si hay API key la incluye en el encabezado de la petición.
    Si no hay key, hace la petición igual — el NIST la acepta
    sin key pero con menor límite de velocidad.

    Incluye lógica de reintentos: si la API falla por error de red
    o servidor, esperamos unos segundos y volvemos a intentar.
    Máximo 3 intentos antes de rendirse.

    Return:
        dict : respuesta JSON del NIST
        None : si el CVE no existe (404) o todos los reintentos fallaron
    """

    parametros = {"cveId": cve_id}
    cabeceras = {}

    # Si tenemos API key la enviamos en el encabezado
    # Si no tenemos key, cabeceras queda vacío y el NIST
    # igualmente responde — solo con menor velocidad permitida
    if api_key:
        cabeceras["apiKey"] = api_key

    intento_actual = 1

    while intento_actual <= MAXIMOS_REINTENTOS:

        try:
            respuesta = requests.get(
                NVD_API_BASE_URL,
                params=parametros,
                headers=cabeceras,
                timeout=30,
            )

            # 404 significa que el CVE no existe en el NIST.
            # No tiene sentido reintentar, devolvemos None directamente.
            if respuesta.status_code == 404:
                return None

            # Si el servidor devolvió otro error lanzamos excepción
            respuesta.raise_for_status()

            # Si llegamos aquí, todo salió bien
            return respuesta.json()

        except requests.exceptions.ConnectionError:
            print(f"  [NVD] Sin conexión. Reintento {intento_actual}/{MAXIMOS_REINTENTOS}...")

        except requests.exceptions.Timeout:
            print(f"  [NVD] Timeout. Reintento {intento_actual}/{MAXIMOS_REINTENTOS}...")

        except requests.exceptions.HTTPError as error:
            print(f"  [NVD] Error del servidor: {error}. Reintento {intento_actual}/{MAXIMOS_REINTENTOS}...")

        # Esperamos antes del siguiente intento
        time.sleep(ESPERA_ENTRE_REINTENTOS)
        intento_actual = intento_actual + 1

    # Máximo de reintentos alcanzado
    print(f"  [NVD] No se pudo consultar {cve_id} después de {MAXIMOS_REINTENTOS} intentos.")
    return None


# ─── Extracción de campos ─────────────────────────────────────────────────────

def extraer_campos(datos_api):
    """
    Recibe el JSON crudo del NIST y extrae solo los campos
    que pide la prueba técnica.

    Campos que extraemos:
        a. Descripción
        b. Métricas CVSS v3.1 y v2 (ambas completas)
        c. Score de Explotabilidad (en cada versión)
        d. Score de Impacto (en cada versión)
        e. Base Score (en cada versión)
        f. Base Severity (en cada versión)
        g. Vector String (en cada versión)
        h. CWEs (debilidades asociadas)
        +  CPEs (plataformas afectadas, para el ranking)

    Return:
        dict con todos los campos, o None si el JSON venía vacío
    """

    lista_vulnerabilidades = datos_api.get("vulnerabilities", [])

    if not lista_vulnerabilidades:
        return None

    cve_objeto = lista_vulnerabilidades[0].get("cve", {})

    # ── a. Descripción ────────────────────────────────────────────
    # Buscamos la descripción en inglés
    descripcion = ""
    for desc in cve_objeto.get("descriptions", []):
        if desc.get("lang") == "en":
            descripcion = desc.get("value", "")
            break

    # ── b/c/d/e/f/g. Métricas CVSS v3.1 ─────────────────────────
    metricas = cve_objeto.get("metrics", {})

    cvss_v31 = {}
    lista_v31 = metricas.get("cvssMetricV31", [])
    if lista_v31:
        datos_cvss_v31 = lista_v31[0].get("cvssData", {})
        cvss_v31 = {
            "version":              "3.1",
            "base_score":           datos_cvss_v31.get("baseScore"),
            "base_severity":        datos_cvss_v31.get("baseSeverity", ""),
            "vector_string":        datos_cvss_v31.get("vectorString", ""),
            "exploitability_score": lista_v31[0].get("exploitabilityScore"),
            "impact_score":         lista_v31[0].get("impactScore"),
        }

    # ── b/c/d/e/f/g. Métricas CVSS v2 ───────────────────────────
    cvss_v2 = {}
    lista_v2 = metricas.get("cvssMetricV2", [])
    if lista_v2:
        datos_cvss_v2 = lista_v2[0].get("cvssData", {})
        cvss_v2 = {
            "version":              "2.0",
            "base_score":           datos_cvss_v2.get("baseScore"),
            "base_severity":        lista_v2[0].get("baseSeverity", ""),
            "vector_string":        datos_cvss_v2.get("vectorString", ""),
            "exploitability_score": lista_v2[0].get("exploitabilityScore"),
            "impact_score":         lista_v2[0].get("impactScore"),
        }

    # ── h. CWEs ───────────────────────────────────────────────────
    # Cada CVE puede tener varios CWEs asociados
    cwes = []
    for debilidad in cve_objeto.get("weaknesses", []):
        for desc in debilidad.get("description", []):
            valor_cwe = desc.get("value", "")
            if valor_cwe and valor_cwe not in cwes:
                cwes.append(valor_cwe)

    # ── CPEs ──────────────────────────────────────────────────────
    # Plataformas y software afectados por este CVE
    cpes = []
    for configuracion in cve_objeto.get("configurations", []):
        for nodo in configuracion.get("nodes", []):
            for cpe_match in nodo.get("cpeMatch", []):
                cpe_string = cpe_match.get("criteria", "")
                if cpe_string and cpe_string not in cpes:
                    cpes.append(cpe_string)

    return {
        "cve_id":      cve_objeto.get("id", ""),
        "descripcion": descripcion,

        # Métricas v3.1 completas
        "cvss_v31_base_score":           cvss_v31.get("base_score"),
        "cvss_v31_base_severity":        cvss_v31.get("base_severity", ""),
        "cvss_v31_vector_string":        cvss_v31.get("vector_string", ""),
        "cvss_v31_exploitability_score": cvss_v31.get("exploitability_score"),
        "cvss_v31_impact_score":         cvss_v31.get("impact_score"),

        # Métricas v2 completas
        "cvss_v2_base_score":            cvss_v2.get("base_score"),
        "cvss_v2_base_severity":         cvss_v2.get("base_severity", ""),
        "cvss_v2_vector_string":         cvss_v2.get("vector_string", ""),
        "cvss_v2_exploitability_score":  cvss_v2.get("exploitability_score"),
        "cvss_v2_impact_score":          cvss_v2.get("impact_score"),

        # Debilidades y plataformas
        "cwes": cwes,
        "cpes": cpes,
    }


# ─── Función principal ────────────────────────────────────────────────────────

def consultar_cve(cve_id, api_key=None):
    """
    Función principal que orquesta la consulta al NIST para un CVE ID.

    Funciona con o sin API key — la diferencia es solo la velocidad:
        - Con key:  espera 1.5s entre peticiones (50 req/min)
        - Sin key:  espera 10.5s entre peticiones (6 req/min)

    Orden de prioridad:
        1. Si el CVE ya está en caché → lo devuelve del disco (instantáneo)
        2. Si no → llama a la API → guarda en caché → devuelve el resultado

    Return:
        dict : datos del CVE
        None : si el CVE no existe en el NIST o hubo un error irrecuperable
    """

    # Paso 1: buscar en caché antes de llamar a la API
    datos_cache = cargar_desde_cache(cve_id)
    if datos_cache is not None:
        return datos_cache

    # Paso 2: consultar la API del NIST
    respuesta_cruda = llamar_api_nvd(cve_id, api_key)

    if respuesta_cruda is None:
        # Guardamos None en caché para no volver a intentarlo
        guardar_en_cache(cve_id, None)
        return None

    # Paso 3: extraer solo los campos que necesitamos
    datos_extraidos = extraer_campos(respuesta_cruda)

    # Paso 4: guardar en caché para futuras corridas
    guardar_en_cache(cve_id, datos_extraidos)

    # Paso 5: esperar el tiempo adecuado según si hay key o no
    if api_key:
        time.sleep(ESPERA_CON_KEY)
    else:
        time.sleep(ESPERA_SIN_KEY)

    return datos_extraidos