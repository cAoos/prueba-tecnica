"""
Nombre: source/nuclei.py
Autor: Cesar Ospina Muñoz
Fecha: 2026-05-12
Descripción: Descargar el listado de CVEs de Nuclei y 
             retornar los datos limpios
"""


import requests
import json


# URL del archivo JSON crudo en el repositorio de GitHub de Nuclei.

NUCLEI_CVES_URL = (
    "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json"
)


def descargar_nuclei():
    """
    Descarga el archivo cves.json de Nuclei y devuelve una lista
    de diccionarios con la información de cada CVE.

    Cada diccionario retornado contiene:
        - cve_id    : identificador único (ej. "CVE-2021-26084")
        - fuente    : siempre "NUCLEI"
        - severity  : severidad según Nuclei (critical/high/medium/low)
        - name      : nombre del template de detección

    Return:
        list[dict]: lista de vulnerabilidades parseadas
        None: si la descarga falla
    """

    print("[NUCLEI] Descargando lista de CVEs desde GitHub...")

    try:
        respuesta = requests.get(NUCLEI_CVES_URL, timeout=30)
        respuesta.raise_for_status()

        vulnerabilidades = []

        # Usamos .text para obtener el contenido crudo como string
        # y lo dividimos en líneas porque el formato es NDJSON
        lineas = respuesta.text.strip().splitlines()

        for linea in lineas:

            # Saltamos líneas vacías
            if not linea.strip():
                continue

            # Parseamos cada línea como un JSON independiente
            try:
                entrada = json.loads(linea)
            except json.JSONDecodeError:
                # Si una línea no es JSON válido la saltamos
                # sin detener todo el proceso
                continue

            # Las claves en este archivo son con mayúscula: "ID", "Info"
            cve_id = (
                entrada.get("ID")
                or entrada.get("id")
                or ""
            )

            # Solo incluimos entradas con CVE ID válido
            if not cve_id.upper().startswith("CVE-"):
                continue

            # La severidad y nombre viven dentro del objeto "Info"
            info = entrada.get("Info", {})

            vulnerabilidad = {
                "cve_id":   cve_id.upper(),
                "fuente":   "NUCLEI",
                "severity": info.get("Severity", ""),
                "name":     info.get("Name", ""),
            }
            vulnerabilidades.append(vulnerabilidad)

        print(f"[NUCLEI] {len(vulnerabilidades)} CVEs descargados.")
        return vulnerabilidades

    except requests.exceptions.ConnectionError:
        print("[NUCLEI] ERROR: No se pudo conectar a GitHub.")
        return None

    except requests.exceptions.Timeout:
        print("[NUCLEI] ERROR: La conexión tardó demasiado.")
        return None

    except requests.exceptions.HTTPError as error:
        print(f"[NUCLEI] ERROR HTTP: {error}")
        return None


def extraer_ids(vulnerabilidades):
    """
    Recibe la lista de diccionarios y devuelve solo los CVE IDs.

    Return:
        set[str]: conjunto de CVE IDs únicos de Nuclei
    """
    conjunto_ids = set()

    for vulnerabilidad in vulnerabilidades:
        cve_id = vulnerabilidad["cve_id"]

        if cve_id:
            conjunto_ids.add(cve_id)

    return conjunto_ids
