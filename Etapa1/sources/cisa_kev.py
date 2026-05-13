"""
Nombre: source/cisa_kev.py
Autor: Cesar Ospina Muñoz
Fecha: 2026-05-12
Descripción: Descargar el catálogo de CISA y 
             retornar los datos limpios
"""

import requests

# URL oficial del catálogo de CISA KEV en formato JSON
cisa_kev_url = ("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")

def descargar_cisa():
    """
    Descarga el catálogo CISA KEV retornando una lista de diccionarios

    Estructura diccionario:
        - cve_id      : identificador único (ej. "CVE-2021-44228")
        - vendor      : proveedor del producto afectado (ej. "Apache")
        - product     : nombre del producto (ej. "Log4j")
        - date_added  : fecha en que CISA añadió esta vulnerabilidad
        - fuente      : siempre "CISA" para identificar el origen
 
    Return:
        list[dict]: lista de vulnerabilidades parseadas
        None: si la descarga falla
    """
    
    print("[CISA] Descargando KEV")

    try:
        # Petición HTTP con timeuot de 30 segundos.
        respuesta = requests.get(cisa_kev_url, timeout=30)

        # Verificar que la respuesta fue exitosa
        respuesta.raise_for_status()
        
        # Parsear el JSON
        datos_crudos = respuesta.json()

        # Extraemos solo la lista de vulnerabilidades.
        lista_crudos = datos_crudos.get("vulnerabilities", [])

        # Iteramos sobre cada entrada y extraemos solo los campos de interes.
        vulnerabilidades = []
        for entrada in lista_crudos:
            vulnerabilidad = {
                "cve_id":     entrada.get("cveID", ""),
                "vendor":     entrada.get("vendorProject", ""),
                "product":    entrada.get("product", ""),
                "date_added": entrada.get("dateAdded", ""),
                "fuente":     "CISA",
            }
            vulnerabilidades.append(vulnerabilidad)
 
        print(f"[CISA] {len(vulnerabilidades)} vulnerabilidades descargadas.")
        return vulnerabilidades

    except requests.exceptions.ConnectionError:
        # No hay conexión a internet o el servidor es inalcanzable
        print("[CISA] ERROR: No se pudo conectar al servidor de CISA.")
        return None
 
    except requests.exceptions.Timeout:
        # El servidor tardó más de 30 segundos en responder
        print("[CISA] ERROR: La conexión tardó demasiado. Intenta de nuevo.")
        return None
 
    except requests.exceptions.HTTPError as error:
        # El servidor respondió con un código de error (4xx, 5xx)
        print(f"[CISA] ERROR HTTP: {error}")
        return None

def extraer_ids(vulnerabilidades):
    """
    Recibe la lista de diccionarios y devuelve solo los CVE IDs.
 
    Return:
        set[str]: conjunto de CVE IDs únicos de CISA
    """
    conjunto_ids = set()

    for vulnerabilidad in vulnerabilidades:
        cve_id = vulnerabilidad["cve_id"]

        if cve_id:
            conjunto_ids.add(cve_id)

    return conjunto_ids
