"""
Nombre: services/cve_service.py
Autor: Cesar Ospina Muñoz
Fecha: 2026-05-13
Descripción: Lógica de negocio para CVEs.
             Delega el almacenamiento a database/storage.py
"""

import math
from database import storage
from models.cve import Cve


def obtener_todos(severidad=None, fuente=None, buscar=None, pagina=1, limite=50):

    resultados = storage.obtener_todos()

    if severidad:
        resultados = [
            cve for cve in resultados
            if str(cve.get("cvss_v31_base_severity", "")).upper() == severidad.upper()
        ]

    if fuente:
        if fuente.upper() == "CISA":
            resultados = [cve for cve in resultados if cve.get("fuente_cisa") == True]
        elif fuente.upper() == "NUCLEI":
            resultados = [cve for cve in resultados if cve.get("fuente_nuclei") == True]
        elif fuente.upper() == "AMBAS":
            resultados = [
                cve for cve in resultados
                if cve.get("fuente_cisa") == True and cve.get("fuente_nuclei") == True
            ]

    if buscar:
        termino = buscar.lower()
        resultados = [
            cve for cve in resultados
            if termino in str(cve.get("cve_id", "")).lower()
            or termino in str(cve.get("descripcion", "")).lower()
        ]

    total  = len(resultados)
    inicio = (pagina - 1) * limite
    fin    = inicio + limite

    return {
        "total":   total,
        "pagina":  pagina,
        "limite":  limite,
        "paginas": math.ceil(total / limite) if total > 0 else 1,
        "datos":   resultados[inicio:fin],
    }


def obtener_por_id(cve_id: str):
    return storage.obtener_por_id(cve_id)


def crear(cve: Cve):
    if storage.obtener_por_id(cve.cve_id) is not None:
        return None
    datos = cve.model_dump()
    storage.insertar(datos)
    return storage.obtener_por_id(cve.cve_id)


def actualizar(cve_id: str, cve: Cve):
    if storage.obtener_por_id(cve_id) is None:
        return None
    datos = cve.model_dump()
    datos["cve_id"] = cve_id
    storage.actualizar(cve_id, datos)
    return storage.obtener_por_id(cve_id)


def eliminar(cve_id: str):
    if storage.obtener_por_id(cve_id) is None:
        return False
    storage.eliminar(cve_id)
    return True


def obtener_estadisticas():
    todos  = storage.obtener_todos()
    total  = len(todos)

    severidades = {}
    for cve in todos:
        sev = str(cve.get("cvss_v31_base_severity", "") or "")
        if sev:
            severidades[sev] = severidades.get(sev, 0) + 1

    solo_cisa   = sum(1 for cve in todos if cve.get("fuente_cisa") and not cve.get("fuente_nuclei"))
    solo_nuclei = sum(1 for cve in todos if cve.get("fuente_nuclei") and not cve.get("fuente_cisa"))
    en_ambas    = sum(1 for cve in todos if cve.get("fuente_cisa") and cve.get("fuente_nuclei"))

    return {
        "total_cves":    total,
        "por_severidad": severidades,
        "por_fuente": {
            "solo_cisa":   solo_cisa,
            "solo_nuclei": solo_nuclei,
            "ambas":       en_ambas,
        },
    }
