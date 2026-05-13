"""
Nombre: services/cve_service.py
Autor: Cesar Ospina Muñoz
Fecha: 2026-05-12
Descripción: Lógica de negocio para la gestión de CVEs.

"""

import math
from database.storage import repositorio
from models.cve import Cve


def obtener_todos(severidad=None, fuente=None, buscar=None, pagina=1, limite=50):
    """
    Devuelve la lista de CVEs aplicando filtros y paginación.

    Parámetros:
        severidad : filtra por cvss_v31_base_severity (CRITICAL, HIGH, MEDIUM, LOW)
        fuente    : filtra por origen (CISA, NUCLEI, AMBAS)
        buscar    : búsqueda de texto en CVE ID y descripción
        pagina    : número de página, empieza en 1
        limite    : cuántos resultados por página

    Retorna:
        dict con total, pagina, limite, paginas y lista de datos
    """

    resultados = list(repositorio.values())

    # Filtro por severidad v3.1
    if severidad:
        resultados = [
            cve for cve in resultados
            if str(cve.get("cvss_v31_base_severity", "")).upper() == severidad.upper()
        ]

    # Filtro por fuente de origen
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

    # Filtro por texto libre
    if buscar:
        termino = buscar.lower()
        resultados = [
            cve for cve in resultados
            if termino in str(cve.get("cve_id", "")).lower()
            or termino in str(cve.get("descripcion", "")).lower()
        ]

    # Paginación
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
    """
    Busca un CVE por su ID exacto.

    Retorna:
        dict con los datos del CVE, o None si no existe
    """
    return repositorio.get(cve_id)


def crear(cve: Cve):
    """
    Inserta un nuevo CVE en el repositorio.

    Retorna:
        dict con los datos del CVE creado
        None si el CVE ya existe
    """

    if cve.cve_id in repositorio:
        return None

    repositorio[cve.cve_id] = cve.model_dump()
    return repositorio[cve.cve_id]


def actualizar(cve_id: str, cve: Cve):
    """
    Actualiza todos los campos de un CVE existente.

    Retorna:
        dict con los datos actualizados
        None si el CVE no existe
    """

    if cve_id not in repositorio:
        return None

    datos_actualizados = cve.model_dump()
    datos_actualizados["cve_id"] = cve_id
    repositorio[cve_id] = datos_actualizados

    return repositorio[cve_id]


def eliminar(cve_id: str):
    """
    Elimina un CVE del repositorio.

    Retorna:
        True si fue eliminado
        False si no existía
    """

    if cve_id not in repositorio:
        return False

    del repositorio[cve_id]
    return True


def obtener_estadisticas():
    """
    Calcula estadísticas generales del dataset actual.

    Retorna:
        dict con total, distribución por severidad y por fuente
    """

    todos  = list(repositorio.values())
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
