"""
Nombre: main.py
Autor: Cesar Ospina Muñoz
Fecha: 2026-05-12
Descripción: Orquestador principal de la Etapa 1.

Este archivo no contiene lógica de negocio propia.
Su única responsabilidad es llamar a cada módulo en el orden
correcto y pasar los datos entre ellos.

Flujo:
    1. Descargar CISA KEV y Nuclei
    2. Unir los CVE IDs de ambas fuentes
    3. Consultar la API del NIST (o usar caché existente)
    4. Exportar el dataset principal enriquecido
    5. Análisis CVE vs CWE
    6. Ranking de plataformas por CPE

Uso:
    python main.py
"""

import json
import pandas
from pathlib import Path
from tqdm import tqdm
from analysis import visualizaciones


from sources import cisa_kev
from sources import nuclei
from api import nvd_api


# Carpeta donde se guardarán todos los archivos de salida
CARPETA_OUTPUT = Path(__file__).parent / "output"

# Carpeta donde están los CVEs ya descargados
CACHE_DIR = Path(__file__).parent / "cache"


def main():
    """
    Función principal que coordina todo el pipeline de datos.
    """

    print("=" * 60)
    print("  ETAPA 1 – Análisis de Vulnerabilidades CVE")
    print("=" * 60)
    print()

    # ── PASO 1: Descargar las dos fuentes ────────────────────────
    print("── Paso 1: Descargando fuentes de datos ──")
    print()

    lista_cisa = cisa_kev.descargar_cisa()
    lista_nuclei_data = nuclei.descargar_nuclei()

    if lista_cisa is None:
        print("ERROR FATAL: No se pudo descargar CISA KEV. Abortando.")
        return

    if lista_nuclei_data is None:
        print("ERROR FATAL: No se pudo descargar Nuclei. Abortando.")
        return

    # ── PASO 2: Unir los CVE IDs ─────────────────────────────────
    print()
    print("── Paso 2: Construyendo conjunto unificado de CVE IDs ──")
    print()

    ids_cisa = cisa_kev.extraer_ids(lista_cisa)
    ids_nuclei = nuclei.extraer_ids(lista_nuclei_data)

    todos_los_ids = ids_cisa | ids_nuclei

    cantidad_en_ambas = 0
    for cve_id in todos_los_ids:
        if cve_id in ids_cisa and cve_id in ids_nuclei:
            cantidad_en_ambas = cantidad_en_ambas + 1

    print(f"  CVEs en CISA KEV:        {len(ids_cisa):>6}")
    print(f"  CVEs en Nuclei:          {len(ids_nuclei):>6}")
    print(f"  CVEs en ambas fuentes:   {cantidad_en_ambas:>6}")
    print(f"  Total único a consultar: {len(todos_los_ids):>6}")
    print()

    # ── PASO 3: Elegir modo de consulta ──────────────────────────
    print("── Paso 3: Modo de enriquecimiento con NVD ──")
    print()

    cves_en_cache = contar_cves_en_cache()
    print(f"  CVEs actualmente en caché: {cves_en_cache}")
    print()
    print("  Opciones:")
    print("    1. Consultar API del NIST (completo, puede tardar varios minutos)")
    print("    2. Usar solo CVEs ya descargados en caché (inmediato)")
    print()

    opcion = input("  Elige una opción (1 o 2): ").strip()

    while opcion not in ["1", "2"]:
        print("  Opción inválida. Escribe 1 o 2.")
        opcion = input("  Elige una opción (1 o 2): ").strip()

    print()

    # ── PASO 3A: Consultar API completa ──────────────────────────
    if opcion == "1":
        vulnerabilidades_enriquecidas = consultar_api_completa(
            todos_los_ids, ids_cisa, ids_nuclei
        )

    # ── PASO 3B: Usar solo caché existente ───────────────────────
    else:
        vulnerabilidades_enriquecidas = cargar_desde_cache_existente(
            todos_los_ids, ids_cisa, ids_nuclei
        )

    if not vulnerabilidades_enriquecidas:
        print("ERROR: No hay datos para procesar. Abortando.")
        return

    print(f"  CVEs listos para analizar: {len(vulnerabilidades_enriquecidas)}")

    # ── PASO 4: Exportar dataset principal ───────────────────────
    print()
    print("── Paso 4: Exportando dataset principal ──")
    exportar_dataset_principal(vulnerabilidades_enriquecidas, CARPETA_OUTPUT)

    # ── PASO 5: Análisis CVE vs CWE ──────────────────────────────
    print()
    print("── Paso 5: Análisis CVE vs CWE ──")
    exportar_analisis_cwe(vulnerabilidades_enriquecidas, CARPETA_OUTPUT)

    # ── PASO 6: Ranking de plataformas CPE ───────────────────────
    print()
    print("── Paso 6: Ranking de plataformas por CPE ──")
    exportar_ranking_cpe(vulnerabilidades_enriquecidas, CARPETA_OUTPUT)

    # ── PASO 7: Generar gráficas ──────────────────────────────────
    print()
    print("── Paso 7: Generando visualizaciones ──")
    visualizaciones.generar_todas(vulnerabilidades_enriquecidas, CARPETA_OUTPUT)

    # ── FIN ───────────────────────────────────────────────────────
    print()
    print("=" * 60)
    print("  Etapa 1 completada exitosamente.")
    print(f"  Archivos generados en: {CARPETA_OUTPUT.resolve()}")
    print("=" * 60)

    


# ─── Modos de consulta ────────────────────────────────────────────────────────

def contar_cves_en_cache():
    """
    Cuenta cuántos archivos JSON hay en la carpeta cache/.

    Retorna:
        int: número de CVEs ya descargados
    """
    if not CACHE_DIR.exists():
        return 0

    archivos_json = list(CACHE_DIR.glob("*.json"))
    return len(archivos_json)


def consultar_api_completa(todos_los_ids, ids_cisa, ids_nuclei):
    """
    Consulta la API del NIST para cada CVE ID.
    Los que ya están en caché se cargan del disco sin llamar a la API.

    Retorna:
        list[dict]: lista de CVEs enriquecidos
    """

    print("── Consultando API del NIST ──")
    print()

    api_key = nvd_api.obtener_api_key()
    print()

    lista_ids_ordenada = sorted(list(todos_los_ids))
    vulnerabilidades_enriquecidas = []

    for cve_id in tqdm(lista_ids_ordenada, desc="Consultando NVD", unit="CVE"):

        datos_nvd = nvd_api.consultar_cve(cve_id, api_key)

        if datos_nvd is None:
            datos_nvd = construir_entrada_vacia(cve_id)

        datos_nvd["fuente_cisa"]   = cve_id in ids_cisa
        datos_nvd["fuente_nuclei"] = cve_id in ids_nuclei

        vulnerabilidades_enriquecidas.append(datos_nvd)

    return vulnerabilidades_enriquecidas


def cargar_desde_cache_existente(todos_los_ids, ids_cisa, ids_nuclei):
    """
    Lee los CVEs directamente desde los archivos JSON en cache/.
    No llama a la API del NIST en ningún momento.

    Los CVEs que no están en caché se incluyen con campos vacíos
    para no perder la referencia de su fuente de origen.

    Retorna:
        list[dict]: lista de CVEs enriquecidos con lo disponible en caché
    """

    print("── Cargando CVEs desde caché local ──")
    print()

    lista_ids_ordenada = sorted(list(todos_los_ids))
    vulnerabilidades_enriquecidas = []

    cargados_desde_cache = 0
    sin_datos = 0

    for cve_id in tqdm(lista_ids_ordenada, desc="Leyendo caché", unit="CVE"):

        ruta_cache = CACHE_DIR / f"{cve_id}.json"

        if ruta_cache.exists():
            try:
                with open(ruta_cache, "r", encoding="utf-8") as archivo:
                    datos_nvd = json.load(archivo)

                # El archivo puede contener None si el CVE no existía en NVD
                if datos_nvd is None:
                    datos_nvd = construir_entrada_vacia(cve_id)

                cargados_desde_cache = cargados_desde_cache + 1

            except (json.JSONDecodeError, IOError):
                datos_nvd = construir_entrada_vacia(cve_id)
                sin_datos = sin_datos + 1
        else:
            # No está en caché — lo incluimos vacío
            datos_nvd = construir_entrada_vacia(cve_id)
            sin_datos = sin_datos + 1

        datos_nvd["fuente_cisa"]   = cve_id in ids_cisa
        datos_nvd["fuente_nuclei"] = cve_id in ids_nuclei

        vulnerabilidades_enriquecidas.append(datos_nvd)

    print()
    print(f"  Cargados desde caché: {cargados_desde_cache}")
    print(f"  Sin datos en caché:   {sin_datos}")

    return vulnerabilidades_enriquecidas


def construir_entrada_vacia(cve_id):
    """
    Construye un diccionario vacío para un CVE que no tiene datos.
    Se usa cuando el NIST no tiene información o no está en caché.

    Retorna:
        dict: con todos los campos esperados pero vacíos
    """
    return {
        "cve_id":                        cve_id,
        "descripcion":                   "No disponible en NVD",
        "cvss_v31_base_score":           None,
        "cvss_v31_base_severity":        "",
        "cvss_v31_vector_string":        "",
        "cvss_v31_exploitability_score": None,
        "cvss_v31_impact_score":         None,
        "cvss_v2_base_score":            None,
        "cvss_v2_base_severity":         "",
        "cvss_v2_vector_string":         "",
        "cvss_v2_exploitability_score":  None,
        "cvss_v2_impact_score":          None,
        "cwes":                          [],
        "cpes":                          [],
    }


# ─── Funciones de exportación ─────────────────────────────────────────────────

def exportar_dataset_principal(vulnerabilidades, carpeta_output):
    """
    Convierte la lista de CVEs enriquecidos en un CSV principal.
    Una fila por CVE con todos los campos aplanados.
    """

    carpeta_output.mkdir(exist_ok=True)

    filas = []
    for vuln in vulnerabilidades:

        fuentes = []
        if vuln.get("fuente_cisa"):
            fuentes.append("CISA")
        if vuln.get("fuente_nuclei"):
            fuentes.append("NUCLEI")
        fuente_texto = " + ".join(fuentes)

        cwes_texto = " | ".join(vuln.get("cwes", []))
        cpes_texto = " | ".join(vuln.get("cpes", [])[:10])

        fila = {
            "cve_id":                        vuln.get("cve_id", ""),
            "fuente":                        fuente_texto,
            "fuente_cisa":                   vuln.get("fuente_cisa", False),
            "fuente_nuclei":                 vuln.get("fuente_nuclei", False),
            "descripcion":                   vuln.get("descripcion", ""),
            "cvss_v31_base_score":           vuln.get("cvss_v31_base_score"),
            "cvss_v31_base_severity":        vuln.get("cvss_v31_base_severity", ""),
            "cvss_v31_vector_string":        vuln.get("cvss_v31_vector_string", ""),
            "cvss_v31_exploitability_score": vuln.get("cvss_v31_exploitability_score"),
            "cvss_v31_impact_score":         vuln.get("cvss_v31_impact_score"),
            "cvss_v2_base_score":            vuln.get("cvss_v2_base_score"),
            "cvss_v2_base_severity":         vuln.get("cvss_v2_base_severity", ""),
            "cvss_v2_vector_string":         vuln.get("cvss_v2_vector_string", ""),
            "cvss_v2_exploitability_score":  vuln.get("cvss_v2_exploitability_score"),
            "cvss_v2_impact_score":          vuln.get("cvss_v2_impact_score"),
            "cwes":                          cwes_texto,
            "cantidad_cpes":                 len(vuln.get("cpes", [])),
            "cpes_muestra":                  cpes_texto,
        }
        filas.append(fila)

    dataframe = pandas.DataFrame(filas)
    ruta_csv = carpeta_output / "vulnerabilidades.csv"
    dataframe.to_csv(ruta_csv, index=False, encoding="utf-8")

    print(f"  Dataset guardado en: {ruta_csv}")

    print("\n  Distribución por severidad (v3.1):")
    conteo = dataframe["cvss_v31_base_severity"].value_counts()
    for severidad, cantidad in conteo.items():
        if severidad:
            print(f"    {severidad:<12}: {cantidad}")
    print()


def exportar_analisis_cwe(vulnerabilidades, carpeta_output):
    """
    Construye la relación CVE ↔ CWE y calcula estadísticas por CWE.
    """

    filas_relacion = []

    for vuln in vulnerabilidades:
        cve_id = vuln.get("cve_id", "")
        cwes = vuln.get("cwes", [])

        if not cwes:
            cwes = ["SIN_CWE"]

        for cwe in cwes:
            fila = {
                "cve_id":                        cve_id,
                "cwe":                           cwe,
                "cvss_v31_base_score":           vuln.get("cvss_v31_base_score"),
                "cvss_v31_exploitability_score": vuln.get("cvss_v31_exploitability_score"),
                "cvss_v31_impact_score":         vuln.get("cvss_v31_impact_score"),
                "cvss_v2_base_score":            vuln.get("cvss_v2_base_score"),
                "cvss_v2_exploitability_score":  vuln.get("cvss_v2_exploitability_score"),
                "cvss_v2_impact_score":          vuln.get("cvss_v2_impact_score"),
                "fuente_cisa":                   vuln.get("fuente_cisa", False),
                "fuente_nuclei":                 vuln.get("fuente_nuclei", False),
            }
            filas_relacion.append(fila)

    tabla_relacion = pandas.DataFrame(filas_relacion)

    columnas_numericas = [
        "cvss_v31_base_score", "cvss_v31_exploitability_score", "cvss_v31_impact_score",
        "cvss_v2_base_score", "cvss_v2_exploitability_score", "cvss_v2_impact_score",
    ]
    for columna in columnas_numericas:
        tabla_relacion[columna] = pandas.to_numeric(tabla_relacion[columna], errors="coerce")

    estadisticas = tabla_relacion.groupby("cwe").agg(
        cantidad_cves=("cve_id", "count"),
        v31_score_promedio=("cvss_v31_base_score", "mean"),
        v31_score_maximo=("cvss_v31_base_score", "max"),
        v31_exploitability_promedio=("cvss_v31_exploitability_score", "mean"),
        v2_score_promedio=("cvss_v2_base_score", "mean"),
        v2_score_maximo=("cvss_v2_base_score", "max"),
    ).reset_index()

    columnas_a_redondear = [
        "v31_score_promedio", "v31_score_maximo", "v31_exploitability_promedio",
        "v2_score_promedio", "v2_score_maximo",
    ]
    estadisticas[columnas_a_redondear] = estadisticas[columnas_a_redondear].round(2)
    estadisticas = estadisticas.sort_values("cantidad_cves", ascending=False)

    ruta_relacion = carpeta_output / "cve_cwe_relacion.csv"
    ruta_estadisticas = carpeta_output / "cwe_estadisticas.csv"

    tabla_relacion.to_csv(ruta_relacion, index=False, encoding="utf-8")
    estadisticas.to_csv(ruta_estadisticas, index=False, encoding="utf-8")

    print(f"  Relación CVE↔CWE guardada en: {ruta_relacion}")
    print(f"  Estadísticas CWE guardadas en: {ruta_estadisticas}")

    print("\n  Top 10 CWEs más frecuentes:")
    print(estadisticas.head(10).to_string(index=False))
    print()


def exportar_ranking_cpe(vulnerabilidades, carpeta_output):
    """
    Parsea los CPE strings y construye un ranking de plataformas
    ordenado por cantidad de CVEs que las afectan.
    """

    tipos_cpe = {
        "a": "Aplicación",
        "o": "Sistema Operativo",
        "h": "Hardware",
    }

    filas = []

    for vuln in vulnerabilidades:
        cve_id = vuln.get("cve_id", "")
        cpes = vuln.get("cpes", [])

        for cpe_string in cpes:

            if not cpe_string.startswith("cpe:"):
                continue

            partes = cpe_string.split(":")

            if len(partes) < 6:
                continue

            tipo_codigo = partes[2]
            vendor      = partes[3]
            producto    = partes[4]
            version     = partes[5]

            if vendor == "*" or producto == "*":
                continue

            fila = {
                "cve_id":              cve_id,
                "tipo":                tipos_cpe.get(tipo_codigo, "Desconocido"),
                "vendor":              vendor,
                "producto":            producto,
                "version":             version if version != "*" else "Todas",
                "cvss_v31_base_score": vuln.get("cvss_v31_base_score"),
                "cvss_v2_base_score":  vuln.get("cvss_v2_base_score"),
            }
            filas.append(fila)

    if not filas:
        print("  Sin datos CPE disponibles.")
        return

    tabla_cpe = pandas.DataFrame(filas)

    tabla_cpe["cvss_v31_base_score"] = pandas.to_numeric(
        tabla_cpe["cvss_v31_base_score"], errors="coerce"
    )

    ranking = tabla_cpe.groupby(["tipo", "vendor", "producto"]).agg(
        cantidad_cves=("cve_id", "nunique"),
        v31_score_promedio=("cvss_v31_base_score", "mean"),
        v31_score_maximo=("cvss_v31_base_score", "max"),
    ).reset_index()

    ranking["v31_score_promedio"] = ranking["v31_score_promedio"].round(2)
    ranking["v31_score_maximo"]   = ranking["v31_score_maximo"].round(2)
    ranking = ranking.sort_values("cantidad_cves", ascending=False)

    ruta_cpe = carpeta_output / "cpe_ranking.csv"
    ranking.to_csv(ruta_cpe, index=False, encoding="utf-8")

    print(f"  Ranking CPE guardado en: {ruta_cpe}")
    print("\n  Top 15 plataformas más afectadas:")
    print(ranking.head(15).to_string(index=False))
    print()


# Punto de entrada
if __name__ == "__main__":
    main()