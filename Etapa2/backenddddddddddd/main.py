"""
Nombre: backend/main.py
Autor: Cesar Ospina Muñoz
Fecha: 2026-05-12
Descripción: API REST para gestión de vulnerabilidades CVE.
             Carga los datos del CSV de Etapa 1 al arrancar.

Endpoints:
    GET    /api/cves          - Listar todos (con filtros opcionales)
    GET    /api/cves/{id}     - Obtener uno por ID
    POST   /api/cves          - Crear un CVE
    PUT    /api/cves/{id}     - Actualizar un CVE
    DELETE /api/cves/{id}     - Eliminar un CVE
    GET    /api/stats         - Estadísticas generales
"""

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from pathlib import Path
import pandas
import math


# ─── Aplicación ───────────────────────────────────────────────────────────────

app = FastAPI(
    title="CVE Manager API",
    description="API REST para gestión de vulnerabilidades CISA y Nuclei",
    version="1.0.0",
)

# Permitimos peticiones desde Angular (localhost:4200)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:4200"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Modelo de datos ──────────────────────────────────────────────────────────

class Cve(BaseModel):
    cve_id: str
    fuente: Optional[str] = ""
    fuente_cisa: Optional[bool] = False
    fuente_nuclei: Optional[bool] = False
    descripcion: Optional[str] = ""
    cvss_v31_base_score: Optional[float] = None
    cvss_v31_base_severity: Optional[str] = ""
    cvss_v31_vector_string: Optional[str] = ""
    cvss_v31_exploitability_score: Optional[float] = None
    cvss_v31_impact_score: Optional[float] = None
    cvss_v2_base_score: Optional[float] = None
    cvss_v2_base_severity: Optional[str] = ""
    cvss_v2_vector_string: Optional[str] = ""
    cvss_v2_exploitability_score: Optional[float] = None
    cvss_v2_impact_score: Optional[float] = None
    cwes: Optional[str] = ""
    cantidad_cpes: Optional[int] = None
    cpes_muestra: Optional[str] = ""


# ─── Base de datos en memoria ─────────────────────────────────────────────────
# Usamos un diccionario donde la clave es el CVE ID.
# Al arrancar se carga desde el CSV de Etapa 1.

base_de_datos: dict[str, dict] = {}


def cargar_csv():
    """
    Carga el CSV generado por Etapa 1 en la base de datos en memoria.
    Si el archivo no existe, la base de datos inicia vacía.
    """

    ruta_csv = Path.home() / "Documentos" / "Bancolombia" / "Repo" / "Etapa1" / "output" / "vulnerabilidades.csv"

    if not ruta_csv.exists():
        print(f"[DataLoader] CSV no encontrado en: {ruta_csv}")
        print("[DataLoader] La API iniciará con base de datos vacía.")
        return

    print(f"[DataLoader] Cargando datos desde: {ruta_csv}")

    dataframe = pandas.read_csv(ruta_csv, low_memory=False)

    cargados = 0
    for _, fila in dataframe.iterrows():

        cve_id = str(fila.get("cve_id", "")).strip()

        if not cve_id or not cve_id.startswith("CVE-"):
            continue

        base_de_datos[cve_id] = limpiar_fila(fila)
        cargados = cargados + 1

    print(f"[DataLoader] {cargados} CVEs cargados en memoria.")


def limpiar_fila(fila):
    """
    Convierte una fila del DataFrame en un diccionario limpio.
    Reemplaza NaN por None para que JSON lo serialice como null.
    """

    resultado = {}
    for columna, valor in fila.items():
        if isinstance(valor, float) and math.isnan(valor):
            resultado[columna] = None
        else:
            resultado[columna] = valor

    return resultado


# Cargamos el CSV al arrancar la aplicación
cargar_csv()


# ─── Endpoints ────────────────────────────────────────────────────────────────

@app.get("/api/cves")
def listar_cves(
    severidad: Optional[str] = Query(None),
    fuente:    Optional[str] = Query(None),
    buscar:    Optional[str] = Query(None),
    pagina:    int           = Query(1, ge=1),
    limite:    int           = Query(50, ge=1, le=500),
):
    """
    Lista todos los CVEs con filtros opcionales y paginación.

    Parámetros:
        severidad : CRITICAL, HIGH, MEDIUM, LOW
        fuente    : CISA, NUCLEI, AMBAS
        buscar    : texto libre en CVE ID o descripción
        pagina    : número de página (desde 1)
        limite    : resultados por página (máx 500)
    """

    resultados = list(base_de_datos.values())

    # Filtro por severidad
    if severidad:
        resultados = [
            cve for cve in resultados
            if str(cve.get("cvss_v31_base_severity", "")).upper() == severidad.upper()
        ]

    # Filtro por fuente
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

    # Filtro por texto
    if buscar:
        buscar_lower = buscar.lower()
        resultados = [
            cve for cve in resultados
            if buscar_lower in str(cve.get("cve_id", "")).lower()
            or buscar_lower in str(cve.get("descripcion", "")).lower()
        ]

    # Paginación
    total = len(resultados)
    inicio = (pagina - 1) * limite
    fin = inicio + limite
    pagina_resultados = resultados[inicio:fin]

    return {
        "total":     total,
        "pagina":    pagina,
        "limite":    limite,
        "paginas":   math.ceil(total / limite) if total > 0 else 1,
        "datos":     pagina_resultados,
    }


@app.get("/api/cves/{cve_id}")
def obtener_cve(cve_id: str):
    """
    Obtiene un CVE por su ID exacto.
    """
    cve = base_de_datos.get(cve_id)

    if cve is None:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} no encontrado")

    return cve


@app.post("/api/cves", status_code=201)
def crear_cve(cve: Cve):
    """
    Crea un nuevo CVE en la base de datos.
    """
    if cve.cve_id in base_de_datos:
        raise HTTPException(status_code=409, detail=f"CVE {cve.cve_id} ya existe")

    base_de_datos[cve.cve_id] = cve.model_dump()
    return base_de_datos[cve.cve_id]


@app.put("/api/cves/{cve_id}")
def actualizar_cve(cve_id: str, cve: Cve):
    """
    Actualiza un CVE existente.
    """
    if cve_id not in base_de_datos:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} no encontrado")

    datos_actualizados = cve.model_dump()
    datos_actualizados["cve_id"] = cve_id
    base_de_datos[cve_id] = datos_actualizados

    return base_de_datos[cve_id]


@app.delete("/api/cves/{cve_id}", status_code=204)
def eliminar_cve(cve_id: str):
    """
    Elimina un CVE de la base de datos.
    """
    if cve_id not in base_de_datos:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} no encontrado")

    del base_de_datos[cve_id]
    return None


@app.get("/api/stats")
def obtener_estadisticas():
    """
    Devuelve estadísticas generales del dataset.
    """

    todos = list(base_de_datos.values())
    total = len(todos)

    # Conteo por severidad
    severidades = {}
    for cve in todos:
        sev = str(cve.get("cvss_v31_base_severity", "") or "")
        if sev:
            severidades[sev] = severidades.get(sev, 0) + 1

    # Conteo por fuente
    solo_cisa   = sum(1 for cve in todos if cve.get("fuente_cisa") and not cve.get("fuente_nuclei"))
    solo_nuclei = sum(1 for cve in todos if cve.get("fuente_nuclei") and not cve.get("fuente_cisa"))
    en_ambas    = sum(1 for cve in todos if cve.get("fuente_cisa") and cve.get("fuente_nuclei"))

    return {
        "total_cves":   total,
        "por_severidad": severidades,
        "por_fuente": {
            "solo_cisa":   solo_cisa,
            "solo_nuclei": solo_nuclei,
            "ambas":       en_ambas,
        },
    }


@app.get("/")
def raiz():
    return {"mensaje": "CVE Manager API funcionando", "docs": "/docs"}
