"""
Nombre: database/storage.py
Autor: Cesar Ospina Muñoz
Fecha: 2026-05-13
Descripción: Almacenamiento con PostgreSQL via SQLAlchemy.
             Si no hay BD disponible, cae back a memoria.
"""

import math
import os
import pandas
from config import RUTA_CSV
from sqlalchemy import create_engine, text


# URL de conexión a PostgreSQL
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:enTeiMDplIBkujgyTvcCCvNEdIlneydY@yamabiko.proxy.rlwy.net:20714/railway"
)

# Motor de SQLAlchemy
engine = None

# Diccionario en memoria como fallback
repositorio: dict[str, dict] = {}

# Flag para saber si estamos usando BD o memoria
usando_base_de_datos = False


def inicializar():
    """
    Intenta conectar a PostgreSQL.
    Si falla, cae a almacenamiento en memoria.
    """
    global engine, usando_base_de_datos

    try:
        engine = create_engine(DATABASE_URL)

        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))

        crear_tabla()
        usando_base_de_datos = True
        print("[Storage] Conectado a PostgreSQL.")

        # Si la tabla está vacía, cargamos el CSV
        if contar_registros() == 0:
            cargar_csv_a_postgres()

    except Exception as error:
        print(f"[Storage] PostgreSQL no disponible: {error}")
        print("[Storage] Usando almacenamiento en memoria.")
        usando_base_de_datos = False
        cargar_csv_memoria()


def crear_tabla():
    """
    Crea la tabla cves si no existe.
    """
    with engine.connect() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS cves (
                cve_id VARCHAR(50) PRIMARY KEY,
                fuente VARCHAR(20),
                fuente_cisa BOOLEAN,
                fuente_nuclei BOOLEAN,
                descripcion TEXT,
                cvss_v31_base_score FLOAT,
                cvss_v31_base_severity VARCHAR(20),
                cvss_v31_vector_string VARCHAR(200),
                cvss_v31_exploitability_score FLOAT,
                cvss_v31_impact_score FLOAT,
                cvss_v2_base_score FLOAT,
                cvss_v2_base_severity VARCHAR(20),
                cvss_v2_vector_string VARCHAR(200),
                cvss_v2_exploitability_score FLOAT,
                cvss_v2_impact_score FLOAT,
                cwes TEXT,
                cantidad_cpes INTEGER,
                cpes_muestra TEXT
            )
        """))
        conn.commit()
    print("[Storage] Tabla cves lista.")


def contar_registros():
    """
    Cuenta cuántos registros hay en la tabla.
    """
    with engine.connect() as conn:
        resultado = conn.execute(text("SELECT COUNT(*) FROM cves"))
        return resultado.scalar()


def cargar_csv_a_postgres():
    """
    Carga el CSV de Etapa 1 en PostgreSQL.
    """
    if not RUTA_CSV.exists():
        print(f"[Storage] CSV no encontrado: {RUTA_CSV}")
        return

    print(f"[Storage] Cargando CSV en PostgreSQL...")
    df = pandas.read_csv(RUTA_CSV, low_memory=False)

    cargados = 0
    with engine.connect() as conn:
        for _, fila in df.iterrows():
            cve_id = str(fila.get("cve_id", "")).strip()
            if not cve_id or not cve_id.startswith("CVE-"):
                continue
            try:
                conn.execute(text("""
                    INSERT INTO cves VALUES (
                        :cve_id, :fuente, :fuente_cisa, :fuente_nuclei,
                        :descripcion,
                        :cvss_v31_base_score, :cvss_v31_base_severity,
                        :cvss_v31_vector_string, :cvss_v31_exploitability_score,
                        :cvss_v31_impact_score,
                        :cvss_v2_base_score, :cvss_v2_base_severity,
                        :cvss_v2_vector_string, :cvss_v2_exploitability_score,
                        :cvss_v2_impact_score,
                        :cwes, :cantidad_cpes, :cpes_muestra
                    ) ON CONFLICT (cve_id) DO NOTHING
                """), {
                    "cve_id":                        cve_id,
                    "fuente":                        str(fila.get("fuente", "") or ""),
                    "fuente_cisa":                   bool(fila.get("fuente_cisa", False)),
                    "fuente_nuclei":                 bool(fila.get("fuente_nuclei", False)),
                    "descripcion":                   str(fila.get("descripcion", "") or "")[:5000],
                    "cvss_v31_base_score":           none_si_nan(fila.get("cvss_v31_base_score")),
                    "cvss_v31_base_severity":        str(fila.get("cvss_v31_base_severity", "") or ""),
                    "cvss_v31_vector_string":        str(fila.get("cvss_v31_vector_string", "") or ""),
                    "cvss_v31_exploitability_score": none_si_nan(fila.get("cvss_v31_exploitability_score")),
                    "cvss_v31_impact_score":         none_si_nan(fila.get("cvss_v31_impact_score")),
                    "cvss_v2_base_score":            none_si_nan(fila.get("cvss_v2_base_score")),
                    "cvss_v2_base_severity":         str(fila.get("cvss_v2_base_severity", "") or ""),
                    "cvss_v2_vector_string":         str(fila.get("cvss_v2_vector_string", "") or ""),
                    "cvss_v2_exploitability_score":  none_si_nan(fila.get("cvss_v2_exploitability_score")),
                    "cvss_v2_impact_score":          none_si_nan(fila.get("cvss_v2_impact_score")),
                    "cwes":                          str(fila.get("cwes", "") or "")[:2000],
                    "cantidad_cpes":                 int(fila.get("cantidad_cpes", 0) or 0),
                    "cpes_muestra":                  str(fila.get("cpes_muestra", "") or "")[:2000],
                })
                cargados += 1
            except Exception:
                continue
        conn.commit()

    print(f"[Storage] {cargados} CVEs cargados en PostgreSQL.")


def cargar_csv_memoria():
    """
    Fallback: carga el CSV en memoria si no hay PostgreSQL.
    """
    if not RUTA_CSV.exists():
        return
    df = pandas.read_csv(RUTA_CSV, low_memory=False)
    for _, fila in df.iterrows():
        cve_id = str(fila.get("cve_id", "")).strip()
        if cve_id and cve_id.startswith("CVE-"):
            repositorio[cve_id] = limpiar_fila(fila)
    print(f"[Storage] {len(repositorio)} CVEs en memoria.")


def none_si_nan(valor):
    if valor is None:
        return None
    try:
        if math.isnan(float(valor)):
            return None
        return float(valor)
    except (TypeError, ValueError):
        return None


def limpiar_fila(fila):
    resultado = {}
    for columna, valor in fila.items():
        if isinstance(valor, float) and math.isnan(valor):
            resultado[columna] = None
        else:
            resultado[columna] = valor
    return resultado


# ─── CRUD ─────────────────────────────────────────────────────────────────────

def obtener_todos():
    if usando_base_de_datos:
        with engine.connect() as conn:
            filas = conn.execute(text("SELECT * FROM cves ORDER BY cve_id")).mappings().all()
            return [dict(f) for f in filas]
    return list(repositorio.values())


def obtener_por_id(cve_id: str):
    if usando_base_de_datos:
        with engine.connect() as conn:
            fila = conn.execute(
                text("SELECT * FROM cves WHERE cve_id = :id"), {"id": cve_id}
            ).mappings().first()
            return dict(fila) if fila else None
    return repositorio.get(cve_id)


def insertar(datos: dict):
    if usando_base_de_datos:
        with engine.connect() as conn:
            conn.execute(text("""
                INSERT INTO cves VALUES (
                    :cve_id, :fuente, :fuente_cisa, :fuente_nuclei,
                    :descripcion,
                    :cvss_v31_base_score, :cvss_v31_base_severity,
                    :cvss_v31_vector_string, :cvss_v31_exploitability_score,
                    :cvss_v31_impact_score,
                    :cvss_v2_base_score, :cvss_v2_base_severity,
                    :cvss_v2_vector_string, :cvss_v2_exploitability_score,
                    :cvss_v2_impact_score,
                    :cwes, :cantidad_cpes, :cpes_muestra
                )
            """), datos)
            conn.commit()
    else:
        repositorio[datos["cve_id"]] = datos


def actualizar(cve_id: str, datos: dict):
    if usando_base_de_datos:
        with engine.connect() as conn:
            conn.execute(text("""
                UPDATE cves SET
                    fuente=:fuente, fuente_cisa=:fuente_cisa,
                    fuente_nuclei=:fuente_nuclei, descripcion=:descripcion,
                    cvss_v31_base_score=:cvss_v31_base_score,
                    cvss_v31_base_severity=:cvss_v31_base_severity,
                    cvss_v31_vector_string=:cvss_v31_vector_string,
                    cvss_v31_exploitability_score=:cvss_v31_exploitability_score,
                    cvss_v31_impact_score=:cvss_v31_impact_score,
                    cvss_v2_base_score=:cvss_v2_base_score,
                    cvss_v2_base_severity=:cvss_v2_base_severity,
                    cvss_v2_vector_string=:cvss_v2_vector_string,
                    cvss_v2_exploitability_score=:cvss_v2_exploitability_score,
                    cvss_v2_impact_score=:cvss_v2_impact_score,
                    cwes=:cwes, cantidad_cpes=:cantidad_cpes,
                    cpes_muestra=:cpes_muestra
                WHERE cve_id=:cve_id
            """), datos)
            conn.commit()
    else:
        repositorio[cve_id] = datos


def eliminar(cve_id: str):
    if usando_base_de_datos:
        with engine.connect() as conn:
            conn.execute(text("DELETE FROM cves WHERE cve_id = :id"), {"id": cve_id})
            conn.commit()
    else:
        repositorio.pop(cve_id, None)
