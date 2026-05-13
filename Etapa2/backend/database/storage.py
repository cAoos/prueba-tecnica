"""
Nombre: database/storage.py
Autor: Cesar Ospina Muñoz
Fecha: 2026-05-12
Descripción: Base de datos en memoria y carga inicial desde CSV.

Diccionario Python como almacenamiento en memoria.
La clave es el CVE ID y el valor es el diccionario de datos.
Si mañana se quiere usar PostgreSQL, solo se modifica este archivo.
"""

import math
import pandas
from config import RUTA_CSV


# Diccionario principal
repositorio: dict[str, dict] = {}


def cargar_csv():
    """
    Lee el CSV de Etapa 1 y puebla el repositorio en memoria.
    Se llama una sola vez al arrancar la aplicación.
    """

    if not RUTA_CSV.exists():
        print(f"[Storage] CSV no encontrado en: {RUTA_CSV}")
        print("[Storage] La API iniciará con base de datos vacía.")
        return

    print(f"[Storage] Cargando datos desde: {RUTA_CSV}")

    dataframe = pandas.read_csv(RUTA_CSV, low_memory=False)

    cargados = 0
    for _, fila in dataframe.iterrows():

        cve_id = str(fila.get("cve_id", "")).strip()

        if not cve_id or not cve_id.startswith("CVE-"):
            continue

        repositorio[cve_id] = limpiar_fila(fila)
        cargados = cargados + 1

    print(f"[Storage] {cargados} CVEs cargados en memoria.")


def limpiar_fila(fila):
    """
    Convierte una fila del DataFrame en un diccionario limpio.
    Reemplaza NaN por None para que JSON.
    """

    resultado = {}

    for columna, valor in fila.items():
        if isinstance(valor, float) and math.isnan(valor):
            resultado[columna] = None
        else:
            resultado[columna] = valor

    return resultado
