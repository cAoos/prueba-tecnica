"""
Nombre: config.py
Autor: Cesar Ospina Muñoz
Fecha: 2026-05-12
Descripción: Configuración global de la aplicación.
"""

from pathlib import Path

# Ruta al CSV generado por Etapa 1
RUTA_CSV = (
    Path.home()
    / "Documentos"
    / "Bancolombia"
    / "Repo"
    / "Etapa1"
    / "output"
    / "vulnerabilidades.csv"
)

# Puerto del servidor
PUERTO = 8080

# Orígenes permitidos para CORS
ORIGENES_PERMITIDOS = [
    "http://localhost:4200",
]
