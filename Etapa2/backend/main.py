"""
Nombre: main.py
Autor: Cesar Ospina Muñoz
Fecha: 2026-05-12
Descripción: Punto de entrada de la aplicación.
             Solo ensambla los módulos y arranca el servidor.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from database.storage import cargar_csv
from routers.cve_router import router as cve_router
from config import ORIGENES_PERMITIDOS


app = FastAPI(
    title="CVE Manager API",
    description="API REST para gestión de vulnerabilidades CISA y Nuclei",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ORIGENES_PERMITIDOS,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Cargamos los datos del CSV al arrancar
cargar_csv()

# Registramos las rutas
app.include_router(cve_router)


@app.get("/")
def raiz():
    return {"mensaje": "CVE Manager API funcionando", "docs": "/docs"}
