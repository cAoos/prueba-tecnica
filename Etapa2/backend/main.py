"""
Nombre: main.py
Autor: Cesar Ospina Muñoz
Fecha: 2026-05-13
Descripción: Punto de entrada. Conecta a PostgreSQL al arrancar.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from database.storage import inicializar
from routers.cve_router import router as cve_router
from config import ORIGENES_PERMITIDOS

app = FastAPI(
    title="CVE Manager API",
    description="API REST para gestión de vulnerabilidades CISA y Nuclei",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ORIGENES_PERMITIDOS,
    allow_methods=["*"],
    allow_headers=["*"],
)

inicializar()

app.include_router(cve_router)

@app.get("/")
def raiz():
    return {"mensaje": "CVE Manager API v2 con PostgreSQL", "docs": "/docs"}
