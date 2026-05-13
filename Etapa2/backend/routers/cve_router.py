"""
Nombre: routers/cve_router.py
Autor: Cesar Ospina Muñoz
Fecha: 2026-05-12
Descripción: Endpoints REST para la gestión de CVEs.

Este módulo traduce peticiones HTTP a llamadas al servicio.
"""

from fastapi import APIRouter, HTTPException, Query
from typing import Optional
from models.cve import Cve
from services import cve_service


router = APIRouter(prefix="/api/cves", tags=["CVEs"])


@router.get("")
def listar_cves(
    severidad: Optional[str] = Query(None, description="CRITICAL, HIGH, MEDIUM, LOW"),
    fuente:    Optional[str] = Query(None, description="CISA, NUCLEI, AMBAS"),
    buscar:    Optional[str] = Query(None, description="Texto libre en ID o descripción"),
    pagina:    int           = Query(1, ge=1),
    limite:    int           = Query(50, ge=1, le=500),
):
    return cve_service.obtener_todos(severidad, fuente, buscar, pagina, limite)


@router.get("/{cve_id}")
def obtener_cve(cve_id: str):
    cve = cve_service.obtener_por_id(cve_id)
    if cve is None:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} no encontrado")
    return cve


@router.post("", status_code=201)
def crear_cve(cve: Cve):
    resultado = cve_service.crear(cve)
    if resultado is None:
        raise HTTPException(status_code=409, detail=f"CVE {cve.cve_id} ya existe")
    return resultado


@router.put("/{cve_id}")
def actualizar_cve(cve_id: str, cve: Cve):
    resultado = cve_service.actualizar(cve_id, cve)
    if resultado is None:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} no encontrado")
    return resultado


@router.delete("/{cve_id}", status_code=204)
def eliminar_cve(cve_id: str):
    eliminado = cve_service.eliminar(cve_id)
    if not eliminado:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} no encontrado")
    return None


@router.get("/stats/resumen")
def estadisticas():
    return cve_service.obtener_estadisticas()
