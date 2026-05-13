"""
Nombre: models/cve.py
Autor: Cesar Ospina Muñoz
Fecha: 2026-05-12
Descripción: Modelo Pydantic que define la estructura de un CVE.
             Pydantic valida automáticamente los tipos de cada campo
             cuando llegan datos desde el frontend o la API.
"""

from pydantic import BaseModel
from typing import Optional


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
