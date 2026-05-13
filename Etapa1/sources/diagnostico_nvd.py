"""
diagnostico_nvd.py
──────────────────
Diagnóstico directo a la API del NIST para ver qué está pasando.
Borrar después de verificar.
"""

import requests
import os
from dotenv import load_dotenv

load_dotenv()

api_key = os.getenv("NVD_API_KEY", "")
CVE_DE_PRUEBA = "CVE-2021-44228"

print(f"API key encontrada: {'Sí' if api_key else 'No'}")
print(f"Consultando: {CVE_DE_PRUEBA}")
print()

url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
parametros = {"cveId": CVE_DE_PRUEBA}
cabeceras = {"apiKey": api_key} if api_key else {}

respuesta = requests.get(url, params=parametros, headers=cabeceras, timeout=30)

print(f"Código de respuesta: {respuesta.status_code}")
print(f"Primeros 300 caracteres:")
print(respuesta.text[:300])

# Verificar exactamente qué key se está usando
print(f"Valor exacto de la key: '{api_key}'")
print(f"Longitud de la key: {len(api_key)} caracteres")
print(f"Cabeceras que se envían: {cabeceras}")
print()

# También probar SIN api key por si el problema es la key misma
print("── Prueba sin API key ──")
respuesta_sin_key = requests.get(url, params=parametros, timeout=30)
print(f"Código sin key: {respuesta_sin_key.status_code}")
print(respuesta_sin_key.text[:200])