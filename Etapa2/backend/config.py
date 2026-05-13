from pathlib import Path

# En producción el CSV está en data/ dentro del proyecto
# En local busca primero ahí, luego en Etapa1/output/
RUTA_CSV_LOCAL = Path(__file__).parent / "data" / "vulnerabilidades.csv"
RUTA_CSV_ETAPA1 = (
    Path.home()
    / "Documentos" / "Bancolombia" / "Repo"
    / "Etapa1" / "output" / "vulnerabilidades.csv"
)

RUTA_CSV = RUTA_CSV_LOCAL if RUTA_CSV_LOCAL.exists() else RUTA_CSV_ETAPA1

PUERTO = 8080
ORIGENES_PERMITIDOS = ["*"]
