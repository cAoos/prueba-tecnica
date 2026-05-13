# Etapa 2 – CVE Manager: Aplicación Full-Stack

**Autor:** Cesar Ospina Muñoz  
**Fecha:** 2026-05-13  
**Rol:** Analista de Metodologías de Riesgo Cibernético y Tecnológico

---

## Links de producción

| Componente      | URL                                                        |
| --------------- | ---------------------------------------------------------- |
| **Frontend**    | https://prueba-tecnica-six-wheat.vercel.app                |
| **Backend API** | https://prueba-tecnica-production-f204.up.railway.app      |
| **API Docs**    | https://prueba-tecnica-production-f204.up.railway.app/docs |

---

## ¿Qué es?

Aplicación web completa para gestionar vulnerabilidades catalogadas en **CISA KEV** y **Nuclei**. Permite visualizar, filtrar, crear, editar y eliminar CVEs con una interfaz clara y estructurada para análisis de riesgo cibernético.

Los datos provienen del pipeline de la Etapa 1 — 5.243 CVEs enriquecidos con métricas CVSS v3.1 y v2, CWEs y CPEs desde la API del NIST.

---

## Stack tecnológico

| Capa            | Tecnología       | Justificación                                 |
| --------------- | ---------------- | --------------------------------------------- |
| Frontend        | Angular 21       | Requerimiento extra de la prueba              |
| Backend         | Python + FastAPI | API REST con documentación automática Swagger |
| Base de datos   | PostgreSQL       | Persistencia real en producción               |
| ORM / Queries   | SQLAlchemy       | Abstracción de base de datos                  |
| Deploy frontend | Vercel           | Deploy automático desde GitHub                |
| Deploy backend  | Railway          | Soporte nativo Python + PostgreSQL integrado  |


---

## Estructura del proyecto

```
Etapa2/
├── backend/
│   ├── main.py                  # Arranque + configuración CORS
│   ├── config.py                # Variables globales y rutas
│   ├── Procfile                 # Comando de inicio para Railway
│   ├── requirements.txt         # Dependencias Python
│   ├── data/
│   │   └── vulnerabilidades.csv # Dataset generado en Etapa 1
│   ├── models/
│   │   └── cve.py               # Esquema Pydantic (validación)
│   ├── database/
│   │   └── storage.py           # PostgreSQL + SQLAlchemy + fallback memoria
│   ├── services/
│   │   └── cve_service.py       # Lógica de negocio (filtros, paginación)
│   └── routers/
│       └── cve_router.py        # Endpoints REST
│
└── frontend/
    └── src/
        └── app/
            ├── models/
            │   └── cve.model.ts          # Interfaces TypeScript
            ├── services/
            │   └── cve.ts                # Cliente HTTP Angular
            └── components/
                ├── cve-list/             # Tabla principal + filtros + stats
                └── cve-form/             # Formulario crear / editar
```

---

## Endpoints de la API

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| GET | `/api/cves` | Listar CVEs con filtros y paginación |
| GET | `/api/cves/{id}` | Obtener un CVE por ID |
| POST | `/api/cves` | Crear un CVE nuevo |
| PUT | `/api/cves/{id}` | Actualizar un CVE existente |
| DELETE | `/api/cves/{id}` | Eliminar un CVE |
| GET | `/api/cves/stats/resumen` | Estadísticas generales del dataset |

### Filtros disponibles en GET /api/cves

| Parámetro | Valores posibles | Ejemplo |
|-----------|-----------------|---------|
| `severidad` | CRITICAL, HIGH, MEDIUM, LOW | `?severidad=CRITICAL` |
| `fuente` | CISA, NUCLEI, AMBAS | `?fuente=CISA` |
| `buscar` | texto libre | `?buscar=log4j` |
| `pagina` | número entero ≥ 1 | `?pagina=2` |
| `limite` | 1 – 500 | `?limite=100` |

---

## Base de datos

**Motor:** PostgreSQL 15 en Railway  
**Tabla principal:** `cves`

| Columna | Tipo | Descripción |
|---------|------|-------------|
| `cve_id` | VARCHAR(50) PK | Identificador único |
| `fuente` | VARCHAR(20) | CISA / NUCLEI / CISA + NUCLEI |
| `fuente_cisa` | BOOLEAN | Presencia en CISA KEV |
| `fuente_nuclei` | BOOLEAN | Presencia en Nuclei |
| `descripcion` | TEXT | Descripción oficial NVD |
| `cvss_v31_base_score` | FLOAT | Score CVSS v3.1 |
| `cvss_v31_base_severity` | VARCHAR(20) | CRITICAL / HIGH / MEDIUM / LOW |
| `cvss_v31_vector_string` | VARCHAR(200) | Vector de ataque v3.1 |
| `cvss_v31_exploitability_score` | FLOAT | Explotabilidad v3.1 |
| `cvss_v31_impact_score` | FLOAT | Impacto v3.1 |
| `cvss_v2_base_score` | FLOAT | Score CVSS v2 |
| `cvss_v2_base_severity` | VARCHAR(20) | HIGH / MEDIUM / LOW |
| `cvss_v2_vector_string` | VARCHAR(200) | Vector de ataque v2 |
| `cvss_v2_exploitability_score` | FLOAT | Explotabilidad v2 |
| `cvss_v2_impact_score` | FLOAT | Impacto v2 |
| `cwes` | TEXT | Debilidades CWE asociadas |
| `cantidad_cpes` | INTEGER | Número de plataformas afectadas |
| `cpes_muestra` | TEXT | Muestra de CPEs afectados |

**Registros cargados:** 5.243 CVEs

---

## Características del frontend

- **Tabla paginada** — 50 CVEs por página, navegación entre 105 páginas
- **Filtros combinables** — severidad, fuente y búsqueda de texto libre
- **Badges de severidad** — CRITICAL (rojo), HIGH (naranja), MEDIUM (amarillo), LOW (verde)
- **Chips de fuente** — CISA (negro/amarillo), NUCLEI (amarillo/negro)
- **Stats en tiempo real** — total de CVEs, distribución por fuente y severidad
- **CRUD completo** — crear, editar y eliminar desde el frontend
- **Branding Bancolombia** — paleta negro `#1A1A1A` + amarillo `#FFD100`

---

## Cómo correrlo localmente

```bash
# 1. Activar entorno virtual
source ~/Documentos/Bancolombia/Repo/Etapa1/venv/bin/activate

# 2. Backend
cd Etapa2/backend
uvicorn main:app --reload --port 8081

# 3. Frontend (en otra terminal)
cd Etapa2/frontend
ng serve --port 4200
```

La app estará disponible en `http://localhost:4200`.  
La API en `http://localhost:8081/docs`.

