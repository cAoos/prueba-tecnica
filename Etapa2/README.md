# Etapa 2 – CVE Manager: Aplicación Full-Stack

**Autor:** Cesar Ospina Muñoz  
**Fecha:** 2026-05-13  
**Rol:** Analista de Metodologías de Riesgo Cibernético y Tecnológico

---

## Links de producción

| Componente | URL |
|------------|-----|
| **Frontend** | https://prueba-tecnica-six-wheat.vercel.app |
| **Backend API** | https://prueba-tecnica-production-f204.up.railway.app |
| **API Docs** | https://prueba-tecnica-production-f204.up.railway.app/docs |

---

## ¿Qué es esto?

Aplicación web completa para gestionar vulnerabilidades catalogadas en **CISA KEV** y **Nuclei**. Permite visualizar, filtrar, crear, editar y eliminar CVEs con una interfaz clara y estructurada para análisis de riesgo.

---

## Stack tecnológico

| Capa | Tecnología | Justificación |
|------|-----------|---------------|
| Frontend | Angular 21 | Requerimiento extra de la prueba |
| Backend | Python + FastAPI | API REST rápida, documentación automática |
| Base de datos | En memoria (CSV) | Prototipo funcional — migración a PostgreSQL planificada |
| Deploy frontend | Vercel | Deploy automático desde GitHub |
| Deploy backend | Railway | Soporte nativo para Python |

---

## Arquitectura

```
┌─────────────────────────────────────────────────────┐
│  Frontend Angular (Vercel)                          │
│  prueba-tecnica-six-wheat.vercel.app                │
└──────────────────────┬──────────────────────────────┘
                       │ HTTP REST
┌──────────────────────▼──────────────────────────────┐
│  Backend FastAPI (Railway)                          │
│  prueba-tecnica-production-f204.up.railway.app      │
│                                                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │
│  │  Router  │→ │ Service  │→ │ Storage (memoria)│  │
│  └──────────┘  └──────────┘  └──────────────────┘  │
│                                      ↑              │
│                               CSV Etapa 1           │
└─────────────────────────────────────────────────────┘
```

---

## Estructura del proyecto

```
Etapa2/
├── backend/
│   ├── main.py                  # Arranque y configuración
│   ├── config.py                # Variables globales
│   ├── Procfile                 # Comando de inicio para Railway
│   ├── requirements.txt
│   ├── data/
│   │   └── vulnerabilidades.csv # Dataset de Etapa 1
│   ├── models/
│   │   └── cve.py               # Esquema Pydantic
│   ├── database/
│   │   └── storage.py           # Almacenamiento en memoria
│   ├── services/
│   │   └── cve_service.py       # Lógica de negocio
│   └── routers/
│       └── cve_router.py        # Endpoints REST
│
└── frontend/
    └── src/
        └── app/
            ├── models/
            │   └── cve.model.ts
            ├── services/
            │   └── cve.ts
            └── components/
                ├── cve-list/    # Tabla principal + filtros
                └── cve-form/    # Formulario CRUD
```

---

## Endpoints de la API

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| GET | `/api/cves` | Listar CVEs (filtros + paginación) |
| GET | `/api/cves/{id}` | Obtener un CVE por ID |
| POST | `/api/cves` | Crear un CVE |
| PUT | `/api/cves/{id}` | Actualizar un CVE |
| DELETE | `/api/cves/{id}` | Eliminar un CVE |
| GET | `/api/cves/stats/resumen` | Estadísticas generales |

### Filtros disponibles en GET /api/cves

| Parámetro | Valores | Ejemplo |
|-----------|---------|---------|
| `severidad` | CRITICAL, HIGH, MEDIUM, LOW | `?severidad=CRITICAL` |
| `fuente` | CISA, NUCLEI, AMBAS | `?fuente=CISA` |
| `buscar` | texto libre | `?buscar=log4j` |
| `pagina` | número | `?pagina=2` |
| `limite` | 1-500 | `?limite=100` |

---

## Características del frontend

- **Tabla paginada** — 50 CVEs por página, 105 páginas para 5.243 CVEs
- **Filtros en tiempo real** — por severidad, fuente y texto libre
- **Badges de severidad** — CRITICAL (rojo), HIGH (naranja), MEDIUM (amarillo), LOW (verde)
- **Chips de fuente** — CISA (negro/amarillo), NUCLEI (amarillo/negro)
- **Stats en tiempo real** — total, por fuente y por severidad en el header
- **CRUD completo** — crear, editar y eliminar desde el frontend
- **Branding Bancolombia** — paleta negro `#1A1A1A` + amarillo `#FFD100`

---

## Cómo correrlo localmente

```bash
# Backend
cd Etapa2/backend
source ../../Etapa1/venv/bin/activate
uvicorn main:app --reload --port 8081

# Frontend (en otra terminal)
cd Etapa2/frontend
ng serve --port 4200
```

---

## Decisiones técnicas

**¿Por qué FastAPI en vez de Java Spring Boot?**
Spring Boot presentó incompatibilidades con el maven-compiler-plugin en el entorno de desarrollo disponible. FastAPI ofrece la misma arquitectura REST con documentación automática (Swagger) y menor tiempo de configuración, permitiendo entregar una solución completa y funcional en el tiempo disponible.

**¿Por qué almacenamiento en memoria?**
El prototipo funcional prioriza demostrar la arquitectura correcta — separación en capas (router → service → storage). La migración a PostgreSQL requiere modificar únicamente `database/storage.py` sin tocar ninguna otra capa, lo que valida el diseño.

**¿Por qué Vercel + Railway?**
Ambas plataformas ofrecen deploy automático desde GitHub, certificado SSL gratuito y dominio público sin configuración adicional. Ideal para una entrega con tiempo limitado.

---

## Próximos pasos

- [ ] Migrar almacenamiento a PostgreSQL en Railway
- [ ] Agregar autenticación JWT
- [ ] Dashboard con gráficas de distribución
- [ ] Exportar resultados filtrados a CSV