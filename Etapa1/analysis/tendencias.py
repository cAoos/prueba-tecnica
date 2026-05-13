"""
Nombre: analysis/tendencias.py
Autor: Cesar Ospina Muñoz
Fecha: 2026-05-12
Descripción: Análisis de tendencias temporales en vulnerabilidades CVE.

Analiza:
    1. Volumen de CVEs por mes a lo largo del tiempo
       con detección automática de picos significativos
    2. Top meses con más CVEs añadidos a CISA KEV
    3. Tiempo entre publicación en NVD y adición a CISA
       (mide qué tan rápido se confirma la explotación activa)

Un "cambio de tendencia significativo" se define como un mes donde
el volumen de CVEs supera la media histórica en más de 2 desviaciones
estándar — criterio estadístico estándar para detección de anomalías.
"""

import pandas
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from pathlib import Path
from datetime import datetime


# Color base consistente con el resto de visualizaciones
COLOR_LINEA    = "#4C72B0"
COLOR_PICO     = "#D62728"
COLOR_MEDIA    = "#55A868"
COLOR_ZONA     = "#FFBB78"


def generar_todas(lista_cisa, vulnerabilidades, carpeta_output):
    """
    Punto de entrada principal del módulo.

    Parámetros:
        lista_cisa        : list[dict] — datos originales de CISA con dateAdded
        vulnerabilidades  : list[dict] — CVEs enriquecidos con fecha NVD
        carpeta_output    : Path — carpeta donde guardar los PNG y CSV
    """

    carpeta_output.mkdir(exist_ok=True)

    print("  Generando análisis de tendencias...")
    print()

    grafica_volumen_mensual(lista_cisa, carpeta_output)
    grafica_top_meses_cisa(lista_cisa, carpeta_output)
    grafica_tiempo_publicacion_a_cisa(lista_cisa, vulnerabilidades, carpeta_output)

    print()
    print(f"  Análisis de tendencias guardado en: {carpeta_output.resolve()}")
    print()


# ─── Análisis 1: Volumen mensual con detección de picos ───────────────────────

def grafica_volumen_mensual(lista_cisa, carpeta_output):
    """
    Línea temporal que muestra cuántos CVEs se añadieron a CISA
    por mes. Marca automáticamente los meses que superan
    la media + 2 desviaciones estándar como picos significativos.

    ¿Por qué 2 desviaciones estándar?
    En estadística, el 95% de los valores normales caen dentro de
    2 desviaciones de la media. Un mes que las supera es estadísticamente
    anómalo — algo inusual ocurrió en el panorama de amenazas.
    """

    # Extraemos y parseamos las fechas de CISA
    filas = []
    for entrada in lista_cisa:
        date_added = entrada.get("date_added", "")
        if not date_added:
            continue
        try:
            fecha = datetime.strptime(date_added, "%Y-%m-%d")
            filas.append({"fecha": fecha, "cve_id": entrada.get("cve_id", "")})
        except ValueError:
            continue

    if not filas:
        print("  [TENDENCIAS 1] Sin fechas disponibles en CISA.")
        return

    tabla = pandas.DataFrame(filas)
    tabla["mes"] = tabla["fecha"].dt.to_period("M")

    # Contamos CVEs por mes
    conteo_mensual = tabla.groupby("mes")["cve_id"].count().reset_index()
    conteo_mensual.columns = ["mes", "cantidad"]
    conteo_mensual["mes_fecha"] = conteo_mensual["mes"].dt.to_timestamp()

    # Calculamos media y desviación estándar
    media     = conteo_mensual["cantidad"].mean()
    desviacion = conteo_mensual["cantidad"].std()
    umbral_pico = media + (2 * desviacion)

    # Identificamos los meses que son picos significativos
    picos = conteo_mensual[conteo_mensual["cantidad"] >= umbral_pico]

    figura, eje = plt.subplots(figsize=(14, 6))

    # Línea principal de volumen
    eje.plot(
        conteo_mensual["mes_fecha"],
        conteo_mensual["cantidad"],
        color=COLOR_LINEA,
        linewidth=1.5,
        label="CVEs por mes",
    )

    # Zona sombreada entre la línea y el eje X para mejor lectura
    eje.fill_between(
        conteo_mensual["mes_fecha"],
        conteo_mensual["cantidad"],
        alpha=0.15,
        color=COLOR_LINEA,
    )

    # Línea de la media histórica
    eje.axhline(
        y=media,
        color=COLOR_MEDIA,
        linestyle="--",
        linewidth=1.2,
        label=f"Media histórica ({media:.1f} CVEs/mes)",
    )

    # Línea del umbral de pico
    eje.axhline(
        y=umbral_pico,
        color=COLOR_PICO,
        linestyle=":",
        linewidth=1.2,
        label=f"Umbral de pico (media + 2σ = {umbral_pico:.1f})",
    )

    # Marcamos cada pico con un punto rojo y su etiqueta de fecha
    for _, fila in picos.iterrows():
        eje.scatter(
            fila["mes_fecha"],
            fila["cantidad"],
            color=COLOR_PICO,
            zorder=5,
            s=60,
        )
        eje.annotate(
            fila["mes_fecha"].strftime("%b %Y"),
            xy=(fila["mes_fecha"], fila["cantidad"]),
            xytext=(0, 10),
            textcoords="offset points",
            ha="center",
            fontsize=8,
            color=COLOR_PICO,
            fontweight="bold",
        )

    # Formato del eje X con años
    eje.xaxis.set_major_formatter(mdates.DateFormatter("%Y"))
    eje.xaxis.set_major_locator(mdates.YearLocator())
    plt.xticks(rotation=45)

    eje.set_xlabel("Fecha", fontsize=11)
    eje.set_ylabel("CVEs añadidos a CISA", fontsize=11)
    eje.set_title(
        "Volumen mensual de CVEs en CISA KEV con detección de picos",
        fontsize=13,
        fontweight="bold",
    )
    eje.legend(fontsize=9)
    eje.spines["top"].set_visible(False)
    eje.spines["right"].set_visible(False)

    plt.tight_layout()
    ruta = carpeta_output / "tendencia_volumen_mensual.png"
    plt.savefig(ruta, dpi=150, bbox_inches="tight")
    plt.close()

    # Guardamos también el CSV con los picos identificados
    ruta_csv = carpeta_output / "tendencia_picos_significativos.csv"
    picos_exportar = picos.copy()
    picos_exportar["mes"] = picos_exportar["mes"].astype(str)
    picos_exportar = picos_exportar.drop(columns=["mes_fecha"])
    picos_exportar.to_csv(ruta_csv, index=False, encoding="utf-8")

    print(f"  [✓] tendencia_volumen_mensual.png")
    print(f"  [✓] tendencia_picos_significativos.csv")
    print()
    print(f"  Media histórica:     {media:.1f} CVEs/mes")
    print(f"  Umbral de pico:      {umbral_pico:.1f} CVEs/mes")
    print(f"  Picos detectados:    {len(picos)}")
    if not picos.empty:
        print(f"  Meses con pico:")
        for _, fila in picos.iterrows():
            print(f"    {fila['mes']}  →  {int(fila['cantidad'])} CVEs")
    print()


# ─── Análisis 2: Top meses con más CVEs en CISA ───────────────────────────────

def grafica_top_meses_cisa(lista_cisa, carpeta_output):
    """
    Barra horizontal con los 15 meses donde CISA añadió
    más CVEs al catálogo. Estos meses representan momentos
    donde el ecosistema de amenazas estuvo especialmente activo.
    """

    filas = []
    for entrada in lista_cisa:
        date_added = entrada.get("date_added", "")
        if not date_added:
            continue
        try:
            fecha = datetime.strptime(date_added, "%Y-%m-%d")
            filas.append({"fecha": fecha, "cve_id": entrada.get("cve_id", "")})
        except ValueError:
            continue

    if not filas:
        print("  [TENDENCIAS 2] Sin fechas disponibles.")
        return

    tabla = pandas.DataFrame(filas)
    tabla["mes_etiqueta"] = tabla["fecha"].dt.strftime("%b %Y")
    tabla["mes_orden"]    = tabla["fecha"].dt.to_period("M")

    conteo = tabla.groupby(["mes_etiqueta", "mes_orden"])["cve_id"].count().reset_index()
    conteo.columns = ["mes_etiqueta", "mes_orden", "cantidad"]
    conteo = conteo.sort_values("cantidad", ascending=False).head(15)

    # Ordenamos de mayor a menor para la barra horizontal
    conteo = conteo.sort_values("cantidad", ascending=True)

    figura, eje = plt.subplots(figsize=(11, 7))

    barras = eje.barh(
        conteo["mes_etiqueta"],
        conteo["cantidad"],
        color=COLOR_LINEA,
        edgecolor="white",
        linewidth=0.5,
    )

    for barra in barras:
        ancho = barra.get_width()
        eje.text(
            ancho + 0.3,
            barra.get_y() + barra.get_height() / 2,
            str(int(ancho)),
            va="center",
            ha="left",
            fontsize=9,
        )

    eje.set_xlabel("CVEs añadidos a CISA KEV", fontsize=11)
    eje.set_title(
        "Top 15 meses con más CVEs añadidos a CISA KEV",
        fontsize=13,
        fontweight="bold",
    )
    eje.spines["top"].set_visible(False)
    eje.spines["right"].set_visible(False)

    plt.tight_layout()
    ruta = carpeta_output / "tendencia_top_meses_cisa.png"
    plt.savefig(ruta, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  [✓] tendencia_top_meses_cisa.png")


# ─── Análisis 3: Tiempo entre NVD y CISA ──────────────────────────────────────

def grafica_tiempo_publicacion_a_cisa(lista_cisa, vulnerabilidades, carpeta_output):
    """
    Calcula cuántos días pasan entre que el NIST publica un CVE
    y CISA lo añade a su catálogo de explotados activamente.

    Un tiempo corto significa que la vulnerabilidad fue explotada
    muy rápido después de ser conocida públicamente — alta urgencia.
    Un tiempo largo puede indicar que el CVE fue descubierto
    explotado en retrospectiva.

    Genera:
        - Histograma de distribución de tiempos
        - CSV con el detalle por CVE
    """

    # Construimos un mapa CVE ID → fecha de adición a CISA
    mapa_fecha_cisa = {}
    for entrada in lista_cisa:
        cve_id     = entrada.get("cve_id", "")
        date_added = entrada.get("date_added", "")
        if cve_id and date_added:
            try:
                mapa_fecha_cisa[cve_id] = datetime.strptime(date_added, "%Y-%m-%d")
            except ValueError:
                continue

    # Construimos un mapa CVE ID → fecha de publicación en NVD
    mapa_fecha_nvd = {}
    for vuln in vulnerabilidades:
        cve_id = vuln.get("cve_id", "")
        # La fecha de publicación viene dentro del JSON de caché
        # la buscamos en el campo published si está disponible
        fecha_nvd = vuln.get("published", "")
        if cve_id and fecha_nvd:
            try:
                fecha_limpia = fecha_nvd[:10]
                mapa_fecha_nvd[cve_id] = datetime.strptime(fecha_limpia, "%Y-%m-%d")
            except ValueError:
                continue

    # Calculamos la diferencia en días para los CVEs que están en ambos mapas
    filas = []
    for cve_id, fecha_cisa in mapa_fecha_cisa.items():
        if cve_id in mapa_fecha_nvd:
            fecha_nvd = mapa_fecha_nvd[cve_id]
            dias_diferencia = (fecha_cisa - fecha_nvd).days

            # Excluimos diferencias negativas (errores de datos)
            # y diferencias mayores a 10 años (outliers extremos)
            if 0 <= dias_diferencia <= 3650:
                filas.append({
                    "cve_id":         cve_id,
                    "fecha_nvd":      fecha_nvd.strftime("%Y-%m-%d"),
                    "fecha_cisa":     fecha_cisa.strftime("%Y-%m-%d"),
                    "dias_diferencia": dias_diferencia,
                })

    if not filas:
        print("  [TENDENCIAS 3] Sin datos suficientes para calcular tiempos.")
        print("  Nota: se necesitan fechas de publicación NVD en el caché.")
        return

    tabla = pandas.DataFrame(filas)

    # Guardamos el CSV detallado
    ruta_csv = carpeta_output / "tendencia_tiempo_nvd_a_cisa.csv"
    tabla.sort_values("dias_diferencia").to_csv(ruta_csv, index=False, encoding="utf-8")

    # Estadísticas
    mediana  = tabla["dias_diferencia"].median()
    promedio = tabla["dias_diferencia"].mean()
    minimo   = tabla["dias_diferencia"].min()
    maximo   = tabla["dias_diferencia"].max()

    # CVEs explotados en menos de 7 días (explotación ultrarrápida)
    ultra_rapidos = len(tabla[tabla["dias_diferencia"] <= 7])

    # Histograma de distribución
    figura, eje = plt.subplots(figsize=(12, 6))

    # Dividimos en rangos significativos
    rangos = [0, 7, 30, 90, 365, 730, 1825, 3650]
    etiquetas_rangos = [
        "0–7 días\n(ultrarrápido)",
        "8–30 días\n(1 mes)",
        "31–90 días\n(3 meses)",
        "91–365 días\n(1 año)",
        "1–2 años",
        "2–5 años",
        "5–10 años",
    ]

    conteos_rangos = []
    for i in range(len(rangos) - 1):
        cantidad = len(tabla[
            (tabla["dias_diferencia"] >= rangos[i]) &
            (tabla["dias_diferencia"] < rangos[i + 1])
        ])
        conteos_rangos.append(cantidad)

    colores_barras = [COLOR_PICO if i == 0 else COLOR_LINEA for i in range(len(conteos_rangos))]

    barras = eje.bar(
        etiquetas_rangos,
        conteos_rangos,
        color=colores_barras,
        edgecolor="white",
        linewidth=0.5,
    )

    for barra in barras:
        altura = barra.get_height()
        if altura > 0:
            eje.text(
                barra.get_x() + barra.get_width() / 2,
                altura + 0.5,
                str(int(altura)),
                ha="center",
                va="bottom",
                fontsize=9,
            )

    eje.set_ylabel("Cantidad de CVEs", fontsize=11)
    eje.set_xlabel("Tiempo entre publicación NVD y adición a CISA", fontsize=11)
    eje.set_title(
        "¿Cuánto tarda una vulnerabilidad en ser confirmada como explotada?",
        fontsize=13,
        fontweight="bold",
    )
    eje.spines["top"].set_visible(False)
    eje.spines["right"].set_visible(False)

    # Nota con estadísticas clave
    nota = (
        f"Mediana: {int(mediana)} días  |  "
        f"Promedio: {int(promedio)} días  |  "
        f"Mín: {int(minimo)} días  |  "
        f"Máx: {int(maximo)} días\n"
        f"CVEs explotados en ≤7 días: {ultra_rapidos} ({ultra_rapidos/len(tabla)*100:.1f}%)"
    )
    eje.text(
        0.98, 0.95,
        nota,
        transform=eje.transAxes,
        ha="right",
        va="top",
        fontsize=8.5,
        color="#444444",
        bbox=dict(boxstyle="round,pad=0.4", facecolor="#F5F5F5", edgecolor="#CCCCCC"),
    )

    plt.tight_layout()
    ruta = carpeta_output / "tendencia_tiempo_nvd_a_cisa.png"
    plt.savefig(ruta, dpi=150, bbox_inches="tight")
    plt.close()

    print(f"  [✓] tendencia_tiempo_nvd_a_cisa.png")
    print(f"  [✓] tendencia_tiempo_nvd_a_cisa.csv")
    print()
    print(f"  CVEs analizados:              {len(tabla)}")
    print(f"  Mediana de días NVD → CISA:   {int(mediana)} días")
    print(f"  Promedio de días NVD → CISA:  {int(promedio)} días")
    print(f"  Explotados en ≤7 días:        {ultra_rapidos} ({ultra_rapidos/len(tabla)*100:.1f}%)")
    print()