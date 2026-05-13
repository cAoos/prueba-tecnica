"""
Nombre: analysis/visualizaciones.py
Autor: Cesar Ospina Muñoz
Fecha: 2026-05-12
Descripción: Genera gráficas a partir del dataset de vulnerabilidades.

Gráficas que genera:
    1. Top 15 plataformas más afectadas (CPE)
    2. Top 10 CWEs más frecuentes
    3. Distribución de severidad CRITICAL / HIGH / MEDIUM / LOW
    4. Score promedio por CWE (barras)
    5. CVEs por fuente: CISA vs Nuclei vs Ambas

Todos los archivos se guardan en la carpeta output/ como PNG.
"""

import pandas
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from pathlib import Path


# Colores por severidad — consistentes en todas las gráficas
COLORES_SEVERIDAD = {
    "CRITICAL": "#D62728",
    "HIGH":     "#FF7F0E",
    "MEDIUM":   "#FFBB78",
    "LOW":      "#2CA02C",
    "":         "#AAAAAA",
}

# Color base para barras sin semántica de severidad
COLOR_PRINCIPAL = "#4C72B0"
COLOR_SECUNDARIO = "#DD8452"


def generar_todas(vulnerabilidades, carpeta_output):
    """
    Punto de entrada principal. Genera todas las gráficas
    y las guarda como PNG en la carpeta output/.

    Parámetros:
        vulnerabilidades : list[dict] — lista de CVEs enriquecidos
        carpeta_output   : Path — carpeta donde guardar los PNG
    """

    carpeta_output.mkdir(exist_ok=True)

    print("  Generando gráficas...")

    grafica_top_plataformas_cpe(vulnerabilidades, carpeta_output)
    grafica_top_cwes_frecuentes(vulnerabilidades, carpeta_output)
    grafica_distribucion_severidad(vulnerabilidades, carpeta_output)
    grafica_score_promedio_por_cwe(vulnerabilidades, carpeta_output)
    grafica_cves_por_fuente(vulnerabilidades, carpeta_output)

    print()
    print(f"  Gráficas guardadas en: {carpeta_output.resolve()}")
    print()


# ─── Gráfica 1: Top 15 plataformas más afectadas ──────────────────────────────

def grafica_top_plataformas_cpe(vulnerabilidades, carpeta_output):
    """
    Barra horizontal con las 15 plataformas que aparecen
    en más CVEs distintos, coloreadas por tipo (App / OS / Hardware).
    """

    tipos_cpe = {
        "a": "Aplicación",
        "o": "Sistema Operativo",
        "h": "Hardware",
    }

    colores_tipo = {
        "Aplicación":       "#4C72B0",
        "Sistema Operativo": "#DD8452",
        "Hardware":          "#55A868",
        "Desconocido":       "#AAAAAA",
    }

    filas = []
    for vuln in vulnerabilidades:
        cve_id = vuln.get("cve_id", "")
        for cpe_string in vuln.get("cpes", []):
            if not cpe_string.startswith("cpe:"):
                continue
            partes = cpe_string.split(":")
            if len(partes) < 6:
                continue
            tipo_codigo = partes[2]
            vendor      = partes[3]
            producto    = partes[4]
            if vendor == "*" or producto == "*":
                continue
            filas.append({
                "cve_id":   cve_id,
                "tipo":     tipos_cpe.get(tipo_codigo, "Desconocido"),
                "etiqueta": f"{vendor} / {producto}",
            })

    if not filas:
        print("  [GRÁFICA 1] Sin datos CPE disponibles.")
        return

    tabla = pandas.DataFrame(filas)

    ranking = tabla.groupby(["etiqueta", "tipo"]).agg(
        cantidad=("cve_id", "nunique")
    ).reset_index().sort_values("cantidad", ascending=False).head(15)

    colores_barras = [colores_tipo.get(t, "#AAAAAA") for t in ranking["tipo"]]

    figura, eje = plt.subplots(figsize=(12, 7))

    barras = eje.barh(
        ranking["etiqueta"],
        ranking["cantidad"],
        color=colores_barras,
        edgecolor="white",
        linewidth=0.5,
    )

    # Etiquetas de valor al final de cada barra
    for barra in barras:
        ancho = barra.get_width()
        eje.text(
            ancho + 0.5,
            barra.get_y() + barra.get_height() / 2,
            str(int(ancho)),
            va="center",
            ha="left",
            fontsize=9,
        )

    # Leyenda de tipos
    parches_leyenda = [
        mpatches.Patch(color=color, label=tipo)
        for tipo, color in colores_tipo.items()
        if tipo != "Desconocido"
    ]
    eje.legend(handles=parches_leyenda, loc="lower right", fontsize=9)

    eje.invert_yaxis()
    eje.set_xlabel("Cantidad de CVEs únicos", fontsize=11)
    eje.set_title("Top 15 plataformas más afectadas por CVEs", fontsize=13, fontweight="bold")
    eje.spines["top"].set_visible(False)
    eje.spines["right"].set_visible(False)

    plt.tight_layout()
    ruta = carpeta_output / "grafica_top_plataformas_cpe.png"
    plt.savefig(ruta, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  [✓] grafica_top_plataformas_cpe.png")


# ─── Gráfica 2: Top 10 CWEs más frecuentes ────────────────────────────────────

def grafica_top_cwes_frecuentes(vulnerabilidades, carpeta_output):
    """
    Barra vertical con los 10 CWEs que aparecen en más CVEs.
    Excluye los placeholders del NIST (SIN_CWE, NVD-CWE-*).
    """

    filas = []
    for vuln in vulnerabilidades:
        cve_id = vuln.get("cve_id", "")
        for cwe in vuln.get("cwes", []):
            if cwe.startswith("NVD-CWE") or cwe == "SIN_CWE":
                continue
            filas.append({"cve_id": cve_id, "cwe": cwe})

    if not filas:
        print("  [GRÁFICA 2] Sin datos CWE disponibles.")
        return

    tabla = pandas.DataFrame(filas)
    conteo = tabla.groupby("cwe")["cve_id"].nunique().sort_values(ascending=False).head(10)

    figura, eje = plt.subplots(figsize=(11, 6))

    barras = eje.bar(
        conteo.index,
        conteo.values,
        color=COLOR_PRINCIPAL,
        edgecolor="white",
        linewidth=0.5,
    )

    for barra in barras:
        altura = barra.get_height()
        eje.text(
            barra.get_x() + barra.get_width() / 2,
            altura + 1,
            str(int(altura)),
            ha="center",
            va="bottom",
            fontsize=9,
        )

    eje.set_ylabel("Cantidad de CVEs únicos", fontsize=11)
    eje.set_xlabel("CWE", fontsize=11)
    eje.set_title("Top 10 CWEs más frecuentes", fontsize=13, fontweight="bold")
    eje.spines["top"].set_visible(False)
    eje.spines["right"].set_visible(False)
    plt.xticks(rotation=30, ha="right")

    plt.tight_layout()
    ruta = carpeta_output / "grafica_top_cwes_frecuentes.png"
    plt.savefig(ruta, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  [✓] grafica_top_cwes_frecuentes.png")


# ─── Gráfica 3: Distribución de severidad ─────────────────────────────────────

def grafica_distribucion_severidad(vulnerabilidades, carpeta_output):
    """
    Dona (donut chart) con la distribución de severidad v3.1.
    Si no hay v3.1 usa v2.
    """

    conteo_severidad = {
        "CRITICAL": 0,
        "HIGH":     0,
        "MEDIUM":   0,
        "LOW":      0,
    }

    for vuln in vulnerabilidades:
        severidad = vuln.get("cvss_v31_base_severity", "")

        if not severidad:
            severidad = vuln.get("cvss_v2_base_severity", "")

        if severidad in conteo_severidad:
            conteo_severidad[severidad] = conteo_severidad[severidad] + 1

    # Quitamos categorías con cero
    etiquetas = []
    valores = []
    colores = []

    colores_dona = {
        "CRITICAL":  "#D62728",
        "HIGH":      "#FF7F0E",
        "MEDIUM":    "#FFBB78",
        "LOW":       "#2CA02C",
    }

    for categoria, valor in conteo_severidad.items():
        if valor > 0:
            etiquetas.append(categoria)
            valores.append(valor)
            colores.append(colores_dona[categoria])

    figura, eje = plt.subplots(figsize=(8, 7))

    wedges, textos, autotextos = eje.pie(
        valores,
        labels=etiquetas,
        colors=colores,
        autopct="%1.1f%%",
        startangle=90,
        wedgeprops={"width": 0.5, "edgecolor": "white", "linewidth": 2},
        pctdistance=0.75,
    )

    for texto in autotextos:
        texto.set_fontsize(10)
        texto.set_fontweight("bold")

    eje.set_title(
        "Distribución de severidad (CVSS v3.1 / v2)",
        fontsize=13,
        fontweight="bold",
        pad=20,
    )

    # Total en el centro de la dona
    total = sum(valores)
    eje.text(0, 0, f"{total}\nCVEs", ha="center", va="center", fontsize=13, fontweight="bold")

    plt.tight_layout()
    ruta = carpeta_output / "grafica_distribucion_severidad.png"
    plt.savefig(ruta, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  [✓] grafica_distribucion_severidad.png")


# ─── Gráfica 4: Score promedio por CWE ────────────────────────────────────────

def grafica_score_promedio_por_cwe(vulnerabilidades, carpeta_output):
    """
    Barra horizontal mostrando el score CVSS v3.1 promedio
    para los 12 CWEs más frecuentes. Coloreada por nivel de riesgo.
    """

    filas = []
    for vuln in vulnerabilidades:
        score = vuln.get("cvss_v31_base_score")
        if score is None:
            score = vuln.get("cvss_v2_base_score")
        if score is None:
            continue

        for cwe in vuln.get("cwes", []):
            if cwe.startswith("NVD-CWE") or cwe == "SIN_CWE":
                continue
            filas.append({"cwe": cwe, "score": float(score)})

    if not filas:
        print("  [GRÁFICA 4] Sin datos suficientes.")
        return

    tabla = pandas.DataFrame(filas)

    # Tomamos los 12 CWEs con más apariciones
    top_cwes = tabla["cwe"].value_counts().head(12).index.tolist()
    tabla_filtrada = tabla[tabla["cwe"].isin(top_cwes)]

    promedios = tabla_filtrada.groupby("cwe")["score"].mean().sort_values(ascending=True)

    def color_por_score(score):
        if score >= 9.0:
            return COLORES_SEVERIDAD["CRITICAL"]
        if score >= 7.0:
            return COLORES_SEVERIDAD["HIGH"]
        if score >= 4.0:
            return COLORES_SEVERIDAD["MEDIUM"]
        return COLORES_SEVERIDAD["LOW"]

    colores_barras = [color_por_score(s) for s in promedios.values]

    figura, eje = plt.subplots(figsize=(11, 7))

    barras = eje.barh(
        promedios.index,
        promedios.values,
        color=colores_barras,
        edgecolor="white",
        linewidth=0.5,
    )

    for barra in barras:
        ancho = barra.get_width()
        eje.text(
            ancho + 0.05,
            barra.get_y() + barra.get_height() / 2,
            f"{ancho:.2f}",
            va="center",
            ha="left",
            fontsize=9,
        )

    # Línea de referencia en 7.0 (umbral HIGH)
    eje.axvline(x=7.0, color="gray", linestyle="--", linewidth=1, alpha=0.6, label="Umbral HIGH (7.0)")
    eje.axvline(x=9.0, color="#D62728", linestyle="--", linewidth=1, alpha=0.6, label="Umbral CRITICAL (9.0)")

    eje.set_xlim(0, 10.5)
    eje.set_xlabel("Score CVSS promedio", fontsize=11)
    eje.set_title("Score promedio por CWE (top 12 más frecuentes)", fontsize=13, fontweight="bold")
    eje.legend(fontsize=9)
    eje.spines["top"].set_visible(False)
    eje.spines["right"].set_visible(False)

    plt.tight_layout()
    ruta = carpeta_output / "grafica_score_promedio_cwe.png"
    plt.savefig(ruta, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  [✓] grafica_score_promedio_cwe.png")


# ─── Gráfica 5: CVEs por fuente ───────────────────────────────────────────────

def grafica_cves_por_fuente(vulnerabilidades, carpeta_output):
    """
    Barra vertical mostrando cuántos CVEs vienen solo de CISA,
    solo de Nuclei, y de ambas fuentes simultáneamente.
    """

    solo_cisa   = 0
    solo_nuclei = 0
    en_ambas    = 0

    for vuln in vulnerabilidades:
        en_cisa   = vuln.get("fuente_cisa", False)
        en_nuclei = vuln.get("fuente_nuclei", False)

        if en_cisa and en_nuclei:
            en_ambas = en_ambas + 1
        elif en_cisa:
            solo_cisa = solo_cisa + 1
        elif en_nuclei:
            solo_nuclei = solo_nuclei + 1

    etiquetas = ["Solo CISA", "Solo Nuclei", "Ambas fuentes"]
    valores   = [solo_cisa, solo_nuclei, en_ambas]
    colores   = ["#4C72B0", "#DD8452", "#55A868"]

    figura, eje = plt.subplots(figsize=(8, 6))

    barras = eje.bar(
        etiquetas,
        valores,
        color=colores,
        edgecolor="white",
        linewidth=0.5,
        width=0.5,
    )

    for barra in barras:
        altura = barra.get_height()
        eje.text(
            barra.get_x() + barra.get_width() / 2,
            altura + 10,
            f"{int(altura):,}",
            ha="center",
            va="bottom",
            fontsize=11,
            fontweight="bold",
        )

    total = sum(valores)
    eje.set_ylim(0, max(valores) * 1.15)
    eje.set_ylabel("Cantidad de CVEs", fontsize=11)
    eje.set_title(
        f"CVEs por fuente de origen (total: {total:,})",
        fontsize=13,
        fontweight="bold",
    )
    eje.spines["top"].set_visible(False)
    eje.spines["right"].set_visible(False)

    plt.tight_layout()
    ruta = carpeta_output / "grafica_cves_por_fuente.png"
    plt.savefig(ruta, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  [✓] grafica_cves_por_fuente.png")