export interface Cve {
  cve_id: string;
  fuente?: string;
  fuente_cisa?: boolean;
  fuente_nuclei?: boolean;
  descripcion?: string;
  cvss_v31_base_score?: number;
  cvss_v31_base_severity?: string;
  cvss_v31_vector_string?: string;
  cvss_v31_exploitability_score?: number;
  cvss_v31_impact_score?: number;
  cvss_v2_base_score?: number;
  cvss_v2_base_severity?: string;
  cvss_v2_vector_string?: string;
  cvss_v2_exploitability_score?: number;
  cvss_v2_impact_score?: number;
  cwes?: string;
  cantidad_cpes?: number;
  cpes_muestra?: string;
}

export interface RespuestaPaginada {
  total: number;
  pagina: number;
  limite: number;
  paginas: number;
  datos: Cve[];
}
