import { Injectable } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';
import { Cve, RespuestaPaginada } from '../models/cve.model';

@Injectable({
  providedIn: 'root'
})
export class CveService {

  private readonly apiUrl = 'http://localhost:8081/api/cves';

  constructor(private http: HttpClient) {}

  listar(filtros: {
    severidad?: string;
    fuente?: string;
    buscar?: string;
    pagina?: number;
    limite?: number;
  }): Observable<RespuestaPaginada> {
    let params = new HttpParams();
    if (filtros.severidad) params = params.set('severidad', filtros.severidad);
    if (filtros.fuente)    params = params.set('fuente', filtros.fuente);
    if (filtros.buscar)    params = params.set('buscar', filtros.buscar);
    if (filtros.pagina)    params = params.set('pagina', filtros.pagina.toString());
    if (filtros.limite)    params = params.set('limite', filtros.limite.toString());
    return this.http.get<RespuestaPaginada>(this.apiUrl, { params });
  }

  obtener(cveId: string): Observable<Cve> {
    return this.http.get<Cve>(`${this.apiUrl}/${cveId}`);
  }

  crear(cve: Cve): Observable<Cve> {
    return this.http.post<Cve>(this.apiUrl, cve);
  }

  actualizar(cveId: string, cve: Cve): Observable<Cve> {
    return this.http.put<Cve>(`${this.apiUrl}/${cveId}`, cve);
  }

  eliminar(cveId: string): Observable<void> {
    return this.http.delete<void>(`${this.apiUrl}/${cveId}`);
  }

  estadisticas(): Observable<any> {
    return this.http.get<any>(`${this.apiUrl}/stats/resumen`);
  }
}
