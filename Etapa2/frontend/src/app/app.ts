import { Component } from '@angular/core';
import { CveListComponent } from './components/cve-list/cve-list';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CveListComponent],
  template: '<app-cve-list></app-cve-list>',
})
export class AppComponent {}
