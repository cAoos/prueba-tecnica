import { TestBed } from '@angular/core/testing';

import { Cve } from './cve';

describe('Cve', () => {
  let service: Cve;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(Cve);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
