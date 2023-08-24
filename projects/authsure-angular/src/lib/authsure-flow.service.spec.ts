import {TestBed} from '@angular/core/testing';

import {AuthSureFlowService} from './authsure-flow.service';

describe('AuthSureFlowService', () => {
  let service: AuthSureFlowService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(AuthSureFlowService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
