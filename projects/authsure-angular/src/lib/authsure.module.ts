import {ModuleWithProviders, NgModule} from '@angular/core';
import {AuthSureFlowService} from "./authsure-flow.service";
import {AuthGuard} from "./auth.guard";
import {AuthSureConfig, AuthSureConfigService} from "./authsure-config";
import {HTTP_INTERCEPTORS} from "@angular/common/http";
import {TokenInterceptor} from "./token.interceptor";
import {HttpErrorInterceptor} from "./http-error.interceptor";


@NgModule()
export class AuthSureModule {
  static forRoot(config?: AuthSureConfig): ModuleWithProviders<AuthSureModule> {
    return {
      ngModule: AuthSureModule,
      providers: [
        AuthGuard,
        {
          provide: HTTP_INTERCEPTORS,
          useClass: TokenInterceptor,
          multi: true
        },
        {
          provide: HTTP_INTERCEPTORS,
          useClass: HttpErrorInterceptor,
          multi: true
        },
        {
          provide: AuthSureConfigService,
          useValue: config,
        },
        AuthSureFlowService
      ],
    };
  }
}
