import {Inject, Injectable, InjectionToken, Optional} from "@angular/core";

export interface AuthSureConfig {
  /**
   * Your AuthSure domain (e.g. "myorganization.authsure.io")
   */
  readonly authSureDomain: string;
  /**
   * TODO REMOVE ME BEFORE PUBLISHING SDK
   * This is for AuthSure Console use only - DO NOT INCLUDE IN PUBLIC SDK
   */
  readonly authSureInviteDomain?: string; // TODO remove from public SDK
  /**
   * The client_id of the ClientConfig on your AuthSure org. that you are utilizing for this Angular SPA
   */
  readonly clientId: string;
  /**
   * Optional list of scopes to be passed into the OIDC Authorize flow. If you are wanting access to an
   * AuthSure-secured API, you should include the relevant scope(s) for that API here.
   */
  readonly scopes?: string[];
  /**
   * Optional
   *
   * Overrides the default behavior of the authorize flow redirect_uri, which is to use the window.location.origin
   * value. This may be useful when an app needs to handle multiple OAuth 2.0/OIDC authorization flow integrations.
   * Note: you will need to add a valid route to some component in your Angular app that matches this URI path in order
   * for this to work.
   */
  readonly redirectUri?: string;
  /**
   * Optional
   *
   * This is for validating the access_token that we get back from AuthSure - include the audience value you expect back
   * for any access_tokens issued by your AuthSure ClientConfig (e.g. API resource or scope value)
   */
  readonly apiAudience?: string; // TODO we may want this to be an array, but it could work fine to validate on just one expected aud value
  /**
   * Optional
   *
   * This is used by the TokenInterceptor to determine whether to include the access_token from AuthSure on HTTP API
   * calls. If the requested URL matches the configured apiBaseUrl, then the access_token will be attached as a Bearer
   * Token in the HTTP Authorization header. If no apiBaseUrl is configured, then all Angular HTTP requests will include
   * the access_token.
   */
  readonly apiBaseUrl?: string; // TODO this may need to be an array as well, but in the case of multiple APIs, people may just leave this undefined
  /**
   * Optional, defaults to true. Enables Refresh Token exchange logic
   */
  readonly useRefreshTokens?: boolean;
}

export const AuthSureConfigService = new InjectionToken<AuthSureConfig>(
  'authsure-angular.config'
);

@Injectable({providedIn: 'root'})
export class AuthSureClientConfig {
  private config?: AuthSureConfig;

  constructor(@Optional() @Inject(AuthSureConfigService) config?: AuthSureConfig) {
    if (config) {
      this.set(config);
    }
  }

  set(config: AuthSureConfig): void {
    this.config = config;
  }

  get(): AuthSureConfig {
    return this.config as AuthSureConfig;
  }
}
