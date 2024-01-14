import {Injectable} from '@angular/core';
// TODO This also threw an error when I imported without adding the dependency
import {HttpBackend, HttpClient, HttpErrorResponse} from "@angular/common/http";
import {EMPTY, mergeMap, Observable, of, share} from "rxjs";
import {Router, UrlSerializer} from "@angular/router";
import * as crypto from 'crypto-js';
import * as jose from 'jose';
import {catchError} from 'rxjs/operators';
// TODO This import is problematic for those not using Angular Material. Instead we should provide a way to register a function to show an error message
import {MatSnackBar} from "@angular/material/snack-bar";
import {AuthSureClientConfig} from "./authsure-config";

@Injectable({
  providedIn: 'root'
})
export class AuthSureFlowService {

  private static readonly BASE_SCOPES = ['openid', 'email', 'profile'];
  private static readonly REFRESH_TOKEN_SCOPE = 'offline_access';

  private static readonly ID_TOKEN = 'id_token';
  private static readonly ACCESS_TOKEN = 'access_token';
  private static readonly REFRESH_TOKEN = 'refresh_token';

  private static readonly TOKEN_NONCE_KEY = 'nonce';
  private static readonly TOKEN_NAME_KEY = 'name';
  private static readonly TOKEN_PROVIDER_ID_KEY = 'provider_id';
  private static readonly TOKEN_PROVIDER_LOGIN_HINT_KEY = 'provider_login_hint';

  private static readonly LOCAL_STORAGE_PREFIX = 'authFlow_';
  private static readonly CODE_VERIFIER_KEY = AuthSureFlowService.LOCAL_STORAGE_PREFIX + 'codeVerifier';
  private static readonly STATE_STRING_KEY = AuthSureFlowService.LOCAL_STORAGE_PREFIX + 'stateString';
  private static readonly NONCE_KEY = AuthSureFlowService.LOCAL_STORAGE_PREFIX + 'nonce';
  private static readonly ID_TOKEN_CLAIMS_KEY = AuthSureFlowService.LOCAL_STORAGE_PREFIX + 'idTokenClaims';
  private static readonly REFRESH_TOKEN_KEY = AuthSureFlowService.LOCAL_STORAGE_PREFIX + 'refreshToken';
  private static readonly PROVIDER_ID_KEY = AuthSureFlowService.LOCAL_STORAGE_PREFIX + 'providerId';
  private static readonly PROVIDER_LOGIN_HINT_KEY = AuthSureFlowService.LOCAL_STORAGE_PREFIX + 'providerLoginHint';
  private static readonly NAME_KEY = AuthSureFlowService.LOCAL_STORAGE_PREFIX + 'name';
  private static readonly PREVIOUS_ROUTER_PATH_KEY = AuthSureFlowService.LOCAL_STORAGE_PREFIX + 'previousRouterPath';

  private http: HttpClient;

  private isExchangingCode = false;

  private nonce: string | undefined;

  private codeVerifierChallenge: string | undefined;
  private stateString: string | undefined;
  private authenticatedUsersName?: string;
  private providerId?: string;
  private providerLoginHint?: string;

  private accessToken?: string;
  private accessTokenExpiration: number | undefined;
  private refreshTokenObservable: Observable<any> | undefined;

  constructor(private config: AuthSureClientConfig, private snackBar: MatSnackBar, private router: Router,
              private serializer: UrlSerializer, handler: HttpBackend) {

    this.http = new HttpClient(handler); // Bypass Interceptors on HTTP calls from this Service

    /**
     * Intercept code from querystring params and exchange for tokens
     */
    const restrictedRedirectUri = config.get().redirectUri?.toLowerCase();

    // Use window.location to avoid a subscription and any delay in starting to process the querystring params
    if (window.location && window.location.search &&
      (!restrictedRedirectUri || window.location.href.toLowerCase().startsWith(restrictedRedirectUri))) {
      const params = new URLSearchParams(window.location.search);
      const code = params.get('code');
      const state = params.get('state');
      // Error out if code query param is present, but state is not
      if (code && !state) {
        console.error('No authorization code and/or state received from AuthSure.');
        return;
      }
      // Error out if state query param is present, but code is not
      if (!code && state) {
        console.error('No authorization code and/or state received from AuthSure.');
        return;
      }
      // Only process if both code and state query params are present
      if (code && state) {
        const scopes = params.get('scope') ?? undefined;
        this.isExchangingCode = true;
        this.logout(); // So we don't get user sessions mixed up
        this.exchangeCode(code, state, scopes).subscribe((result: boolean) => {
          if (result) {
            this.isExchangingCode = false;
          } else {
            this.snackBar.open('An error was encountered while processing your sign in. Please try again.', 'OK');
          }
        });
      }
    }
  }

  public initiateAuthFlow(stateString?: string | undefined): void {
    // Don't initiate auth flow if we're currently exchanging codes
    if (this.isExchangingCode) {
      return;
    }

    const authSureConfig = this.config.get();
    let scopes = authSureConfig.scopes;

    if (scopes) {
      // Add any base scopes that are not present
      for (const baseScope of AuthSureFlowService.BASE_SCOPES) {
        if (!scopes.includes(baseScope)) {
          scopes.push(baseScope);
        }
      }
    } else {
      // Add all base scopes
      scopes = AuthSureFlowService.BASE_SCOPES;
    }
    const indexOfRefreshTokenScope = scopes.indexOf(AuthSureFlowService.REFRESH_TOKEN_SCOPE);
    if (authSureConfig.useRefreshTokens ?? true) {
      if (indexOfRefreshTokenScope === -1) {
        scopes.push(AuthSureFlowService.REFRESH_TOKEN_SCOPE);
      }
    } else {
      // Remove offline_access scope if it is present
      if (indexOfRefreshTokenScope > -1) {
        scopes.splice(indexOfRefreshTokenScope, 1);
      }
    }
    this.cleanUpDeprecatedPersistedData();
    if (stateString) {
      this.stateString = stateString;
      this.storePersistedItem(AuthSureFlowService.STATE_STRING_KEY, this.stateString);
    }
    this.generateRandomValues(!stateString);
    const providerId = this.getProviderId();
    const provider = providerId === '' ? undefined : providerId;
    let providerLoginHint = this.getProviderLoginHint();
    providerLoginHint = providerLoginHint === '' ? undefined : providerLoginHint;
    let authFlowBaseUrl;
    let authorizePath;
    authFlowBaseUrl = `https://${authSureConfig.authSureDomain}`;
    authorizePath = ['connect', 'authorize'];
    const tree = this.router.createUrlTree(authorizePath, {
      queryParams: {
        response_type: 'code',
        code_challenge: this.codeVerifierChallenge,
        code_challenge_method: 'S256',
        client_id: authSureConfig.clientId,
        redirect_uri: authSureConfig.redirectUri ?? window.location.origin,
        scope: scopes ? scopes.join(' ') : '',
        state: this.stateString,
        nonce: this.nonce,
        provider: provider,
        login_hint: providerLoginHint,
        prompt: provider ? 'none' : undefined
      }
    });
    const authorizeUri = this.serializer.serialize(tree);
    window.location.href = authFlowBaseUrl + authorizeUri;
  }

  private generateRandomValues(generateStateString = false) {
    this.generateNonce();
    this.generateCodeVerifierAndChallenge();
    if (generateStateString) {
      this.stateString = crypto.lib.WordArray.random(24).toString(crypto.enc.Base64url);
      this.storePersistedItem(AuthSureFlowService.STATE_STRING_KEY, this.stateString);
    }
  }

  private generateCodeVerifierAndChallenge() {
    const codeVerifier = crypto.lib.WordArray.random(24).toString(crypto.enc.Base64url);
    this.storePersistedItem(AuthSureFlowService.CODE_VERIFIER_KEY, codeVerifier);
    if (codeVerifier) {
      this.codeVerifierChallenge = crypto.SHA256(codeVerifier).toString(crypto.enc.Base64url);
    }
  }

  private generateNonce() {
    this.nonce = crypto.lib.WordArray.random(24).toString(crypto.enc.Base64url);
    this.storePersistedItem(AuthSureFlowService.NONCE_KEY, this.nonce);
  }

  public exchangeCode(code: string, stateString: string, scopes?: string): Observable<boolean> {
    if (this.getPersistedItem(AuthSureFlowService.STATE_STRING_KEY) != stateString) {
      console.error('Auth Flow Error: State string from auth callback did not match stored state string.');
      throw Error('Auth Flow Error: State string from auth callback did not match stored state string.');
    }

    const tokenUrl = `https://${this.config.get().authSureDomain}/connect/token`;
    return this.http.post<any>(tokenUrl, {
      grant_type: 'authorization_code',
      client_id: this.config.get().clientId,
      code_verifier: this.getPersistedItem(AuthSureFlowService.CODE_VERIFIER_KEY),
      code,
      scope: scopes
    }, {
      headers: {
        'content-type': 'application/json'
      }
    }).pipe(
      mergeMap(async (tokens: any) => {
        let hadAccessToken = false;
        let hadIdToken = false;
        for (const token in tokens) {
          if (token.endsWith('_token')) {
            const result = await this.validateJwt(token, tokens[token]);
            if (result) {
              if (token === 'id_token') {
                hadIdToken = true;
              } else if (token === 'access_token') {
                hadAccessToken = true;
              }
            } else {
              console.error(`JWT validation failed on ${token} from authorization_code exchange`);
              return false;
            }
          }
        }
        if (!hadIdToken) {
          console.error(`Result from authorization_code exchange did not contain an id_token`);
          return false;
        }
        if (!hadAccessToken) {
          console.error(`Result from authorization_code exchange did not contain an access_token`);
          return false;
        }
        const previousRouterPath = this.getAndClearPreviousRouterPath();
        if (previousRouterPath) {
          this.snackBar.open('Hang on while we redirect you back to where you were...', 'Dismiss', {duration: 2500});
          const previousRouterPathParts = previousRouterPath.split('#');
          const previousUrl = previousRouterPathParts[0];
          await this.router.navigate([previousUrl], {
            fragment: previousRouterPathParts.length > 1 ? previousRouterPathParts[1] : undefined
          });
        } else {
          await this.router.navigate(['manage', 'orgs']);
        }
        return true;
      }),
      catchError((error: HttpErrorResponse) => {
        if (error.error instanceof Error) {
          console.error('An error occurred with code->token exchange:', error.error.message);
          console.error(error);
        } else {
          console.error(`code->token exchange returned code ${error.status}, body was: ${JSON.stringify(error.error)}`);
          console.error(error);
        }
        this.snackBar.open('There was an error signing you in. Please try again.', 'OK');
        return EMPTY;
      })
    );
  }

  public exchangeRefreshToken(): Observable<boolean | undefined> {
    const refreshToken = this.getRefreshToken();
    if (!refreshToken) {
      console.debug('Auth Flow: No refresh token present. Skipping refresh token exchange.');
      return of(false);
    }

    if (!this.refreshTokenObservable) {
      this.snackBar.open('Hang on while we reestablish your session...', 'Dismiss');
      const tokenUrl = `https://${this.config.get().authSureDomain}/connect/token`;
      this.refreshTokenObservable = this.http.post<any>(tokenUrl, {
        grant_type: AuthSureFlowService.REFRESH_TOKEN,
        client_id: this.config.get().clientId,
        refresh_token: refreshToken
      }, {
        headers: {
          'content-type': 'application/json'
        }
      });
      return this.refreshTokenObservable.pipe(
        share(),
        mergeMap(async (tokens: any) => {
          this.refreshTokenObservable = undefined;
          this.snackBar.dismiss();
          let hadAccessToken = false;
          for (const token in tokens) {
            if (token.endsWith('_token')) {
              const result = await this.validateJwt(token, tokens[token]);
              if (result) {
                if (token === 'access_token') {
                  hadAccessToken = true;
                }
              } else {
                console.error(`JWT validation failed on ${token} from refresh_token exchange`);
                return false;
              }
            }
          }
          if (hadAccessToken) {
            return true;
          } else {
            console.error(`Result from refresh_token exchange did not contain a new access_token`);
            return false;
          }
        }),
        catchError((error: HttpErrorResponse) => {
          if (error.error instanceof Error) {
            console.error('An error occurred with refresh_token->token exchange:', error.error.message);
          } else {
            console.error(`refresh_token->token exchange returned code ${error.status}, body was: ${JSON.stringify(error.error)}`);
          }
          return of(false);
        })
      );
    } else {
      return of(undefined);
    }
  }

  public async validateJwt(jwtType: string, jwt: string) {
    if (jwtType === AuthSureFlowService.REFRESH_TOKEN) {
      this.storePersistedItem(AuthSureFlowService.REFRESH_TOKEN_KEY, jwt);
      return true;
    }
    const authSureConfig = this.config.get();
    const jwksUrl = `https://${authSureConfig.authSureDomain}/.well-known/openid-configuration/jwks`;
    const jwks = jose.createRemoteJWKSet(new URL(jwksUrl));
    const {payload, protectedHeader} = await jose.jwtVerify(jwt, jwks, {
      issuer: `https://${authSureConfig.authSureDomain}`,
      audience: jwtType === AuthSureFlowService.ACCESS_TOKEN ? authSureConfig.apiAudience : authSureConfig.clientId,
      clockTolerance: 5
    });
    if (jwtType === AuthSureFlowService.ACCESS_TOKEN) {
      this.accessToken = jwt;
      this.accessTokenExpiration = Number(payload.exp) * 1000;
    }
    if (jwtType === AuthSureFlowService.ID_TOKEN) {
      if (payload) {
        const nonce = this.getNonce();
        if (nonce && payload[AuthSureFlowService.TOKEN_NONCE_KEY] !== nonce) {
          console.error('Nonce mismatch on id_token - auth failed');
          throw new Error('Nonce mismatch on id_token - auth failed');
        }
        this.storePersistedItem(AuthSureFlowService.ID_TOKEN_CLAIMS_KEY, JSON.stringify(payload));
        if (payload[AuthSureFlowService.TOKEN_NAME_KEY]) {
          this.authenticatedUsersName = payload[AuthSureFlowService.TOKEN_NAME_KEY] as string;
          this.storePersistedItem(AuthSureFlowService.NAME_KEY, this.authenticatedUsersName);
        }
        if (payload[AuthSureFlowService.TOKEN_PROVIDER_ID_KEY]) {
          this.providerId = payload[AuthSureFlowService.TOKEN_PROVIDER_ID_KEY] as string;
          this.storePersistedItem(AuthSureFlowService.PROVIDER_ID_KEY, this.providerId);
        }
        if (payload[AuthSureFlowService.TOKEN_PROVIDER_LOGIN_HINT_KEY]) {
          this.providerLoginHint = payload[AuthSureFlowService.TOKEN_PROVIDER_LOGIN_HINT_KEY] as string;
          this.storePersistedItem(AuthSureFlowService.PROVIDER_LOGIN_HINT_KEY, this.providerLoginHint);
        }
      }
    }
    return payload;
  }

  public isAuthenticated(): boolean {
    return this.persistedItemExists(AuthSureFlowService.ID_TOKEN_CLAIMS_KEY);
  }

  public getIdTokenClaims(): any {
    const idTokenClaimsJson = this.getPersistedItem(AuthSureFlowService.ID_TOKEN_CLAIMS_KEY);
    if (idTokenClaimsJson) {
      return JSON.parse(idTokenClaimsJson);
    }
  }

  public getVirtualIdentityId(): string | undefined {
    const idTokenClaims = this.getIdTokenClaims();
    if (idTokenClaims && idTokenClaims.sub) {
      return idTokenClaims.sub;
    }
    return;
  }

  public getAccessToken(): string | undefined {
    return this.accessToken;
  }

  private getRefreshToken(): string | null {
    return this.getPersistedItem(AuthSureFlowService.REFRESH_TOKEN_KEY);
  }

  public getPreviousRouterPath(): string | null {
    return this.getPersistedItem(AuthSureFlowService.PREVIOUS_ROUTER_PATH_KEY);
  }

  public getAndClearPreviousRouterPath(): string | null {
    const previousRouterPath = this.getPersistedItem(AuthSureFlowService.PREVIOUS_ROUTER_PATH_KEY);
    if (previousRouterPath) {
      this.removePersistedItem(AuthSureFlowService.PREVIOUS_ROUTER_PATH_KEY);
    }
    return previousRouterPath;
  }

  private setPreviousRouterPath(value?: string) {
    if (value) {
      return this.storePersistedItem(AuthSureFlowService.PREVIOUS_ROUTER_PATH_KEY, value);
    }
  }

  public logout(preserveProviderId = false, previousRouterPath?: string) {
    this.cleanUpDeprecatedPersistedData();
    this.removePersistedItem(AuthSureFlowService.ID_TOKEN_CLAIMS_KEY);
    this.removePersistedItem(AuthSureFlowService.NAME_KEY);
    this.accessToken = undefined;
    this.removePersistedItem(AuthSureFlowService.REFRESH_TOKEN_KEY);
    this.authenticatedUsersName = undefined;
    if (preserveProviderId) {
      this.setPreviousRouterPath(previousRouterPath);
    } else {
      this.removePersistedItem(AuthSureFlowService.PROVIDER_ID_KEY);
      this.removePersistedItem(AuthSureFlowService.PROVIDER_LOGIN_HINT_KEY);
      this.providerId = undefined;
      this.providerLoginHint = undefined;
    }
  }

  private getNonce(): string | undefined {
    if (!this.nonce) {
      this.nonce = this.getPersistedItem(AuthSureFlowService.NONCE_KEY) ?? undefined;
    }
    return this.nonce;
  }

  public getAuthenticatedUsersName(): string | undefined {
    if (!this.authenticatedUsersName) {
      this.authenticatedUsersName = this.getPersistedItem(AuthSureFlowService.NAME_KEY) ?? undefined;
    }
    return this.authenticatedUsersName;
  }

  public getProviderId(): string | undefined {
    if (!this.providerId) {
      this.providerId = this.getPersistedItem(AuthSureFlowService.PROVIDER_ID_KEY) ?? undefined;
    }
    return this.providerId;
  }

  public getProviderLoginHint(): string | undefined {
    if (!this.providerLoginHint) {
      this.providerLoginHint = this.getPersistedItem(AuthSureFlowService.PROVIDER_LOGIN_HINT_KEY) ?? undefined;
    }
    return this.providerLoginHint;
  }

  private persistedItemExists(key: string) {
    return localStorage.getItem(key) !== null;
  }

  private getPersistedItem(key: string) {
    return localStorage.getItem(key);
  }

  private storePersistedItem(key: string, value: string) {
    localStorage.setItem(key, value);
  }

  private removePersistedItem(key: string) {
    localStorage.removeItem(key);
  }

  private cleanUpDeprecatedPersistedData() {
    if (this.persistedItemExists(AuthSureFlowService.LOCAL_STORAGE_PREFIX + "idToken")) {
      this.removePersistedItem(AuthSureFlowService.LOCAL_STORAGE_PREFIX + "idToken");
    }
    // This is just for backwards compatibility since we're no longer storing this in local storage
    if (this.persistedItemExists(AuthSureFlowService.LOCAL_STORAGE_PREFIX + "accessToken")) {
      this.removePersistedItem(AuthSureFlowService.LOCAL_STORAGE_PREFIX + "accessToken");
    }
  }
}
