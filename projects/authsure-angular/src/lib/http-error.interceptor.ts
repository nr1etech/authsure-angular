import {Injectable} from '@angular/core';
import {HttpErrorResponse, HttpEvent, HttpHandler, HttpInterceptor, HttpRequest} from '@angular/common/http';
import {EMPTY, Observable, switchMap, throwError} from 'rxjs';
import {catchError} from "rxjs/operators";
import {MatSnackBar} from "@angular/material/snack-bar";
import {Router} from "@angular/router";
import {AuthSureFlowService} from "./authsure-flow.service";

@Injectable()
export class HttpErrorInterceptor implements HttpInterceptor {

  private alreadyLoggedOut = false;

  constructor(private snackBar: MatSnackBar, private auth: AuthSureFlowService, private router: Router) {
  }

  intercept(request: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    return next.handle(request)
      .pipe(
        catchError((error: HttpErrorResponse) => {
          if (error.error instanceof ErrorEvent) {
            console.error(`HTTP Client Error: ${error.error.message}`);
          } else {
            console.error(`HTTP Error Code: ${error.status},  Message: ${error.message}`);
            // TODO check just for 401 once there's a CORS fix on AWS JWT Authorizer
            // TODO figure out if we can do better error handling when CloudFront times out (504 err)
            if (error.status === 401 || error.status === 0) { // NOTE: 0 is good enough for now as this only happens on JWT Authorizer failure
              // Try exchanging refresh token first
              return this.auth.exchangeRefreshToken().pipe(switchMap((result: boolean | undefined) => {
                if (result) {
                  return this.notifyOrReloadCurrentRoute(request, next);
                } else if (result === false) { // We should do nothing on undefined
                  return this.logoutAndLoginAgain();
                }
                return EMPTY;
              }));
            } else if (error.status === 403) {
              this.snackBar.open('Access was denied to the resource. Please try again.', 'OK', {duration: undefined});
            } else if (error.status === 404) {
              this.snackBar.open('Resource could not be found. Please try again.', 'OK', {duration: undefined});
            } else if (error.status === 500) {
              this.snackBar.open('System error occurred. Please try again.', 'OK', {duration: undefined});
            }
          }
          return throwError(error);
        })
      )
  }

  private notifyOrReloadCurrentRoute(request: HttpRequest<any>, next: HttpHandler): Observable<any> {
    if (request.method === 'POST' || request.method === 'PUT' || request.method === 'DELETE'
      || request.method === 'PATCH') {
      // Retry POST/PUT/PATCH/DELETE requests
      request = request.clone({
        setHeaders: {
          Authorization: `Bearer ${this.auth.getAccessToken()}`
        }
      });
      return next.handle(request);
    } else {
      // Reload route for other HTTP methods
      const routerUrlParts = this.router.url.split('#');
      const currentUrl = routerUrlParts[0];
      this.router.navigateByUrl('/', {skipLocationChange: true}).then(() => {
        this.router.navigate([currentUrl], {
          fragment: routerUrlParts.length > 1 ? routerUrlParts[1] : undefined
        }).then();
      });
    }
    return EMPTY;
  }

  private logoutAndLoginAgain() {
    if (!this.alreadyLoggedOut) {
      this.alreadyLoggedOut = true;
      this.snackBar.open('Your session has timed out. Sending you to sign in again.', '', {duration: undefined});
      this.auth.logout(true, this.router.url);
      this.auth.initiateAuthFlow();
    }
    return EMPTY;
  }
}
