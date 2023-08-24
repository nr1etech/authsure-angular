import {Injectable} from '@angular/core';
import {HttpEvent, HttpHandler, HttpInterceptor, HttpRequest} from '@angular/common/http';
import {Observable} from 'rxjs';
import {AuthSureFlowService} from "./auth-sure-flow.service";
import {AuthSureClientConfig} from "./auth-sure-config";

@Injectable()
export class TokenInterceptor implements HttpInterceptor {

  constructor(private auth: AuthSureFlowService, private config: AuthSureClientConfig) { }

  intercept(request: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    const apiBaseUrl = this.config.get().apiBaseUrl;
    // Add AT to all requests to configured API base URL, and to all outgoing requests if API base URL is not configured
    if (!apiBaseUrl || request.url.startsWith(apiBaseUrl)) {
      request = request.clone({
        setHeaders: {
          Authorization: `Bearer ${this.auth.getAccessToken()}`
        }
      });
    }
    return next.handle(request);
  }
}
