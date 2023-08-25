# AuthSure Angular SDK

This SDK is used for integrating basic Angular SPA authentication through the AuthSure Authentication Platform.

## Installing

From the root of your Angular project run `npm install @authsure/authsure-angular` to install the SDK.

## Configuring

In the imports section of your `app.module.ts` add the following section:

```
    AuthSureModule.forRoot({
      authSureDomain: '{YOUR_AUTHSURE_ORG_ID}.authsure.io',
      clientId: '{YOUR_AUTHSURE_CLIENT_ID}',
      scopes: ['{YOUR_API_SCOPE_HERE}'],
      apiAudience: '{YOUR_API_SCOPE_OR_RESOURCE_HERE}',
      apiBaseUrl: 'https://{YOUR_API_BASE_URL}',
      useRefreshTokens: true // Optional, default is true
    }),
```

This will configure the basic behavior for a Authorization Code + PKCE flow for your Angular SPA.

To set up which routes should be protected by authentication, add the following to your route(s) (`app-routing.module.ts`):

```
  {
    path: 'some-path-to-secured-resource',
    component: SomeComponentName},
    canActivate: [AuthGuard],
    ...
  }
```

## Options

See the `AuthSureConfig` interface for documentation on the various configuration options for the authentication flow.
