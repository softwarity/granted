# @softwarity/nestjs-granted

[![npm version](https://img.shields.io/npm/v/@softwarity/nestjs-granted.svg)](https://www.npmjs.com/package/@softwarity/nestjs-granted)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-yellow.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![Node](https://img.shields.io/node/v/@softwarity/nestjs-granted.svg)](https://nodejs.org)
[![Unit tests](https://github.com/softwarity/nestjs-granted/actions/workflows/unit-tests.yml/badge.svg)](https://github.com/softwarity/nestjs-granted/actions/workflows/unit-tests.yml)

**RBAC security for NestJS endpoints.** Declarative, decorator-based authorization built on a small algebra of composable boolean specifications — and a pluggable provider that reads the current user from HTTP headers or from a verified JWT.

📚 **Full documentation:** [softwarity.github.io/nestjs-granted](https://softwarity.github.io/nestjs-granted/)

---

## Why?

You have endpoints behind an API gateway (or an OAuth2 proxy) that already authenticated the caller and forwards the identity — either as plain headers (`username`, `roles`) or as a `Bearer` JWT. You don't want another auth stack; you just want to **declare, per route, who is allowed in** and **inject the identity** into your handlers. That's exactly what this module does, and nothing more.

```ts
@Get('orders/:userId')
@GrantedTo(and(isAuthenticated(), or(hasRole('ADMIN'), isUser('Param', 'userId'))))
findOrders(@Username() me: string, @Roles() roles: string[]) { /* ... */ }
```

## Features

- 🛡️ **One decorator to secure a route** — `@GrantedTo(...specs)`, applied by a global guard
- 🧩 **Composable boolean specifications** — `and`, `or`, `not`, `hasRole`, `isAuthenticated`, `isUser`, `isTenant`, `isTrue`, `isFalse`
- 💉 **Parameter decorators** — `@Username()`, `@Roles()`, `@Tenant()`
- 🪜 **Role hierarchy** — declare that one role implies others (`ADMIN ⇒ MANAGER ⇒ USER`); checks and injection see the expanded set
- 🧹 **Known-roles filtering** — keep only the roles your module owns, ignoring those a shared token carries for other services
- 🔌 **Pluggable principal provider** — HTTP headers (JSON or CSV roles) or a verified JWT
- 🔑 **JWT verification** with **IdP presets** — RFC 9068/SCIM, Azure AD/Entra, Keycloak, Okta — or a fully custom claim mapping
- 🔄 **JWKS key rotation** — verification keys fetched from the IdP's JWKS endpoint, cached, and re-fetched when it rotates them; each key verifies with its own algorithm (RSA, ECDSA, EdDSA), nothing to configure
- 🌐 **Several IdPs via OpenID discovery** — list their `/.well-known/openid-configuration` URLs: each token is verified with the keys of its own issuer
- 🤝 **Service-to-service in Kubernetes** — the services of your namespace call each other with their pod's token and pass every check (`bypass`)
- 🏢 **Multi-tenant aware** — `@Tenant()` injection plus `isTenant` to block cross-tenant access
- 🪶 **Tiny & dependency-light** — just `jsonwebtoken`; works on NestJS 10, 11 & 12

## Installation

```bash
npm install @softwarity/nestjs-granted
# peer deps you probably already have
npm install @nestjs/common @nestjs/core @nestjs/platform-express rxjs reflect-metadata
```

### Peer dependencies

| name | version |
|---|---|
| @nestjs/common | >=10 <13 |
| @nestjs/core | >=10 <13 |
| @nestjs/platform-express | >=10 <13 |
| rxjs | ^7.5 |
| reflect-metadata | ^0.1.13 \|\| ^0.2 |

> NestJS 12 ships as ESM only. This library is CommonJS and loads it through Node's `require(esm)`, so with NestJS 12 you need Node.js ≥ 20.19 or ≥ 22.12 — the same requirement NestJS 12 itself has for CommonJS apps. ESM apps work too.

---

## Getting started

### 1. Register the module

```ts
import { Module } from '@nestjs/common';
import { GrantedModule } from '@softwarity/nestjs-granted';

@Module({
  imports: [
    // `apply: false` loads the module but disables enforcement (handy per environment).
    GrantedModule.forRoot({ apply: true }),
  ],
})
export class AppModule {}
```

By default the module reads the identity from HTTP headers (`username`, `roles`, `tenant`). To decode it from a JWT instead, pass a `GrantedJwtPrincipalProvider` (see below).

### 2. Inject identity into your handlers

```ts
@Get('me')
me(
  @Username() username: string,
  @Roles() roles: string[],
  @Tenant() tenant: string | undefined,
) {
  return { username, roles, tenant };
}
```

### 3. Secure endpoints

```ts
@Get('admin')
@GrantedTo(and(isAuthenticated(), hasRole('ADMIN')))
adminOnly() { /* ... */ }
```

A route with **no** `@GrantedTo` is open. A route with `@GrantedTo(...)` passes only if **every** spec returns `true`.

`@GrantedTo` also applies at the **controller class** level — a baseline for every route inside it. Class and method specs are **merged**: all of them must pass (class = baseline, method tightens).

```ts
@Controller('admin')
@GrantedTo(isAuthenticated())          // baseline: every route requires a logged-in caller
export class AdminController {
  @Get('stats')
  stats() { /* needs: isAuthenticated() */ }

  @Get('config')
  @GrantedTo(hasRole('ADMIN'))         // tightened: isAuthenticated() AND hasRole('ADMIN')
  config() { /* ... */ }
}
```

> There is no "opt-out": a method can't loosen a class-level spec (specs are AND-merged). Leave a controller un-annotated and secure routes individually if some must stay open.

### Denied requests — `GrantedForbiddenException`

When a spec fails, the guard throws a `GrantedForbiddenException` (a `ForbiddenException`). The caller gets the same bare `403` NestJS sends for any guard returning `false` — nothing about the policy leaks:

```json
{ "statusCode": 403, "message": "Forbidden resource", "error": "Forbidden" }
```

The details stay on the exception, for your app to log in its own format — the library logs nothing itself:

| Property     | Content                                                                                         |
|--------------|-------------------------------------------------------------------------------------------------|
| `deniedSpec` | `id` of the first spec that failed, e.g. `hasRole(ADMIN)` — an `and(...)` / `or(...)` is reported whole |
| `username`   | the caller's username                                                                           |
| `roles`      | the caller's roles after hierarchy expansion and `knownRoles` filtering — what the specs saw    |
| `tenant`     | the caller's tenant, if any                                                                     |

```ts
@Catch(GrantedForbiddenException)
export class DenialFilter extends BaseExceptionFilter {
  private readonly logger = new Logger('Access');
  catch(e: GrantedForbiddenException, host: ArgumentsHost) {
    this.logger.debug(`denied: user=${e.username} roles=[${e.roles}] spec=${e.deniedSpec}`);
    super.catch(e, host); // unchanged 403 response
  }
}

// main.ts
app.useGlobalFilters(new DenialFilter(app.getHttpAdapter()));
```

> Don't put these details in the response: the required roles and the request fields an ownership check compares tell an attacker what to forge.

---

## Boolean specifications

`@GrantedTo` takes one or more `BooleanSpec`. Combine them freely:

```ts
GrantedTo(...specs: BooleanSpec[])     // all must pass

and(...specs)                          // every spec passes
or(...specs)                           // at least one passes
not(spec)                              // inverts a spec
isTrue()                               // always allow
isFalse()                              // always deny
hasRole(role: string)                  // role is in the user's roles (after hierarchy expansion)
isAuthenticated()                      // username is set and not 'anonymous'
isUser(type: 'Param'|'Query'|'Body', field: string)    // request value === username
isTenant(type: 'Param'|'Query'|'Body', field: string)  // request value === caller's tenant
```

### Ownership checks — `isUser` / `isTenant`

`isAuthenticated()` and `hasRole()` prove *who* the caller is. They do **not** prove that the record a request targets belongs to that caller — the classic **IDOR** hole, where a logged-in user just edits an id in the URL or body to hit someone else's data.

Consider `POST /orders` protected only by `isAuthenticated()`. Mallory is a real, logged-in user; she forges the body so the order is booked on **Alice's** account:

```bash
curl -X POST https://api.example.com/orders \
  -H 'authorization: Bearer <mallory-valid-token>' \
  -d '{ "customer": { "id": "alice" }, "items": [ ... ] }'
```

Auth passes — the token is valid. Nothing checks that `body.customer.id` is *her own* id. `isUser` reads that value **from the request** and requires it to equal the caller's `username`:

```ts
// the owner declared in the body must be the caller (admins excepted)
@Post('orders')
@GrantedTo(and(isAuthenticated(), or(hasRole('ADMIN'), isUser('Body', 'customer.id'))))
createOrder() { /* body.customer.id === caller, or caller is ADMIN */ }

// the resource owner in the URL must be the caller
@Patch('users/:userId/profile')
@GrantedTo(or(hasRole('ADMIN'), isUser('Param', 'userId')))
update(@Param('userId') userId: string) { /* ... */ }
```

Mallory's forged POST now returns `403` (`'alice'` ≠ `'mallory'`), and she can't read `/users/alice/profile` by swapping the id.

`isTenant` is the same check one level up — for multi-tenant APIs. It matches the **requested** tenant (URL/query/body) against the caller's **claimed** tenant (from the token/headers, never the attacker-controlled payload), blocking cross-tenant access:

```ts
@Post('tenants/:tenantId/invoices')
@GrantedTo(and(isAuthenticated(), or(hasRole('ADMIN'), isTenant('Param', 'tenantId'))))
createInvoice() { /* a request for /tenants/globex/... from an acme token is rejected */ }
```

> Authorization reads `username`, `roles` and (via `isTenant`) `tenant`. Note `isTenant` only checks that a *requested* tenant matches the *claimed* one — it does not replace data-layer scoping (`WHERE tenant_id = ?`), which you still apply with the injected `@Tenant()` value.

---

## Roles: known set & hierarchy

Two module-level options shape the roles before the guard and `@Roles()` ever see them. They work with any provider (header or JWT).

**`knownRoles`** — a gateway often issues one token whose roles span several services. Declare the roles *this* module cares about and the rest are dropped, so your view isn't polluted:

```ts
GrantedModule.forRoot({
  knownRoles: ['ORDER_READ', 'ORDER_WRITE', 'ORDER_ADMIN'],
});
// token roles ['ORDER_WRITE', 'BILLING_ADMIN', 'CRM_USER'] → seen as ['ORDER_WRITE']
```

**`roleHierarchy`** — map a role to the roles it implies. Expansion is transitive and cycle-safe, applied *before* `knownRoles` filtering, for both the guard and `@Roles()`:

```ts
GrantedModule.forRoot({
  roleHierarchy: {
    ORDER_ADMIN: ['ORDER_WRITE'],
    ORDER_WRITE: ['ORDER_READ'],
  },
});
// caller holds ['ORDER_ADMIN'] → hasRole('ORDER_READ') passes; @Roles() yields all three
```

---

## Principal providers

The identity is resolved by an `IGrantedPrincipalProvider`. Two are shipped.

### `GrantedPrincipalProvider` (default) — from headers

| info | default header | parsing | fallback |
|---|---|---|---|
| `username` | `username` | raw string | `anonymous` |
| `roles` | `roles` | JSON array, or CSV | `[]` |
| `tenant` | `tenant` | raw string | `undefined` |

Both the **header names** and the **roles encoding** are configurable:

```ts
import { GrantedModule, GrantedPrincipalProvider } from '@softwarity/nestjs-granted';

GrantedModule.forRoot({
  principalProvider: new GrantedPrincipalProvider({
    usernameHeader: 'x-user',   // default 'username'
    rolesHeader: 'x-roles',     // default 'roles'
    tenantHeader: 'x-tenant',   // default 'tenant'
    rolesFormat: 'csv',         // default 'json' — 'ROLE1, ROLE2' instead of ["ROLE1","ROLE2"]
  }),
});
```

> These options are specific to the header provider — JWT identity comes from configurable claims (`rolesClaim`, etc.), and roles there are already an array.

### `GrantedJwtPrincipalProvider` — from a verified JWT

Reads `Authorization: Bearer <token>`, verifies the token and maps its claims to `username` / `roles` / `tenant`. A missing or invalid token gives an **anonymous** request: your `@GrantedTo` specs decide what it may reach.

Pick the case that matches your setup:

| Your setup | Use |
|---|---|
| The IdP gave you a public key file | [`pemFile`](#a-public-key-file) |
| The IdP publishes a JWKS URL | [`jwksUri`](#a-jwks-url) |
| One or several IdPs, each with a `/.well-known/openid-configuration` | [`discoveryUris`](#one-or-several-idps-by-their-discovery-url) |
| The other services of your cluster must get through | [`discoveryUris` + `bypass`](#let-the-services-of-your-cluster-through) |

#### A public key file

```ts
GrantedModule.forRoot({
  apply: true,
  principalProvider: GrantedJwtPrincipalProvider.keycloak({
    pemFile: 'config/jwt_public_key.pem', // or base64Key: '-----BEGIN PUBLIC KEY-----…'
    algorithm: 'RS256',                   // default 'ES256'
  }),
});
```

#### A JWKS URL

```ts
GrantedJwtPrincipalProvider.keycloak({
  jwksUri: 'https://sso.example.com/realms/acme/protocol/openid-connect/certs',
});
```

No algorithm to set, and nothing to redeploy when the IdP rotates its keys.

#### One or several IdPs, by their discovery URL

```ts
new GrantedJwtPrincipalProvider({
  discoveryUris: [
    'https://sso.example.com/realms/acme', // '/.well-known/openid-configuration' is appended
    'http://partner-idp.iam:8080/.well-known/openid-configuration',
  ],
});
```

Each token is checked with the keys of the IdP that issued it (its `iss`). A token from an IdP that isn't listed is anonymous. An internal URL is fine: the issuer is read from the document, not from the URL.

#### Let the services of your cluster through

Service A calls service B with its pod's service account token. B lets the services of its namespace through, whatever the `@GrantedTo`, and keeps checking users as usual:

```ts
new GrantedJwtPrincipalProvider({
  discoveryUris: [
    {
      uri: 'https://kubernetes.default.svc', // the cluster's API server signs the service account tokens
      bearerTokenFile: '/var/run/secrets/kubernetes.io/serviceaccount/token', // it serves its keys to an authenticated caller only
      bypass: ['system:serviceaccount:canopy:*'],
    },
    'https://sso.example.com/realms/acme', // users
  ],
});
```

| Caller | Result on B |
|---|---|
| A user, through the IdP | `@GrantedTo` checked as usual |
| A service account of `canopy` | passes every `@GrantedTo` — `@Username()` is `system:serviceaccount:canopy:orders` |
| Any other service account (another namespace, a third-party component) | checked as usual: authenticated, but without any role |

On B's pod, trust the cluster CA, which signs the API server certificate:

```yaml
env:
  - name: NODE_EXTRA_CA_CERTS
    value: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
```

On A, send the pod's token — read it at each call, the kubelet rotates it:

```ts
const token = readFileSync('/var/run/secrets/kubernetes.io/serviceaccount/token', 'utf8').trim();
await fetch('http://billing/api/invoices', { headers: { authorization: `Bearer ${token}` } });
```

> Keep `bypass` to your own namespace: every pod of the cluster carries a token signed by the same API server. Outside a cluster the token file is missing: that entry logs a warning and its tokens stay anonymous; the other IdPs keep working.

#### Claims → identity

| Factory | username | roles | tenant |
|---|---|---|---|
| `GrantedJwtPrincipalProvider.rfc9068(...)` | `sub` | `roles` | `tenant` |
| `GrantedJwtPrincipalProvider.azureAd(...)` | `preferred_username` | `roles` | `tid` |
| `GrantedJwtPrincipalProvider.keycloak(...)` | `preferred_username` | `realm_access.roles` | `tenant` |
| `GrantedJwtPrincipalProvider.okta(...)` | `sub` | `groups` | `tenant` |
| `new GrantedJwtPrincipalProvider(...)` | `usernameClaim` (`sub`) | `rolesClaim` (`roles`) | `tenantClaim` (`tenant`) |

Every claim is overridable, dotted paths included: `GrantedJwtPrincipalProvider.okta({ jwksUri, usernameClaim: 'email' })`, `rolesClaim: 'realm_access.roles'`.

#### Refuse tokens issued for another API

The provider checks the signature and the expiry. Behind a gateway that already checks the rest, that's enough. Reachable without the gateway, or sharing an IdP with other apps? Check the audience, and the issuer with a key or a JWKS URL:

```ts
GrantedJwtPrincipalProvider.keycloak({
  jwksUri: 'https://sso.example.com/realms/acme/protocol/openid-connect/certs',
  issuer: 'https://sso.example.com/realms/acme',
  audience: 'orders-api', // a string, a RegExp, or a list
});
```

With `discoveryUris`, the issuer comes from each document, and an entry can have its own audience: `{ uri, audience: 'internal' }`.

#### Options

| Option | Default | |
|---|---|---|
| `pemFile` / `base64Key` | — | Public key, as a file or inline PEM. |
| `algorithm` | `'ES256'` with a key; each key's own with a JWKS | With a JWKS, an optional allowlist: `['ES256', 'EdDSA']`. |
| `jwksUri` | — | JWKS URL. Alongside `discoveryUris`, needs `issuer`. |
| `discoveryUris` | — | IdP URLs, or `{ uri, bearerTokenFile?, audience?, bypass? }`. |
| ↳ `bearerTokenFile` | — | Token sent to this IdP only, when it wants one (the Kubernetes API server does). Re-read at each fetch. |
| ↳ `audience` | `audience` | Accepted `aud` for this IdP's tokens. |
| ↳ `bypass` | — | `sub` patterns (`*` = anything) whose tokens from this IdP pass every `@GrantedTo`. |
| `issuer` | not checked | Accepted `iss`, with `pemFile` / `base64Key` / `jwksUri`. |
| `audience` | not checked | Accepted `aud`. |
| `usernameClaim` / `rolesClaim` / `tenantClaim` | see presets | Claim paths. |
| `jwksCacheMaxAge` | 10 min | Keys and documents older than this are re-fetched. |
| `jwksCooldown` | 30 s | At most one fetch per IdP in this delay. |
| `jwksTimeout` | 5 s | Timeout of a fetch. |

Good to know:
- A token signed by a key the provider doesn't know yet triggers one re-fetch: a key rotation needs no restart.
- If an IdP is down, the last known keys are kept and a warning is logged.
- The algorithm comes from the key, never from the token: `alg: none` and RSA/HMAC confusion are rejected.
- The token and the key material are never logged.

### Custom provider

Implement `IGrantedPrincipalProvider` to read the identity from anywhere. Handle both `Request` (the guard) and `IncomingMessage` (the parameter decorators):

```ts
export class MyGrantedPrincipalProvider implements IGrantedPrincipalProvider {
  getUsernameFromRequest(req: Request): string { return req.header('x-user') || 'anonymous'; }
  getRolesFromRequest(req: Request): string[] { return JSON.parse(req.header('x-roles') || '[]'); }
  getTenantFromRequest(req: Request): string | undefined { return req.header('x-tenant') || undefined; }

  getUsernameFromIncomingMessage(msg: IncomingMessage): string { return (msg.headers['x-user'] as string) || 'anonymous'; }
  getRolesFromIncomingMessage(msg: IncomingMessage): string[] { return JSON.parse((msg.headers['x-roles'] as string) || '[]'); }
  getTenantFromIncomingMessage(msg: IncomingMessage): string | undefined { return (msg.headers['x-tenant'] as string) || undefined; }
}
```

```ts
GrantedModule.forRoot({ apply: true, principalProvider: new MyGrantedPrincipalProvider() })
```

Resolving the identity needs I/O (a remote key set, a session store…)? Also implement the optional `prepare(request): Promise<void>` hook. The guard awaits it once per request, before any getter is called — on open routes and with `apply: false` too, since the parameter decorators run after the guard. Store what the getters need on the request: they stay synchronous.

---

## License

Apache-2.0 © [Softwarity](https://www.softwarity.io/)
