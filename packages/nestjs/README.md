# @softwarity/nestjs-granted

[![npm version](https://img.shields.io/npm/v/@softwarity/nestjs-granted.svg)](https://www.npmjs.com/package/@softwarity/nestjs-granted)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-yellow.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![Node](https://img.shields.io/node/v/@softwarity/nestjs-granted.svg)](https://nodejs.org)
[![Unit tests](https://github.com/softwarity/nestjs-granted/actions/workflows/unit-tests.yml/badge.svg)](https://github.com/softwarity/nestjs-granted/actions/workflows/unit-tests.yml)

**Decide, route by route, who may call your NestJS API.** Put `@GrantedTo(...)` on a route: a global guard checks it on every request. Your handlers read the caller with `@Username()`, `@Roles()` and `@Tenant()`. The caller comes from gateway headers or from a verified JWT.

📚 **Documentation:** [softwarity.github.io/nestjs-granted](https://softwarity.github.io/nestjs-granted/)

```ts
@Get('orders/:userId')
@GrantedTo(or(hasRole('ADMIN'), isUser('Param', 'userId'))) // an admin, or the user named in the URL
findOrders(@Username() me: string) { /* ... */ }
```

It doesn't log anyone in: something in front of your service — a gateway, an identity provider — has authenticated the caller and passes the identity on.

- [Getting started](#getting-started)
- [Protect your routes](#protect-your-routes)
- [Read the caller](#read-the-caller)
- [Where the identity comes from](#where-the-identity-comes-from) — headers, JWT, several IdPs, the services of your cluster
- [Roles](#roles)
- [Options reference](#options-reference)

---

## Getting started

```bash
npm install @softwarity/nestjs-granted
```

Node.js ≥ 20 (≥ 20.19 or ≥ 22.12 with NestJS 12), NestJS 10 to 12, Express. Peer dependencies: `@nestjs/common`, `@nestjs/core`, `@nestjs/platform-express`, `rxjs`, `reflect-metadata`.

```ts
import { Module } from '@nestjs/common';
import { GrantedModule } from '@softwarity/nestjs-granted';

@Module({
  imports: [GrantedModule.forRoot()],
})
export class AppModule {}
```

The caller is read from the `username`, `roles` and `tenant` headers. Your requests carry a JWT instead? See [Where the identity comes from](#where-the-identity-comes-from).

```ts
@Controller('reports')
export class ReportsController {
  @Get()
  @GrantedTo(hasRole('ADMIN'))
  list(@Username() username: string) {
    // only reached by an ADMIN
  }
}
```

A route without `@GrantedTo` is open. With it, the request gets a `403` unless every rule passes.

---

## Protect your routes

**Logged-in users only**

```ts
@GrantedTo(isAuthenticated())
```

**A role** — an implied role counts too, see [Roles](#roles)

```ts
@GrantedTo(hasRole('ADMIN'))
```

**One role among several**

```ts
@GrantedTo(or(hasRole('ADMIN'), hasRole('ACCOUNTANT')))
```

**Several conditions** — the arguments must all pass

```ts
@GrantedTo(isAuthenticated(), not(hasRole('SUSPENDED')))
```

**A whole controller**

```ts
@Controller('admin')
@GrantedTo(isAuthenticated())   // every route of the controller
export class AdminController {
  @Get('stats')
  stats() {}                    // logged-in users

  @Get('config')
  @GrantedTo(hasRole('ADMIN'))  // logged-in users that are ADMIN
  config() {}
}
```

A method adds conditions to its controller's, it can't remove them. If a route must stay open, put `@GrantedTo` on each route rather than on the class.

**Users may only touch their own data** — a logged-in user can change an id in the URL or the body to reach someone else's data; roles don't stop that, `isUser` does:

```ts
// PATCH /users/alice/profile, sent by mallory → 403
@Patch('users/:userId/profile')
@GrantedTo(or(hasRole('ADMIN'), isUser('Param', 'userId')))
updateProfile() {}

// POST /orders { "customer": { "id": "alice" } }, sent by mallory → 403
@Post('orders')
@GrantedTo(or(hasRole('ADMIN'), isUser('Body', 'customer.id')))
createOrder() {}
```

> This checks the id a request names. A route that *lists* records (`GET /orders`) must still filter its query by the caller, with `@Username()`.

**Users may only touch their own tenant**

```ts
// POST /tenants/globex/invoices, sent by a user of acme → 403
@Post('tenants/:tenantId/invoices')
@GrantedTo(or(hasRole('ADMIN'), isTenant('Param', 'tenantId')))
createInvoice() {}
```

A caller without a tenant is refused. Filter your queries with `@Tenant()` as well.

**Reuse a rule**

```ts
export const ownerOrAdmin = (param: string) => or(hasRole('ADMIN'), isUser('Param', param));

@Delete('users/:userId')
@GrantedTo(ownerOrAdmin('userId'))
remove() {}
```

**Write your own rule**

```ts
export const hasScope = (scope: string): BooleanSpec => ({
  id: `hasScope(${scope})`, // shown in the 403 details
  apply: (request, username, roles, tenant) => (request.header('x-scopes') ?? '').split(' ').includes(scope),
});
```

**All the rules**

| Rule | Passes when |
|---|---|
| `isAuthenticated()` | the caller is known (not `anonymous`) |
| `hasRole('ADMIN')` | the caller has the role, directly or [implied](#roles) |
| `isUser('Param', 'userId')` | the request value is the caller's username — `'Param'`, `'Query'` or `'Body'` (dotted path) |
| `isTenant('Param', 'tenantId')` | the request value is the caller's tenant; refused when the caller has none |
| `and(a, b, …)` | all pass |
| `or(a, b, …)` | one passes |
| `not(a)` | `a` fails |
| `isTrue()` / `isFalse()` | always / never — e.g. to lock a route |

### Why did a request get a 403?

The caller gets a bare `403`, with nothing about your rules. The details are on the exception — `GrantedForbiddenException` — for you to log:

```ts
@Catch(GrantedForbiddenException)
export class DenialFilter extends BaseExceptionFilter {
  private readonly logger = new Logger('Access');
  catch(e: GrantedForbiddenException, host: ArgumentsHost) {
    // e.g. denied: user=bob roles=[USER] rule=hasRole(ADMIN)
    this.logger.debug(`denied: user=${e.username} roles=[${e.roles}] rule=${e.deniedSpec}`);
    super.catch(e, host);
  }
}

// main.ts
app.useGlobalFilters(new DenialFilter(app.getHttpAdapter()));
```

`deniedSpec` is the first rule that failed, `roles` the roles it was checked against (after [hierarchy and filtering](#roles)), plus `username` and `tenant`. Don't send them back: they tell an attacker what to forge.

### Turn the checks off, in development or tests

```ts
GrantedModule.forRoot({ apply: process.env['ENFORCE_RBAC'] !== 'false' })
```

Every request gets through; `@Username()` and the other decorators keep working.

---

## Read the caller

```ts
@Get('me')
me(@Username() username: string, @Roles() roles: string[], @Tenant() tenant: string | undefined) {
  return { username, roles, tenant };
}
```

| Decorator | Gives | When the caller has none |
|---|---|---|
| `@Username()` | `string` | `'anonymous'` |
| `@Roles()` | `string[]` — the roles the rules see, after [hierarchy and filtering](#roles) | `[]` |
| `@Tenant()` | `string \| undefined` | `undefined` |

---

## Where the identity comes from

| Your setup | Use |
|---|---|
| A gateway puts the user in HTTP headers | [Headers](#headers-from-a-gateway) — the default |
| Requests carry `Authorization: Bearer <JWT>` | [`GrantedJwtPrincipalProvider`](#a-jwt--grantedjwtprincipalprovider) |
| Something else — a session, another scheme | [Your own provider](#your-own-provider) |

### Headers from a gateway

Nothing to configure when your gateway sends `username`, `roles` (a JSON array) and `tenant`. Other names, or roles as a comma-separated list:

```ts
GrantedModule.forRoot({
  principalProvider: new GrantedPrincipalProvider({
    usernameHeader: 'x-user',
    rolesHeader: 'x-roles',
    tenantHeader: 'x-tenant',
    rolesFormat: 'csv', // 'ADMIN, USER' instead of ["ADMIN","USER"]
  }),
});
```

> Only trust these headers when your service can't be reached without the gateway: anyone else could send them.

### A JWT — `GrantedJwtPrincipalProvider`

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

All the options: [Options reference](#options-reference).

Good to know:
- A token signed by a key the provider doesn't know yet triggers one re-fetch: a key rotation needs no restart.
- If an IdP is down, the last known keys are kept and a warning is logged.
- The algorithm comes from the key, never from the token: `alg: none` and RSA/HMAC confusion are rejected.
- The token and the key material are never logged.

### Your own provider

Implement `IGrantedPrincipalProvider`. Each value has two getters: one for the guard (`Request`), one for the parameter decorators (`IncomingMessage`).

```ts
export class SessionProvider implements IGrantedPrincipalProvider {
  constructor(private readonly sessions: SessionStore) {}

  // Optional: awaited once per request, before the getters — the place for I/O.
  async prepare(req: IncomingMessage): Promise<void> {
    req['session'] = await this.sessions.find(req.headers['x-session-id'] as string);
  }

  getUsernameFromRequest(req: Request) { return req['session']?.username ?? 'anonymous'; }
  getRolesFromRequest(req: Request) { return req['session']?.roles ?? []; }
  getTenantFromRequest(req: Request) { return req['session']?.tenant; }

  getUsernameFromIncomingMessage(msg: IncomingMessage) { return msg['session']?.username ?? 'anonymous'; }
  getRolesFromIncomingMessage(msg: IncomingMessage) { return msg['session']?.roles ?? []; }
  getTenantFromIncomingMessage(msg: IncomingMessage) { return msg['session']?.tenant; }
}

GrantedModule.forRoot({ principalProvider: new SessionProvider(sessions) });
```

A `prepare()` that throws fails the request: catch what should rather give an anonymous caller. To let a caller through every rule, also implement `isBypassed(request): boolean`.

---

## Roles

Two options of `forRoot` adjust the caller's roles before any rule runs, whatever they come from. `@Roles()` gives the adjusted list.

**A role implies others — `roleHierarchy`**

```ts
GrantedModule.forRoot({
  roleHierarchy: {
    ADMIN: ['MANAGER'],
    MANAGER: ['USER'],
  },
});
// a caller with ['ADMIN'] passes hasRole('MANAGER') and hasRole('USER')
```

**Ignore the roles meant for other services — `knownRoles`**

```ts
GrantedModule.forRoot({
  knownRoles: ['ORDER_READ', 'ORDER_WRITE', 'ORDER_ADMIN'],
});
// token roles ['ORDER_WRITE', 'BILLING_ADMIN', 'CRM_USER'] → ['ORDER_WRITE']
```

With both, the hierarchy is applied first: an implied role is kept if it is known.

---

## Options reference

### `GrantedModule.forRoot(options)`

| Option | Default | |
|---|---|---|
| `apply` | `true` | `false` lets every request through; the decorators keep working. |
| `principalProvider` | headers | [Where the identity comes from](#where-the-identity-comes-from). |
| `roleHierarchy` | — | A role → the roles it implies: [Roles](#roles). |
| `knownRoles` | all roles kept | The roles to keep: [Roles](#roles). |

Options are read once, at startup — there is no `forRootAsync`. Read your environment variables or files before, and pass the values.

### `new GrantedPrincipalProvider(options)` — headers

| Option | Default | |
|---|---|---|
| `usernameHeader` | `'username'` | Missing → `'anonymous'`. |
| `rolesHeader` | `'roles'` | Missing → `[]`. |
| `tenantHeader` | `'tenant'` | Missing → `undefined`. |
| `rolesFormat` | `'json'` | `'json'`: `["ADMIN","USER"]`. `'csv'`: `ADMIN, USER`. |

### `GrantedJwtPrincipalProvider` — JWT

`new GrantedJwtPrincipalProvider(options)`, or a preset that sets the claims: `.rfc9068()`, `.azureAd()`, `.keycloak()`, `.okta()`.

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

---

## License

Apache-2.0 © [Softwarity](https://www.softwarity.io/)
