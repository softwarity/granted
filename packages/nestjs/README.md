# @softwarity/nestjs-granted

[![npm version](https://img.shields.io/npm/v/@softwarity/nestjs-granted.svg)](https://www.npmjs.com/package/@softwarity/nestjs-granted)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
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
- 🧩 **Composable boolean specifications** — `and`, `or`, `not`, `hasRole`, `isAuthenticated`, `isUser`, `isTrue`, `isFalse`
- 💉 **Parameter decorators** — `@Username()`, `@Roles()`, `@Tenant()`
- 🔌 **Pluggable user-info provider** — read from HTTP headers (default) or from a verified JWT
- 🔑 **JWT verification** with **IdP presets** — RFC 9068/SCIM, Azure AD/Entra, Keycloak, Okta — or a fully custom claim mapping
- 🏢 **Multi-tenant aware** — inject the caller's tenant for data-scoping (orthogonal to authorization)
- 🪶 **Tiny & dependency-light** — just `jsonwebtoken`; works on NestJS 10 & 11

## Installation

```bash
npm install @softwarity/nestjs-granted
# peer deps you probably already have
npm install @nestjs/common @nestjs/core @nestjs/platform-express rxjs reflect-metadata
```

### Peer dependencies

| name | version |
|---|---|
| @nestjs/common | >=10 <12 |
| @nestjs/core | >=10 <12 |
| @nestjs/platform-express | >=10 <12 |
| rxjs | ^7.5 |
| reflect-metadata | ^0.1.13 \|\| ^0.2 |

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

By default the module reads the identity from HTTP headers (`username`, `roles`, `tenant`). To decode it from a JWT instead, pass a `GrantedInfoJwtProvider` (see below).

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
hasRole(role: string)                  // role is in the user's roles
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

## User-info providers

The identity is resolved by an `IGrantedInfoProvider`. Two are shipped.

### `GrantedInfoProvider` (default) — from headers

| info | source header | default |
|---|---|---|
| `username` | `username` | `anonymous` |
| `roles` | `roles` (JSON array) | `[]` |
| `tenant` | `tenant` | `undefined` |

### `GrantedInfoJwtProvider` — from a verified JWT

Reads the `Authorization: Bearer <token>` header, verifies the token with your public key, and maps the claims to `username` / `roles` / `tenant`. Claim names are configurable (dotted paths supported for nested claims), with presets for common IdPs:

```ts
import { GrantedModule, GrantedInfoJwtProvider } from '@softwarity/nestjs-granted';

@Module({
  imports: [
    GrantedModule.forRoot({
      apply: true,
      // Preset — you only provide the key material:
      infoProvider: GrantedInfoJwtProvider.keycloak({
        algorithm: 'RS256',
        pemFile: 'config/jwt_public_key.pem',
      }),
    }),
  ],
})
export class AppModule {}
```

#### Presets

| Factory | username | roles | tenant |
|---|---|---|---|
| `GrantedInfoJwtProvider.rfc9068(...)` | `sub` | `roles` | `tenant` |
| `GrantedInfoJwtProvider.azureAd(...)` | `preferred_username` | `roles` | `tid` |
| `GrantedInfoJwtProvider.keycloak(...)` | `preferred_username` | `realm_access.roles` | `tenant` |
| `GrantedInfoJwtProvider.okta(...)` | `sub` | `groups` | `tenant` |

Every field is overridable, e.g. `GrantedInfoJwtProvider.okta({ pemFile, usernameClaim: 'email' })`.

#### Custom claim mapping

```ts
new GrantedInfoJwtProvider({
  algorithm: 'RS256',
  pemFile: 'config/jwt_public_key.pem',
  // or base64Key: '-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----',
  usernameClaim: 'sub',              // default 'sub'
  rolesClaim: 'realm_access.roles',  // default 'roles' — dotted paths supported
  tenantClaim: 'tid',                // default 'tenant'
});
```

> A token that is missing, malformed, or fails verification yields an **anonymous** request — it's then up to your specs (e.g. `isAuthenticated()`) to reject it. The provider never logs the token or the key material.

### Custom provider

Implement `IGrantedInfoProvider` to read the identity from anywhere. Handle both `Request` (route handlers) and `IncomingMessage` (param decorators run earlier in the pipeline):

```ts
export class MyGrantedInfoProvider implements IGrantedInfoProvider {
  getUsernameFromRequest(req: Request): string { return req.header('x-user') || 'anonymous'; }
  getRolesFromRequest(req: Request): string[] { return JSON.parse(req.header('x-roles') || '[]'); }
  getTenantFromRequest(req: Request): string | undefined { return req.header('x-tenant') || undefined; }

  getUsernameFromIncomingMessage(msg: IncomingMessage): string { return (msg.headers['x-user'] as string) || 'anonymous'; }
  getRolesFromIncomingMessage(msg: IncomingMessage): string[] { return JSON.parse((msg.headers['x-roles'] as string) || '[]'); }
  getTenantFromIncomingMessage(msg: IncomingMessage): string | undefined { return (msg.headers['x-tenant'] as string) || undefined; }
}
```

```ts
GrantedModule.forRoot({ apply: true, infoProvider: new MyGrantedInfoProvider() })
```

---

## License

MIT © [Softwarity](https://www.softwarity.io/)
