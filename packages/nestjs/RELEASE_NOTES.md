# Release Notes

## NEXT RELEASE

---

## 5.4.0

### New features

- **Several identity providers, through OpenID discovery: `discoveryUris`.** List the IdPs' discovery documents — `discoveryUris: ['http://idp-a:8080/.well-known/openid-configuration', …]`, or the URL they live under, `/.well-known/openid-configuration` being appended. Each document gives its IdP's `issuer` and `jwks_uri`: nothing else to configure. A token is verified only with the keys of the IdP whose `issuer` is its `iss` — a key of one IdP never validates a token claiming another, and a token whose `iss` no document announces is rejected without any key fetch; no URL is ever taken from the token. The issuer is the document's, whatever the URL it was fetched from, so an IdP reached through an in-cluster address keeps its public issuer. Documents are fetched on first use and cached like the keys (`jwksCacheMaxAge`, `jwksCooldown`, `jwksTimeout`); a re-fetched document pointing to a new `jwks_uri` is followed; an IdP whose document can't be fetched doesn't affect the others.
- **`discoveryUris` and `jwksUri` cohabit.** `jwksUri` then needs `issuer`, which routes tokens to its keys and applies to it only — the construction throws otherwise. `audience` is checked whatever the IdP.

### Changes

- With `jwksUri` and `issuer`, a token claiming another issuer is now rejected before any key lookup, so it never triggers a JWKS fetch.

### Internal changes

- `granted-info.jwt-provider.ts`: the JWK Set cache is now one source per issuer (`jwksUri`'s, then one per `discoveryUris` entry), sharing the same cache / cooldown / failure handling with the discovery documents.
- `test/jwks.spec.ts`: `discoveryUris` — routing by issuer, unknown issuer, document outage and retry, `jwks_uri` change, cohabitation with `jwksUri`, construction errors.
- Docs (README and site): *Several identity providers — OpenID discovery* section, `discoveryUris` in the option tables.

---

## 5.3.0

### New features

- **Denials are diagnosable: the guard throws a `GrantedForbiddenException`.** Until now the guard returned `false` and a 403 said nothing about why — which spec failed, with which roles. It now throws `GrantedForbiddenException`, a `ForbiddenException` carrying `deniedSpec` (the `id` of the first spec that failed, e.g. `hasRole(ADMIN)`; an `and(...)` / `or(...)` is reported whole), `username`, `roles` (after hierarchy expansion and `knownRoles` filtering — what the specs saw) and `tenant`. The library logs nothing: the host app logs these in its own format from an exception filter (`@Catch(GrantedForbiddenException)`). The response body is unchanged — `{ "statusCode": 403, "message": "Forbidden resource", "error": "Forbidden" }` — so the caller learns nothing about the policy.

### Changes

- `AppGuard.canActivate` now throws on a denial instead of resolving to `false`. Only matters if you call the guard yourself; existing filters catching `ForbiddenException` still catch it.

### Internal changes

- `test/guard.spec.ts`: exception details, composed specs reported whole, response body unchanged, and an HTTP test (supertest) with a host filter receiving the details.
- Docs (README and site): *Denied requests* section with a logging filter example.

---

## 5.2.0

### New features

- **With `jwksUri`, each key verifies with its own algorithm — no `algorithm` to configure.** The provider used to verify with a single configured algorithm (default `RS256`), which had to match the one the IdP signs with: an IdP moving to ES256 turned every caller anonymous (`invalid algorithm`) until the service was reconfigured. The algorithm now comes from the JWK Set: the key is picked by the token's `kid` and verifies with the `alg` that key declares. A set can mix algorithms, and the issuer can change algorithm without any change on the service side. A key published without `alg` gets the one its type implies — RS256 for RSA, ES256 / ES384 / ES512 for EC on P-256 / P-384 / P-521, EdDSA for Ed25519. The algorithm never comes from the token: one whose `alg` header differs from its key's is rejected, which rules out `alg: none` and RSA/HMAC confusion attacks.
- **EdDSA (Ed25519) tokens, with `jwksUri`.** On top of RS256 / RS384 / RS512, PS256 / PS384 / PS512 and ES256 / ES384 / ES512. `jsonwebtoken` has no EdDSA, so Node's `crypto` verifies the signature and the provider checks `exp`, `nbf`, `issuer` and `audience` the same way. Not available with a PEM key (`base64Key` / `pemFile`): asking for it there throws at construction.
- **`algorithm` accepts a list.** `algorithm: ['ES256', 'EdDSA']`. New exported type `JwtAlgorithm` (`jsonwebtoken`'s `Algorithm`, plus `'EdDSA'`).

### Changes

- **Breaking — with a PEM key (`base64Key` / `pemFile`), `algorithm` now defaults to `ES256` instead of `RS256`.** A provider that relied on the default with an RSA key must now say so — `algorithm: 'RS256'` — or every token is treated as anonymous (`invalid algorithm`). Providers that already set `algorithm` are not affected. This default is never read with `jwksUri`: there, each key brings its own algorithm.
- **With `jwksUri`, `algorithm` is now optional and acts as an allowlist.** Unset, every key of the set is accepted with its own algorithm — it no longer defaults to `RS256`, so a set publishing ES256 or EdDSA keys now has their tokens accepted too; set `algorithm: 'RS256'` to keep the previous restriction. Set, a token signed with another algorithm is rejected. For a key published without `alg`, the allowlist also settles which algorithm it verifies with, so `algorithm: 'PS256'` keeps working with such keys. A key whose declared `alg` its type can't verify (an RSA key announcing `ES256`) verifies nothing.
- With `jwksUri`, `none` and the HS* algorithms now throw at construction, as does an empty list. Such a provider used to start and treat every token as anonymous.
- With `jwksUri` and no `algorithm`, the provider's `algorithm` property is `undefined`, and the warning logged on a failed verification reads `JWT verification failed (JWKS)`.

### Internal changes

- `test/jwks.spec.ts`: RS256, ES256 and EdDSA tokens verified against one set with no `algorithm`; allowlist; unknown `kid`; tokens announcing another algorithm than their key (`RS384`, `HS256` signed with the public key, `none`); keys without `alg`, or with one their type can't verify; EdDSA signature, dates, issuer and audience.
- `test/info-providers.spec.ts`: `ES256` default with a PEM key, list of algorithms.
- Docs (README and site): the JWKS is enough, the algorithm is set on the issuer side only.

---

## 5.1.0

### New features

- **JWKS endpoint with automatic key rotation in `GrantedJwtPrincipalProvider`.** New `jwksUri` option — the URL of the JWK Set the IdP publishes (e.g. `https://idp.example.com/.well-known/jwks.json`) — as an alternative to `base64Key` / `pemFile`, available on every preset (`GrantedJwtPrincipalProvider.keycloak({ jwksUri })`). Keys are fetched on first use and cached. When a token fails verification — typically because the IdP rotated its signing key — the set is re-fetched once and the token verified again, so a rotation needs neither a restart nor a new PEM. The key is picked by the token's `kid` (every key is tried when it has none), with the configured `algorithm`; symmetric and `"use": "enc"` keys in the set are ignored. Tuning: `jwksCacheMaxAge` (default 10 min — older keys are re-fetched, so a withdrawn key stops being accepted), `jwksCooldown` (default 30 s — never two fetches closer than that, so forged `kid`s can't hammer the IdP; concurrent requests share one fetch) and `jwksTimeout` (default 5 s). A failed fetch keeps the last known keys and logs a warning. Combining `jwksUri` with `base64Key` / `pemFile` throws at construction. No new dependency: Node's built-in `fetch` and `crypto` do the work.
- **Optional `issuer` / `audience` checks in `GrantedJwtPrincipalProvider`.** Unset by default, so nothing changes: behind a gateway that already validated the token, the signature and validity dates remain the only checks. When set, a token whose `iss` isn't one of the accepted issuers (`string | string[]`), or whose `aud` doesn't match (`string | RegExp`, or an array of them), is treated as anonymous. Worth it when the service can be reached without the gateway, or with an IdP that signs other apps' tokens with the same keys (Microsoft Entra ID shares its keys across tenants). Both need a key — `base64Key`, `pemFile` or `jwksUri` — and throw at construction without one. With a JWKS, such a rejection doesn't trigger a re-fetch: the key matched.
- **Optional async `prepare(request)` hook on `IGrantedPrincipalProvider`.** The guard awaits it once per request before reading the identity — on open routes and with `apply: false` too, since the parameter decorators run after the guard. A provider can do I/O there (the JWKS fetch above, a session lookup…) while its getters stay synchronous. Existing providers need no change.

### Changes

- `AppGuard.canActivate` is now `async` and returns `Promise<boolean>`, to await `prepare`. This only matters if you call the guard yourself.

### Internal changes

- New `test/jwks.spec.ts` suite, run against a local JWKS server: rotation, cooldown, cache max age, shared fetch, outage, timeout, ignored key types, no unverified fallback, no re-fetch on an issuer / audience mismatch. `issuer` / `audience` specs added to `test/info-providers.spec.ts`. The guard specs are now async and cover `prepare`.
- Docs (README and site): JWKS section, `jwksUri`, `issuer` and `audience` options, `prepare()` hook. Also fixes the pipeline order stated in the README and on the Principal providers page: parameter decorators run after the guard, not before.

---

## 5.0.0

### Changes

- **Relicensed under Apache-2.0** (previously MIT), for its explicit patent grant — easier to adopt for companies whose legal teams pre-approve Apache over MIT. `LICENSE` and the `package.json` `license` field are updated; versions up to 4.1.0 stay MIT.

- **NestJS 12 support.** The `@nestjs/common` / `@nestjs/core` / `@nestjs/platform-express` peer range is widened to `>=10.0.0 <13.0.0`. NestJS 12 ships as ESM only; the library stays CommonJS and loads it through Node's `require(esm)`, so with NestJS 12 the host app needs Node.js ≥ 20.19 or ≥ 22.12 (the same requirement NestJS 12 itself has for CommonJS apps). ESM host apps work too. No API change; NestJS 10 and 11 remain supported.

### Internal changes

- Dev dependencies moved to NestJS 12 (`@nestjs/common`, `@nestjs/core`, `@nestjs/platform-express`, `@nestjs/testing` `^12.0.1`) and Jest 30 (`jest`, `@types/jest` `^30`, `ts-jest` `^29.4`).
- Jest can only load the ESM-only NestJS packages through its `require(esm)` support, which needs `--experimental-vm-modules` and Node.js ≥ 24.9. `npm test`, `test:watch` and `test:cov` now run `node --experimental-vm-modules node_modules/jest/bin/jest.js`; running the test suite locally requires Node 24.9+.
- CI workflows that run Jest (unit tests, publish) now use Node 24.
- Releases now go through [`softwarity/release-flow`](https://github.com/softwarity/release-flow): the *Create Tag/Release* workflow takes a `patch` / `minor` / `major` choice, checks lint, tests and build before tagging, resolves this `## NEXT RELEASE` section into the version and publishes the GitHub Release from it. This file is new — earlier versions have no release notes.
- Doc site: icons migrated to Material Symbols (license badge now Apache-2.0).

---
