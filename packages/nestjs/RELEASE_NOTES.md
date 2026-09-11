# Release Notes

## NEXT RELEASE

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
