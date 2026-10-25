# Release Notes

## NEXT RELEASE

### New features

- **Go and Quarkus: each route's rule in the OpenAPI document, as nestjs-granted writes it for `@GrantedTo`.** The same document in the three languages: in `security`, the entries are alternatives (or) and the roles of one entry are all required (and) — `or(hasRole(A), and(hasRole(B), hasRole(C)))` gives `[{bearer: [A]}, {bearer: [B, C]}]`, a branch without a role `{bearer: []}`, an open route `{}` — and a `403` states the rule in clear, `Forbidden unless: hasRole(A) or (hasRole(B) and hasRole(C))`; the scheme is `bearer` unless configured. **Go** depends on no router nor OpenAPI library: every built-in `Spec` now carries its role alternatives and its label, and `granted.Describe(scheme, specs...)` gives the `Security` and the `Forbidden` description to copy onto an operation — several specs read as an `and`, as `Require` has them; a `Spec` built by hand reads as an authenticated caller, labelled by its `ID`. **Quarkus**, with `quarkus-smallrye-openapi` (nothing happens without it), writes the rule of each route's `@RolesAllowed`, `@Authenticated`, `@PermitAll` or `@DenyAll` — the method's replacing the class's, `${...}` roles resolved with the build-time configuration, `deny-unannotated-endpoints` / `default-roles-allowed` reflected — plus a `401` where an anonymous caller is refused, as Quarkus answers it; smallrye-openapi's own automatic requirement and `401`/`403` are replaced on those routes, a `@SecurityRequirement` or an `@APIResponse` 401/403 the host declared is kept. Option `granted.openapi.security-scheme` (build time), added to the document as an HTTP bearer scheme unless it defines one by that name.
- **Go: `(*JWTProvider).Ready(ctx)`, the readiness check of Quarkus's `granted-jwks`.** `nil` once the keys of each identity provider are fetched; otherwise an error naming each provider without keys and why — a status, a TLS handshake, a timeout, never a token. It asks what a verification asks, through the same cache and cooldown, so probing it in a loop never hammers an IdP. `OpenIDProvider.SkipReadiness` leaves a provider out — the Kubernetes API server; with a `Key` or `Unverified` there is nothing to wait for. The host wires it to its own health endpoint.

### Internal changes

- Go tests for `Describe` on the cases of nestjs-granted's OpenAPI tests, and for `Ready` (up after a fetch, down when the discovery or the JWK Set fails, `SkipReadiness`, one fetch per cooldown, the context ending the wait). Quarkus tests on a document smallrye-openapi really generates (`/q/openapi`): class and method rules, `**`, `@Authenticated`, `@PermitAll`, `@DenyAll`, a route without rule, the host's own 403 and responses, smallrye's auto-security replaced, `${...}` roles, `deny-unannotated-endpoints`, a custom scheme name and an existing scheme kept.

---

## 5.10.0

### New features

- **Quarkus: the JWK Sets of a cluster's own authorities — `granted.jwt.tls-configuration-name`.** Names a configuration of Quarkus's TLS registry (`quarkus.tls.<name>.*`, e.g. `quarkus.tls.cluster.trust-store.pem.certs=${TLS_CA_FILES}`) that every discovery document and JWK Set is fetched with, the bearer-token provider's included; `discovery-uris[n].tls-configuration-name` gives a provider its own. Unset, nothing changes: the JVM's authorities. The host name is always verified. A name the registry doesn't know stops the start, naming the property; so does a configuration trusting every certificate, unless `quarkus.tls.trust-all` is on — anyone on the path could otherwise serve the keys and sign any token. A failed fetch now says what failed in the log: the HTTP status, a TLS handshake, a timeout, a refused connection.
- **Quarkus: the `granted-jwks` readiness check.** Registered when `quarkus-smallrye-health` is present (`granted.health.enabled=false`, at build time, leaves it out). DOWN while a provider has no key, naming the provider and why — never a token; UP with each provider's number of keys. It asks what a verification asks, through the same cache, TLS configuration, bearer token and cooldown, so probing it never hammers an IdP. `discovery-uris[n].readiness=false` leaves a provider out — the Kubernetes API server, whose outage must not take the pod out of its users' traffic. With a PEM key there is nothing to fetch: UP. It replaces the `JwksReadinessCheck` each service wrote.

### Changes

- **Quarkus: `granted.source=jwt` with nothing to verify the token now stops the start.** No key material (`public-key`, `public-key-file`, `jwks-uri`, `discovery-uris`) and neither quarkus-oidc nor quarkus-smallrye-jwt: the application used to start and treat every caller as anonymous, every protected route answering 401 without a word in the logs.

### Internal changes

- Quarkus tests: an IdP over HTTPS with a certificate of a test authority (BouncyCastle, test scope) — trusted or not, a host name that doesn't match, a provider's own TLS configuration; the readiness check (DOWN, UP, `readiness=false`, one fetch per cooldown however often it is probed); a canopy service's configuration end to end. The extension's own tests (`deployment`, `QuarkusExtensionTest`): what stops the start, the readiness check registered or left out, a parameter type `@GrantedClaim` can't fill failing the build.

---

## 5.9.0

### New features

- **`io.softwarity:quarkus-granted` — granted for Quarkus**, a Quarkus extension on Maven Central (`quarkus-granted` and `quarkus-granted-deployment`), under the same version as the NestJS package and with its behaviour. The caller comes from the gateway's headers (`username`, `roles` as a JSON array or a comma-separated list, `tenant`; names configurable) or, with `granted.source=jwt`, from a JWT. granted verifies it itself with every option of nestjs-granted's `GrantedJwtPrincipalProvider` — `granted.jwt.public-key` / `public-key-file` (ES256 by default, HS* with a shared secret), `jwks-uri` (each key verifies with its own algorithm, never the token's; `algorithm` an allowlist; `none` and HS* refused), `discovery-uris[n]` (OpenID Providers routed by `iss`, with `issuer` + `jwks-uri` given outright, `bearer-token-file`, their own `audience`, and `bypass` patterns of `sub` passing every role check), `jwks-cache-max-age` / `jwks-cooldown` / `jwks-timeout`, `issuer`, `audience` (strings or `/patterns/`), the claim paths and the presets (`rfc9068`, `azure-ad`, `keycloak`, `okta`); an invalid token is an anonymous caller — or reads the token quarkus-oidc / quarkus-smallrye-jwt verified, when no key is configured. Roles go through a transitive hierarchy and an optional `known-roles` filter before `@RolesAllowed` sees them. The caller is injected into resource methods — `@GrantedUsername`, `@GrantedRoles`, `@GrantedTenant`, `@GrantedClaim("territories") List<String>` with the conversion its type asks for and `required = true` answering 403 — or read from the request-scoped `GrantedCaller` elsewhere. Every 403 is logged with the rule spelled as nestjs-granted names it (`hasRole(ADMIN) not met by 'bob' (roles: USER)`); the response stays bare unless `granted.access-denied.details=true`. See [quarkus/README.md](./quarkus/README.md).
- **`github.com/softwarity/granted/go/v5` — granted for Go.** Plain `net/http`: `g.Middleware(mux)` reads the caller, `g.Require(granted.HasRole("ADMIN"))(handler)` checks a route, with the specs of nestjs-granted (`HasRole`, `IsAuthenticated`, `IsUser`, `IsTenant`, `HasClaim`, `And` / `Or` / `Not`), its role hierarchy and known roles. Handlers read the caller from the request context: `granted.Username(ctx)`, `Roles(ctx)`, `Tenant(ctx)`, and any claim, typed — `granted.Claims[string](ctx, "territories")`. The caller comes from the gateway's headers (roles as a JSON array or a comma-separated list, detected), or from a JWT verified with every option of the NestJS provider: PEM key, JWK Set, several OpenID Providers by their discovery document (bearer token file, own audience, `sub` bypass), issuer and audience, cache / cooldown / timeout of the fetches. A JWK Set key verifies with its own algorithm, never the one the token announces. A refusal is a bare 403, its reason logged through `log/slog`. Released with the other packages: the module is tagged `go/vX.Y.Z` on the same commit as `vX.Y.Z`. See [go/README.md](./go/README.md).

### Changes

- **NestJS: `@Claim` is renamed `@GrantedClaim`**, and `ClaimOptions` `GrantedClaimOptions` — the name the Quarkus extension uses too, where `@Claim` is MicroProfile JWT's. Same behaviour. `@Claim` and `ClaimOptions` stay exported, deprecated, until the next major version.
- **NestJS: the roles header's encoding is detected.** With `rolesFormat` unset, a value starting with `[` is read as a JSON array, anything else as a comma-separated list — as the Quarkus and Go implementations do. Before, an unset `rolesFormat` meant JSON only, and a comma-separated value made `JSON.parse` throw. `rolesFormat: 'json'` or `'csv'` still forces one. Malformed JSON now gives no role, with a warning that never shows the value, instead of failing the request.
- **NestJS: the published typings keep their documentation.** The build stripped every comment, JSDoc included: an IDE showed no description of an option, and couldn't flag a deprecated name. It now keeps them.

### Bug fixes

- **NestJS: roles carried as a string in a JWT are split, never spread into characters.** A `roles` claim holding `"ADMIN,USER"` — or just `"ADMIN"` — was turned into a set of its characters (`A`, `D`, `M`…): a rule on a one-letter role passed for the wrong caller, and the real roles were lost. A string is now read as a comma-separated list (or a JSON array), only the strings of a list are kept, and anything else gives no role.

### Internal changes

- **The repository moved to [`softwarity/granted`](https://github.com/softwarity/granted)**, which hosts the Quarkus and Go implementations next to this one. Nothing changes for an application: the package is still `@softwarity/nestjs-granted`, its API is the same. The library now lives in `packages/nestjs/`, with its whole history, in an npm workspace; the doc site moves to [softwarity.github.io/granted](https://softwarity.github.io/granted/). Every package of the repository will carry the same version.
- The release run publishes the Quarkus extension to Maven Central before the npm package (`scripts/publish.sh`), after checking the Central token and the signing key; `scripts/version-all.mjs` writes the version into every pom of `quarkus/`. The unit-test workflow gets a Quarkus job (`./mvnw verify`, 107 tests): the claim rules, the role hierarchy and the JWT verifier case by case against nestjs-granted's specs with a local OpenID Provider (`runtime`); headers and smallrye-jwt modes, the injected parameters (`integration-tests`); granted's own verification end to end — discovery, a bearer-token provider, bypass, PEM (`integration-tests-jwt`). The two test applications are never published.
- The release run tests the Go module (`go vet`, `go test -race`) and tags it `go/vX.Y.Z` on the release commit; `scripts/version-all.mjs` keeps the module path's major version (`…/go/v5`) in step with the release. The unit-test workflow gets a Go job.
- NestJS: new `test/roles-format.spec.ts` suite (roles as a string, a list, a JSON array or a comma-separated list, malformed JSON); `test/claim.spec.ts` becomes `test/granted-claim.spec.ts`, and checks the deprecated `@Claim` still works.
- Docs: the site covers the three implementations — an overview with the same route in NestJS, Quarkus and Go, then a page for each.
- Publication now happens inside the release run, through release-flow's `publish` step (`scripts/publish.sh`), before anything is pushed: a refused `npm publish` leaves no tag, no GitHub Release and no commit behind. The separate tag-triggered workflow is gone.

---

## 5.8.0

### New features

- **`@Claim(name, options?)` — any other attribute of the caller, injected into a handler.** Roles decide which actions a caller may take; claims scope which data. `list(@Claim('territories', { type: 'string', array: true }) territories: string[])` gives the territories a tenant may touch, ready for a `WHERE territory IN (...)`. The value is read through the principal provider, like `@Username()`: a claim of the verified JWT with `GrantedJwtPrincipalProvider` (dotted paths for nested claims, e.g. `'realm_access.territories'`) — never a header of the same name —, the header of that name with `GrantedPrincipalProvider`. Options: `type` (`'string' | 'number' | 'boolean'`, of each element with `array`), `array` (a single value is taken as a list of one) and `required` (403 when missing or invalid). A string value is parsed: with `array`, a JSON array or a comma-separated list; `number` and `boolean` convert strictly. A missing value gives `undefined`, or `[]` with `array`; a value of the wrong type is treated as missing, with a warning naming the claim but never its value; in a list, only the elements of the wrong type are dropped (`['FR', 42, 'GP']` gives `['FR', 'GP']`), and a list left empty counts as missing. A number or a boolean given as a string converts. Without options, the value is given as found. New exported type `ClaimOptions`.
- **New optional method `getClaimFromIncomingMessage(msg, name)` on `IGrantedPrincipalProvider`**, used by `@Claim`; both built-in providers implement it. Existing custom providers keep compiling and working; only a route using `@Claim` needs it, and fails with an error naming the method when it's missing.

### Internal changes

- New `test/claim.spec.ts` suite, end to end through a controller: JWT (dotted path, lists, numbers, booleans, single value as a list, failed verification, header of the same name ignored), JWKS after `prepare()`, gateway headers (JSON and CSV lists, strict conversions, malformed JSON, empty header), wrong types and their warning, `required`, a provider without the method.
- Docs (README and site): `@Claim` on *Read the caller*, the method on *Your own provider*.

---

## 5.7.0

### New features

- **The roles of `@GrantedTo` appear in the OpenAPI document.** With `@nestjs/swagger`, each protected route gets a `security`: one entry per alternative (`or`), listing the roles it requires (`and`) — `or(hasRole('ADMIN'), and(hasRole('MANAGER'), hasRole('AUDIT')))` → `[{ bearer: [ADMIN] }, { bearer: [MANAGER, AUDIT] }]`. Controller and route rules are merged; a branch without a role gives `bearer: []`, `isTrue()` gives `{}`. Each route also gets a `403` response describing the rule in clear — `Forbidden unless: hasRole(ADMIN) or isUser(Param, id)` —, unless the host declared its own; the default `200`/`201` (or the `@HttpCode()`) is kept. Nothing to add on the host side, and no dependency on `@nestjs/swagger`. New option `openApiSecurityScheme` (default `'bearer'`, the name `addBearerAuth()` gives).

### Internal changes

- `security/openapi.ts`: each built-in spec records its role alternatives and its label; `@GrantedTo` registers the routes and `GrantedModule`, once instantiated, writes the `swagger/apiSecurity` and `swagger/apiResponse` metadata of each one, class and method merged. `@nestjs/swagger` added as a devDependency, for the test that generates a real document.

---

## 5.6.0

### New features

- **A `discoveryUris` entry can give its issuer and JWK Set outright: `{ issuer, jwksUri, bearerTokenFile?, audience?, bypass? }`.** No discovery document is read for it. The Kubernetes API server's document announces its internal control-plane address as `jwks_uri` (e.g. `https://172.20.0.3:6443/openid/v1/jwks`), out of reach of a process run outside the cluster — a service under a dev tunnel got every service account token rejected — while `https://kubernetes.default.svc/openid/v1/jwks` serves the same keys. `bearerTokenFile`, `audience` and `bypass` apply as with a discovered entry, and tokens are routed by that issuer. `issuer` and `jwksUri` go together or not at all; `uri` is then optional.

### Internal changes

- `granted-info.jwt-provider.ts`: `OpenIdProvider.uri` optional, `issuer` / `jwksUri` added; such an entry becomes a plain `JwksSource` carrying its token file, audience and bypass.
- `test/jwks.spec.ts`: no document read, token sent to the given JWK Set only, bypass kept and limited to its tokens, routing by the given issuer, its own audience, issuer and jwksUri required together.

---

## 5.5.0

### New features

- **Service-to-service in Kubernetes: `bypass`.** A `discoveryUris` entry can now be an object, `{ uri, bearerTokenFile?, audience?, bypass? }`. A verified token from that IdP whose `sub` matches a `bypass` pattern (`*` = anything) passes every `@GrantedTo`. With `{ uri: 'https://kubernetes.default.svc', bearerTokenFile: '/var/run/secrets/kubernetes.io/serviceaccount/token', bypass: ['system:serviceaccount:my-namespace:*'] }`, the services of the `my-namespace` namespace call each other with their pod's service account token and get through, while users keep being checked as usual. A service account outside the patterns is checked like anyone: authenticated, without any role. `@Username()` gives the service account's `sub`, even with a preset reading another claim.
- **`bearerTokenFile`: an IdP that wants a token to serve its keys.** The Kubernetes API server answers 403 to anonymous requests for its discovery document and JWKS. The file's content is sent as `Authorization: Bearer` to that IdP's document and to the `jwks_uri` it announces — never to another IdP — and re-read at every fetch, so a token rotated by the kubelet is picked up. A missing file fails that IdP alone, with a warning.
- **HTTPS with a private CA is up to the host app.** For the Kubernetes API server, whose certificate the cluster CA signs: `NODE_EXTRA_CA_CERTS=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`.
- **An audience per IdP**: `{ uri, audience }` replaces the global `audience` for that IdP's tokens.
- **`IGrantedPrincipalProvider.isBypassed?(request)`**: a custom provider can let a principal through every `@GrantedTo` too.

### Internal changes

- `granted-info.jwt-provider.ts`: `OpenIdProvider`, `JwtAudience`. Each source carries its issuer, audience and bypass; a payload is flagged as bypassing only once verified by its own source. `app.guard.ts` returns `true` before evaluating the specs when `isBypassed` says so.
- `test/jwks.spec.ts`: the token reaches its IdP's document and keys only, a rotated file is re-read, a missing file fails that IdP alone; bypass on matching `sub` only, from its own IdP only, never on an unverified, expired or unsigned token; audience per entry. `test/guard.spec.ts`: a bypassing principal passes every spec.
- Docs (README and site) rewritten around use cases: *Getting started*, *Protect your routes* (with ownership, the rules and the 403 details), *Read the caller*, *Where the identity comes from* (headers, a JWT — key file, JWKS URL, several IdPs, the services of a cluster —, your own provider), *Roles*, *Options reference*. The site's former *Resource ownership*, *Boolean specifications* and *Configuration* pages redirect to the new ones.

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
