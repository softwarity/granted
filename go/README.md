# granted (Go)

**Decide, route by route, who may call your Go service.** Wrap a handler with
`Require(...)`: only the callers satisfying every spec reach it, the others get
a `403`. Handlers read the caller from the request's context —
`granted.Username(ctx)`, `Roles(ctx)`, `Tenant(ctx)`, and any other claim with
`granted.Claims[string](ctx, "territories")`.

It doesn't log anyone in: something in front of your service — a gateway, an
identity provider — has authenticated the caller and passes the identity on, as
HTTP headers or as a signed JWT. The NestJS and Quarkus implementations of
[granted](https://github.com/softwarity/granted) read the caller and decide the
same way.

```bash
go get github.com/softwarity/granted/go/v5
```

There is no registry to publish to: the import path is the repository, and a
version is a git tag. `go/vX.Y.Z` is what this module is fetched under; the npm
and Maven packages carry `vX.Y.Z` for the same release. The path ends with the
major version, as Go requires from v2 on: `/v5` for every 5.x.

Plain `net/http`: a middleware is a `func(http.Handler) http.Handler`, so it fits
the standard mux, chi, and anything that takes one.

## Getting started

```go
import granted "github.com/softwarity/granted/go/v5"

g := granted.New(granted.Options{}) // the caller from the username, roles and tenant headers

mux := http.NewServeMux()
mux.Handle("GET /reports", g.Require(granted.HasRole("ADMIN"))(reports))
mux.Handle("GET /me", http.HandlerFunc(me)) // no Require: open

http.ListenAndServe(":8080", g.Middleware(mux))
```

`Middleware` reads the caller of every request and puts it in its context.
`Require` checks a route; without the middleware in front, it reads the caller
itself.

## Protect your routes

| Spec | Passes when |
|---|---|
| `HasRole("ADMIN")` | the caller holds the role, after the [hierarchy](#roles) |
| `IsAuthenticated()` | something identified the caller |
| `IsUser(granted.Param, "id")` | the request names the caller: `PATCH /users/{id}` |
| `IsTenant(granted.Param, "tenant")` | the request names the caller's tenant; a caller without one is refused |
| `HasClaim[int]("maxAmount")`, `HasClaims[string]("territories")` | the caller has the claim, of that type |
| `And(...)`, `Or(...)`, `Not(...)`, `IsTrue()`, `IsFalse()` | they combine |

`IsUser` and `IsTenant` read a path parameter (`granted.Param`, through
`r.PathValue`), a query parameter (`granted.Query`) or a field of a JSON body by
dotted path (`granted.Body`, `"customer.id"` — the handler still reads the body
whole).

```go
mux.Handle("GET /orders/{userId}", g.Require(granted.Or(granted.HasRole("ADMIN"), granted.IsUser(granted.Param, "userId")))(orders))
```

A spec is a plain struct — write your own:

```go
func HasScope(scope string) granted.Spec {
	return granted.Spec{
		ID: "hasScope(" + scope + ")", // named in the refusal
		Check: func(r *http.Request, c *granted.Caller) bool {
			return slices.Contains(granted.Claims[string](r.Context(), "scope"), scope)
		},
	}
}
```

### Why did a request get a 403?

The caller gets a bare `403` — `{"statusCode":403,"message":"Forbidden resource","error":"Forbidden"}` —
with nothing about your rules. The reason is logged through `log/slog`, with its
fields (`denied.spec`, `denied.username`, `denied.roles`, `denied.tenant`):

```
GET /reports denied: hasRole(ADMIN) not met by 'bob' (roles: USER; tenant: acme)
```

`Options.OnDenied` writes the refusal your way; the reason is logged first either way.

## Read the caller

```go
func me(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	json.NewEncoder(w).Encode(map[string]any{
		"username": granted.Username(ctx), // "anonymous" when nothing identified the caller
		"roles":    granted.Roles(ctx),    // after the hierarchy and the known roles
		"tenant":   granted.Tenant(ctx),   // "" when the caller has none
	})
}
```

### Any other claim

Roles decide *which actions* a caller may take; claims scope *which data*. When
a tenant manages several territories and may only touch those, read them — from
the token, or from the gateway's headers — and filter by them:

```go
mux.Handle("GET /stations", g.Require(granted.HasRole("FORECASTER"))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	territories := granted.Claims[string](r.Context(), "territories")
	rows, err := db.Query(r.Context(), "SELECT * FROM stations WHERE territory = ANY($1)", territories)
	…
})))
```

The value comes from the same place as the rest of the identity: a claim of the
**verified** JWT (dotted paths for nested claims, e.g. `realm_access.territories`),
or the header of that name with the header provider — never from a header when
the identity comes from a JWT.

| Function | Gives |
|---|---|
| `Claims[T](ctx, name)` | a list — empty, never nil, when missing |
| `Claim[T](ctx, name)` | one value, and whether it was there with that type |
| `RawClaim(ctx, name)` | the value as found |

`T` is `string`, `bool`, `int`, `int64` or `float64`.

- **Strings are parsed.** Headers only carry strings: a list is a JSON array (`["FR","GP"]`) or a comma-separated list (`FR, GP`); numbers and booleans convert strictly (`"5000"`, `"true"` / `"false"`). A string claim of a JWT is parsed the same way. A single value is a list of one.
- **The wrong type** — a number where strings are expected, a list where one value is — reads as missing, with a warning naming the claim, never its value. In a list, only the elements of the wrong type are dropped (`["FR", 42, "GP"]` gives `["FR", "GP"]`), with a warning too.
- **Required?** Put `HasClaims[string]("territories")` in the route's `Require`: a caller without it gets a `403`.

## Where the identity comes from

### Headers from a gateway — the default

Nothing to configure when your gateway sends `username`, `roles` and `tenant`.
The roles header is a JSON array when it starts with `[`, a comma-separated list
otherwise. Other names:

```go
granted.New(granted.Options{Provider: granted.HeaderProvider{UsernameHeader: "X-User", RolesHeader: "X-Roles", TenantHeader: "X-Tenant"}})
```

Nothing is verified: the service must only be reachable through the gateway,
which must strip these headers from inbound requests.

### A JWT

```go
provider, err := granted.NewJWTProvider(granted.JWTConfig{
	Claims:  granted.Keycloak,
	JWKSURI: "https://sso.example.com/realms/acme/protocol/openid-connect/certs",
})
g := granted.New(granted.Options{Provider: provider})
```

Reads `Authorization: Bearer <token>`. A token that is missing, malformed or
fails verification gives an **anonymous** caller — never an error; your specs
refuse it. The token is never logged. The identity headers are never read.

| Key material | |
|---|---|
| `Key` / `KeyFile` | a PEM public key — `ES256` by default, `Algorithms` to change it; or, with `HS*` algorithms, a shared secret |
| `JWKSURI` | the identity provider's JWK Set: fetched on first use, cached, re-fetched when a token is signed by a key rotated in since |
| `DiscoveryURIs` | OpenID Providers: each by its discovery document, or by its issuer and JWK Set given outright |

**With a JWK Set, no algorithm to configure.** Each key verifies with the
algorithm the set declares for it (its `alg`): RS256/384/512, PS256/384/512,
ES256/384/512 or EdDSA. A key published without `alg` gets the one its type
implies. The algorithm never comes from the token: a token whose `alg` header
differs from its key's is refused, which rules out `alg: none` and RSA/HMAC
confusion. `Algorithms`, when set, is an allowlist; `none` and `HS*` are refused
at construction.

| Option | Default | |
|---|---|---|
| `Claims` | `sub`, `roles`, `tenant` | presets `RFC9068`, `AzureAD`, `Keycloak`, `Okta`; dotted paths allowed |
| `Issuer` | not checked | accepted `iss` |
| `Audience` | not checked | accepted `aud`: `Values` and/or `Patterns` |
| `JWKSCacheMaxAge` | 10 min | keys older than this are re-fetched, so a withdrawn key stops being accepted |
| `Cooldown` | 30 s | never two fetches closer than this, so forged `kid`s can't hammer the identity provider |
| `Timeout` | 5 s | of a fetch |

A failed fetch keeps the last known keys and logs a warning. Concurrent requests
share one fetch.

#### Several identity providers, and the services of your cluster

```go
granted.NewJWTProvider(granted.JWTConfig{
	DiscoveryURIs: []granted.OpenIDProvider{
		{URI: "http://meerkat.gateway"}, // /.well-known/openid-configuration is appended
		{
			Issuer:          "https://kubernetes.default.svc.cluster.local",
			JWKSURI:         "https://kubernetes.default.svc/openid/v1/jwks",
			BearerTokenFile: "/var/run/secrets/kubernetes.io/serviceaccount/token",
			Bypass:          []string{"system:serviceaccount:my-namespace:*"},
		},
	},
})
```

A token is verified only with the keys of the provider whose issuer is its
`iss`; no URL is ever taken from the token. A provider's `Bypass` lists the
`sub` patterns whose tokens — from that provider only — pass every `Require`:
the services of your namespace call each other with their pod's token.

### Your own provider

```go
granted.New(granted.Options{Provider: granted.ProviderFunc(func(r *http.Request) granted.Principal {
	session := sessions.Get(r)
	return granted.Principal{Username: session.User, Roles: session.Roles, Claim: session.Attribute}
})})
```

## Roles

```go
granted.New(granted.Options{
	RoleHierarchy: map[string][]string{"ADMIN": {"MANAGER"}, "MANAGER": {"USER"}}, // transitive
	KnownRoles:    []string{"ADMIN", "MANAGER", "USER"},                          // drop the roles meant for other services
})
```

The hierarchy is expanded first, then the unknown roles are dropped. `Roles(ctx)`
gives the roles the specs saw. `Options.Disabled` lets every request through
while still reading the caller — for a local profile.
