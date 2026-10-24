# granted (Quarkus)

Route-level authorization for a Quarkus service behind a gateway or an identity provider — the behaviour of [`@softwarity/nestjs-granted`](../packages/nestjs), so a NestJS and a Quarkus service on the same version read the same caller and decide the same way. The caller comes from the gateway's headers or from a JWT, verified by granted itself (PEM key, JWK Set, OpenID discovery) or by quarkus-oidc / quarkus-smallrye-jwt; its roles are shaped by a hierarchy; it is injected into your resource methods; every 403 is explained in the log.

```xml
<dependency>
    <groupId>io.softwarity</groupId>
    <artifactId>quarkus-granted</artifactId>
    <version>5.8.0</version>
</dependency>
```

A Quarkus extension (`quarkus-granted`, and `quarkus-granted-deployment` which Quarkus picks up by itself). It brings `quarkus-rest` and `quarkus-security`. Built against Quarkus 3.40, Java 21.

The rules are the ones Quarkus already has — `@RolesAllowed`, `@Authenticated`, `@PermitAll`, `@DenyAll`. granted decides who the caller is and which roles they are judged on.

## Read the caller

```java
@Path("/stations")
public class StationResource {

    @GET
    @RolesAllowed("FORECASTER")
    public List<Station> list(@GrantedClaim("territories") List<String> territories) {
        // Roles decide which actions a caller may take; claims scope which data.
        return Station.list("territory in ?1", territories);
    }

    @GET
    @Path("/me")
    public Me me(@GrantedUsername String username, @GrantedRoles Set<String> roles, @GrantedTenant String tenant) {
        return new Me(username, roles, tenant);
    }
}
```

| Parameter | Type | When the caller has none |
|---|---|---|
| `@GrantedUsername` | `String` | `"anonymous"` |
| `@GrantedRoles` | `Set<String>` or `List<String>` — the roles the rules see, after the hierarchy and `known-roles` | empty |
| `@GrantedTenant` | `String` | `null` |
| `@GrantedClaim("name")` | `String`, `Integer`, `Long`, `Double`, `Boolean`, `Object` (as found), or a `List` / `Set` of one of them | `null`, or an empty list |
| `@GrantedClaim(value = "name", required = true)` | the same — a primitive (`int`, `long`…) needs `required` | a `403` |

The value is read for each request, never captured: a resource is a singleton. A parameter of a type the annotation can't fill fails the build, naming the annotation and the type.

A claim is read where the rest of the identity comes from: a claim of the **verified** token (dotted paths for nested claims, e.g. `realm_access.territories`), or the header of that name in headers mode — never from a header when the identity comes from a JWT.

- **Strings are parsed.** A list is a JSON array (`["FR","GP"]`) or a comma-separated list (`FR, GP`); a single value is a list of one. A number or a boolean given as a string (`"5000"`, `"true"`) converts.
- **The wrong type** — a number where strings are expected, a list where one value is — is treated as missing, with a warning naming the claim, never its value. In a list, only the elements of the wrong type are dropped (`["FR", 42, "GP"]` gives `["FR", "GP"]`); a list left empty counts as missing.

### Outside a resource — `GrantedCaller`

The same values, for a service called by the resource:

```java
@Inject
GrantedCaller caller;

List<String> territories = caller.claims("territories", String.class);
String username = caller.username();            // "anonymous" without a caller
Set<String> roles = caller.roles();
Optional<String> tenant = caller.tenant();
Optional<Long> max = caller.claim("maxAmount", Long.class);
List<String> required = caller.requireClaims("territories", String.class); // or a 403
```

`GrantedCaller` is request-scoped: each call reads the request being served.

## Where the caller comes from

### Headers from a gateway — the default

Nothing to configure when the gateway sends `username`, `roles` (a JSON array or a comma-separated list, both read) and `tenant`. Other names:

```properties
granted.headers.username=x-user
granted.headers.roles=x-roles
granted.headers.tenant=x-tenant
```

A request without the username header is anonymous. Nothing is verified here: the service must never be reachable except through the gateway.

### A JWT, verified by granted

`granted.source=jwt` and key material: granted verifies `Authorization: Bearer <token>` itself, the way nestjs-granted does — no quarkus-oidc or smallrye-jwt needed (leave them out: two mechanisms would compete for the same header). A missing, malformed or invalid token gives an **anonymous** caller, never a 401 of its own: the rules decide. The token and the keys are never logged.

```properties
granted.source=jwt
granted.jwt.preset=keycloak

# A PEM key - ES256 by default:
granted.jwt.public-key-file=config/jwt_public_key.pem
# or the issuer's JWK Set - each key verifies with its own algorithm:
granted.jwt.jwks-uri=https://sso.example.com/realms/acme/protocol/openid-connect/certs
```

- **The algorithm comes from the key, never from the token.** With a JWK Set, the key picked by the token's `kid` verifies with the `alg` the set declares for it — RS256 / RS384 / RS512, PS256 / PS384 / PS512, ES256 / ES384 / ES512 or EdDSA; a key without `alg` gets the one its type implies. A token announcing another algorithm is refused: no `alg: none`, no RSA/HMAC confusion. `granted.jwt.algorithm`, optional, is then an allowlist; `none` and HS* are refused at startup.
- **Rotation without restart.** Keys are fetched on first use and cached; a token signed by an unknown key triggers one re-fetch, never two within `jwks-cooldown`. Older than `jwks-cache-max-age`, the set is re-fetched, so a withdrawn key stops being accepted. A failed fetch keeps the last known keys.

#### Several OpenID Providers — `discovery-uris`

```properties
granted.jwt.discovery-uris[0].uri=https://gateway.example.com
# The Kubernetes API server: issuer and JWK Set given, a bearer token to fetch them,
# and the service accounts of the namespace passing every role check.
granted.jwt.discovery-uris[1].issuer=https://kubernetes.default.svc.cluster.local
granted.jwt.discovery-uris[1].jwks-uri=https://kubernetes.default.svc/openid/v1/jwks
granted.jwt.discovery-uris[1].bearer-token-file=/var/run/secrets/kubernetes.io/serviceaccount/token
granted.jwt.discovery-uris[1].bypass=system:serviceaccount:my-namespace:*
```

Each provider's discovery document gives its issuer and JWK Set. A token is verified only with the keys of the provider whose issuer is its `iss`; any other `iss` is rejected, and no URL is ever taken from the token. A bearer token file goes to that provider only, read again at every fetch. A `bypass` pattern (`*` matches anything) lets that provider's matching tokens pass every role and permission check — named by their `sub` — and no other provider's.

#### Issuer and audience

```properties
granted.jwt.issuer=https://sso.example.com/realms/acme
granted.jwt.audience=orders-api,/^reports-/
```

Not checked when unset. An audience between slashes is a pattern. A discovery provider takes its issuer from its document, and can have its own `audience`.

### A JWT, verified by quarkus-oidc or quarkus-smallrye-jwt

`granted.source=jwt` without key material: add and configure one of them as usual; granted reads the token it verified — the `*-claim` options and the preset apply, and the roles of `roles-claim` are added to those the extension mapped itself.

## Roles

```properties
# ADMIN implies MANAGER, which implies USER: an ADMIN passes @RolesAllowed("USER").
granted.role-hierarchy.ADMIN=MANAGER
granted.role-hierarchy.MANAGER=USER
# Drop every other role - after the hierarchy is expanded - so a token shared with other services doesn't bring theirs.
granted.known-roles=ADMIN,MANAGER,USER
```

## Why did a request get a 403?

Every refusal is logged at `WARN`, with the rule as nestjs-granted names it, the caller, the roles it was judged on and its tenant:

```
GET /stations denied: hasRole(FORECASTER) not met by 'bob' (roles: USER; tenant: acme)
```

The fields go to the MDC for that line (`denied.spec`, `denied.username`, `denied.roles`, `denied.tenant`, `http.request.method`, `url.path`), for a JSON log to carry as attributes. The caller gets nestjs-granted's bare `{"statusCode":403,"error":"Forbidden","message":"Forbidden resource"}`: the details tell an attacker what to forge. Where every caller is trusted, `granted.access-denied.details=true` writes the reason into the response too.

An anonymous caller on a protected route gets a `401`, as Quarkus answers it.

## Options

| Property | Default | |
|---|---|---|
| `granted.source` | `headers` | `headers` or `jwt` |
| `granted.headers.username` / `.roles` / `.tenant` | `username` / `roles` / `tenant` | Header names |
| `granted.jwt.preset` | — | `rfc9068`, `azure-ad`, `keycloak`, `okta`: the claim mapping of that IdP |
| `granted.jwt.username-claim` / `.roles-claim` / `.tenant-claim` | `sub` / `roles` / `tenant`, or the preset's | Claims, dotted paths allowed |
| `granted.jwt.public-key` / `.public-key-file` | — | PEM public key (or certificate); with HS*, `public-key` is the shared secret |
| `granted.jwt.algorithm` | `ES256` with a PEM key; none with a JWK Set | A list. With a JWK Set, an allowlist |
| `granted.jwt.jwks-uri` | — | The issuer's JWK Set |
| `granted.jwt.discovery-uris[n].uri` | — | An OpenID Provider's discovery document, or the URL it lives under |
| `granted.jwt.discovery-uris[n].issuer` + `.jwks-uri` | — | Instead of `uri`: issuer and JWK Set given outright |
| `granted.jwt.discovery-uris[n].bearer-token-file` | — | Token sent to this provider only, read at every fetch |
| `granted.jwt.discovery-uris[n].audience` | `granted.jwt.audience` | This provider's accepted `aud` |
| `granted.jwt.discovery-uris[n].bypass` | — | `sub` patterns of this provider passing every role check |
| `granted.jwt.jwks-cache-max-age` | `10M` | Keys and documents older than this are re-fetched |
| `granted.jwt.jwks-cooldown` | `30S` | Minimum delay between two fetches |
| `granted.jwt.jwks-timeout` | `5S` | Timeout of a fetch |
| `granted.jwt.issuer` | — | Accepted `iss` (a list) |
| `granted.jwt.audience` | — | Accepted `aud` (a list; `/pattern/` for a regex) |
| `granted.role-hierarchy.<ROLE>` | — | The roles `<ROLE>` implies |
| `granted.known-roles` | — (every role kept) | The roles this service knows |
| `granted.access-denied.details` | `false` | The reason of a 403 in the response too |

A configuration that could only look secure — an issuer without a key, a JWK Set with HS256, `discovery-uris` with a PEM key — stops the application at startup.
