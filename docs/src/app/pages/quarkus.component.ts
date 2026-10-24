import { Component } from '@angular/core';
import { CodeComponent } from '../code/code.component';

@Component({
  selector: 'app-quarkus',
  imports: [CodeComponent],
  template: `
    <h2>Quarkus</h2>
    <div class="callout">Published with the next release of granted, alongside the NestJS package.</div>
    <p>
      <strong>io.softwarity:quarkus-granted</strong> is a Quarkus extension with the behaviour of nestjs-granted:
      the caller from the gateway's headers or from a JWT — verified by granted itself, or by quarkus-oidc /
      quarkus-smallrye-jwt — its roles shaped by a hierarchy, injected into your resource methods, every refusal
      explained in the log. The rules are the ones Quarkus already has — <code>&#64;RolesAllowed</code>,
      <code>&#64;Authenticated</code>, <code>&#64;PermitAll</code>, <code>&#64;DenyAll</code>.
    </p>

    <h3>Install</h3>
    <app-code lang="xml">&lt;dependency&gt;
    &lt;groupId&gt;io.softwarity&lt;/groupId&gt;
    &lt;artifactId&gt;quarkus-granted&lt;/artifactId&gt;
    &lt;version&gt;5.8.0&lt;/version&gt;
&lt;/dependency&gt;</app-code>
    <p>Quarkus 3.40, Java 21. Quarkus picks up <code>quarkus-granted-deployment</code> by itself.</p>

    <h3>Read the caller</h3>
    <app-code lang="java">&#64;GET
&#64;RolesAllowed("FORECASTER")
public List&lt;Station&gt; list(&#64;GrantedClaim("territories") List&lt;String&gt; territories) &#123;
    return Station.list("territory in ?1", territories);
&#125;

&#64;GET
&#64;Path("/me")
public Me me(&#64;GrantedUsername String username, &#64;GrantedRoles Set&lt;String&gt; roles, &#64;GrantedTenant String tenant) &#123;
    return new Me(username, roles, tenant);
&#125;</app-code>
    <table>
      <thead><tr><th>Parameter</th><th>Type</th><th>When the caller has none</th></tr></thead>
      <tbody>
        <tr><td><code>&#64;GrantedUsername</code></td><td><code>String</code></td><td><code>"anonymous"</code></td></tr>
        <tr><td><code>&#64;GrantedRoles</code></td><td><code>Set&lt;String&gt;</code> or <code>List&lt;String&gt;</code> — after the hierarchy and <code>known-roles</code></td><td>empty</td></tr>
        <tr><td><code>&#64;GrantedTenant</code></td><td><code>String</code></td><td><code>null</code></td></tr>
        <tr><td><code>&#64;GrantedClaim("name")</code></td><td><code>String</code>, <code>Integer</code>, <code>Long</code>, <code>Double</code>, <code>Boolean</code>, <code>Object</code>, or a <code>List</code> / <code>Set</code> of one of them</td><td><code>null</code>, or an empty list</td></tr>
        <tr><td><code>&#64;GrantedClaim(value = "name", required = true)</code></td><td>the same — a primitive (<code>int</code>, <code>long</code>…) needs <code>required</code></td><td>a <code>403</code></td></tr>
      </tbody>
    </table>
    <p>
      Read for each request, never captured. A parameter of a type the annotation can't fill fails the build.
      Claims follow the rules of nestjs-granted's <code>&#64;GrantedClaim</code>: a list is a JSON array or a
      comma-separated list, a number or a boolean given as a string converts, a value of the wrong type is treated
      as missing — in a list, only the elements of the wrong type are dropped — with a warning that never shows the
      value. Outside a resource, inject the request-scoped <code>GrantedCaller</code>:
    </p>
    <app-code lang="java">&#64;Inject
GrantedCaller caller;

List&lt;String&gt; territories = caller.claims("territories", String.class);
String username = caller.username();
Optional&lt;Long&gt; max = caller.claim("maxAmount", Long.class);
List&lt;String&gt; required = caller.requireClaims("territories", String.class); // or a 403</app-code>

    <h3>Where the caller comes from</h3>
    <p>
      <strong>Headers from a gateway</strong> — the default. Nothing to configure when the gateway sends
      <code>username</code>, <code>roles</code> (a JSON array or a comma-separated list) and <code>tenant</code>.
      Nothing is verified: the service must never be reachable except through the gateway.
    </p>
    <app-code lang="properties">granted.headers.username=x-user
granted.headers.roles=x-roles
granted.headers.tenant=x-tenant</app-code>
    <p>
      <strong>A JWT verified by granted</strong> — <code>granted.source=jwt</code> and key material, every option
      of nestjs-granted's JWT provider. A missing or invalid token is an anonymous caller; the algorithm always
      comes from the key, never from the token.
    </p>
    <app-code lang="properties">granted.source=jwt
granted.jwt.preset=keycloak
granted.jwt.public-key-file=config/jwt_public_key.pem   # ES256 by default
# or: granted.jwt.jwks-uri=https://sso.example.com/realms/acme/protocol/openid-connect/certs
# or several OpenID Providers, routed by the token's iss:
granted.jwt.discovery-uris[0].uri=https://gateway.example.com
granted.jwt.discovery-uris[1].issuer=https://kubernetes.default.svc.cluster.local
granted.jwt.discovery-uris[1].jwks-uri=https://kubernetes.default.svc/openid/v1/jwks
granted.jwt.discovery-uris[1].bearer-token-file=/var/run/secrets/kubernetes.io/serviceaccount/token
granted.jwt.discovery-uris[1].bypass=system:serviceaccount:my-namespace:*</app-code>
    <p>
      <strong>A JWT verified by quarkus-oidc or quarkus-smallrye-jwt</strong> — <code>granted.source=jwt</code>
      without key material: granted reads the token the extension verified, with the same claim mapping.
    </p>

    <h3>Roles</h3>
    <app-code lang="properties">granted.role-hierarchy.ADMIN=MANAGER
granted.role-hierarchy.MANAGER=USER
granted.known-roles=ADMIN,MANAGER,USER</app-code>

    <h3>Why did a request get a 403?</h3>
    <p>Every refusal is logged at <code>WARN</code>, the rule spelled as nestjs-granted names it:</p>
    <app-code lang="text">GET /stations denied: hasRole(FORECASTER) not met by 'bob' (roles: USER; tenant: acme)</app-code>
    <p>
      The caller gets the bare <code>&#123;"statusCode":403,"error":"Forbidden","message":"Forbidden resource"&#125;</code>,
      unless <code>granted.access-denied.details=true</code>. An anonymous caller on a protected route gets a
      <code>401</code>.
    </p>

    <h3>Options</h3>
    <table>
      <thead><tr><th>Property</th><th>Default</th><th>Notes</th></tr></thead>
      <tbody>
        <tr><td><code>granted.source</code></td><td><code>headers</code></td><td><code>headers</code> or <code>jwt</code></td></tr>
        <tr><td><code>granted.headers.username</code> / <code>.roles</code> / <code>.tenant</code></td><td><code>username</code> / <code>roles</code> / <code>tenant</code></td><td>Header names</td></tr>
        <tr><td><code>granted.jwt.preset</code></td><td>—</td><td><code>rfc9068</code>, <code>azure-ad</code>, <code>keycloak</code>, <code>okta</code></td></tr>
        <tr><td><code>granted.jwt.username-claim</code> / <code>.roles-claim</code> / <code>.tenant-claim</code></td><td><code>sub</code> / <code>roles</code> / <code>tenant</code>, or the preset's</td><td>Dotted paths allowed</td></tr>
        <tr><td><code>granted.jwt.public-key</code> / <code>.public-key-file</code></td><td>—</td><td>PEM public key or certificate; with HS*, the shared secret</td></tr>
        <tr><td><code>granted.jwt.algorithm</code></td><td><code>ES256</code> with a PEM key</td><td>A list; with a JWK Set, an allowlist (no <code>none</code>, no HS*)</td></tr>
        <tr><td><code>granted.jwt.jwks-uri</code></td><td>—</td><td>The issuer's JWK Set</td></tr>
        <tr><td><code>granted.jwt.discovery-uris[n].uri</code></td><td>—</td><td>Discovery document, or the URL it lives under</td></tr>
        <tr><td><code>granted.jwt.discovery-uris[n].issuer</code> + <code>.jwks-uri</code></td><td>—</td><td>Instead of <code>uri</code>: given outright</td></tr>
        <tr><td><code>granted.jwt.discovery-uris[n].bearer-token-file</code></td><td>—</td><td>Sent to this provider only, read at every fetch</td></tr>
        <tr><td><code>granted.jwt.discovery-uris[n].audience</code></td><td><code>granted.jwt.audience</code></td><td>This provider's accepted <code>aud</code></td></tr>
        <tr><td><code>granted.jwt.discovery-uris[n].bypass</code></td><td>—</td><td><code>sub</code> patterns passing every role check</td></tr>
        <tr><td><code>granted.jwt.jwks-cache-max-age</code> / <code>.jwks-cooldown</code> / <code>.jwks-timeout</code></td><td><code>10M</code> / <code>30S</code> / <code>5S</code></td><td>JWK Set and discovery document fetches</td></tr>
        <tr><td><code>granted.jwt.issuer</code> / <code>.audience</code></td><td>—</td><td>Accepted <code>iss</code> / <code>aud</code>; <code>/pattern/</code> for an audience regex</td></tr>
        <tr><td><code>granted.role-hierarchy.&lt;ROLE&gt;</code></td><td>—</td><td>The roles it implies</td></tr>
        <tr><td><code>granted.known-roles</code></td><td>— (every role kept)</td><td>The roles this service knows</td></tr>
        <tr><td><code>granted.access-denied.details</code></td><td><code>false</code></td><td>The reason of a 403 in the response too</td></tr>
      </tbody>
    </table>
  `,
})
export class QuarkusComponent {}
