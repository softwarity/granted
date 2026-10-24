import { Component } from '@angular/core';
import { RouterLink } from '@angular/router';
import { CodeComponent } from '../code/code.component';

@Component({
  selector: 'app-quarkus',
  imports: [CodeComponent, RouterLink],
  template: `
    <h2>Quarkus</h2>
    <div class="callout">Published with the next release of granted, alongside the NestJS package.</div>
    <p>
      <strong>io.softwarity:quarkus-granted</strong> is a Quarkus extension. It reads the caller the way
      nestjs-granted does — from the gateway's headers or from a verified JWT, with the same options — shapes its
      roles with a hierarchy, explains every refusal in the log, and hands your resources the caller as method
      parameters. The rules are the ones Quarkus already has: <code>&#64;RolesAllowed</code>,
      <code>&#64;Authenticated</code>, <code>&#64;PermitAll</code>, <code>&#64;DenyAll</code>.
    </p>

    <h3>Install</h3>
    <app-code lang="xml">&lt;dependency&gt;
    &lt;groupId&gt;io.softwarity&lt;/groupId&gt;
    &lt;artifactId&gt;quarkus-granted&lt;/artifactId&gt;
    &lt;version&gt;&lt;!-- the version of every granted package --&gt;&lt;/version&gt;
&lt;/dependency&gt;</app-code>
    <p>
      Quarkus 3.40, Java 21. Its version is the one every granted package carries.
    </p>

    <h3>Read the caller</h3>
    <app-code lang="java">&#64;Path("/stations")
public class StationResource &#123;

    &#64;GET
    &#64;RolesAllowed("FORECASTER")
    public List&lt;Station&gt; list(&#64;GrantedClaim("territories") List&lt;String&gt; territories) &#123;
        return Station.list("territory in ?1", territories);
    &#125;
&#125;</app-code>
    <table>
      <thead><tr><th>Parameter</th><th>Gives</th><th>When the caller has none</th></tr></thead>
      <tbody>
        <tr><td><code>&#64;GrantedUsername String</code></td><td>the username</td><td><code>"anonymous"</code></td></tr>
        <tr><td><code>&#64;GrantedRoles Set&lt;String&gt;</code></td><td>the roles the rules see, after the hierarchy and <code>known-roles</code></td><td>empty</td></tr>
        <tr><td><code>&#64;GrantedTenant String</code></td><td>the tenant</td><td><code>null</code></td></tr>
        <tr><td><code>&#64;GrantedClaim("name") T</code></td><td>any other attribute, converted to the parameter's type — <code>String</code>, <code>Integer</code>, <code>Long</code>, <code>Boolean</code>, or a <code>List</code> of them</td><td><code>null</code>, or an empty list</td></tr>
      </tbody>
    </table>
    <p>
      Each parameter is read from the request being served — the resource is a singleton, nothing is kept from
      one call to the next. With a JWT, a claim comes from the <strong>verified</strong> token, never from a
      header. Claims follow the rules of nestjs-granted's
      <a routerLink="/nestjs/parameter-decorators"><code>&#64;GrantedClaim</code></a>: a list is a JSON array or a
      comma-separated list, a number or a boolean given as a string converts, a value of the wrong type is treated
      as missing — in a list, only the elements of the wrong type are dropped — with a warning that never shows
      the value. <code>&#64;GrantedClaim(value = "territories", required = true)</code> answers <code>403</code>
      when it is missing.
    </p>
    <p>Outside a resource — in a service — inject the request-scoped <code>GrantedCaller</code>:</p>
    <app-code lang="java">&#64;Inject
GrantedCaller caller;

List&lt;String&gt; territories = caller.claims("territories", String.class);
Optional&lt;Integer&gt; max = caller.claim("maxAmount", Integer.class);</app-code>

    <h3>Where the caller comes from</h3>
    <p>
      <strong>Headers from a gateway</strong> — the default. Nothing to configure when the gateway sends
      <code>username</code>, <code>roles</code> (a JSON array or a comma-separated list, detected) and
      <code>tenant</code>. Nothing is verified: the service must never be reachable except through the gateway.
    </p>
    <app-code lang="properties">granted.headers.username=x-user
granted.headers.roles=x-roles
granted.headers.tenant=x-tenant</app-code>

    <p>
      <strong>A JWT</strong> — with every option of nestjs-granted. The signature is verified by
      <code>quarkus-oidc</code>, configured by granted from these properties; each JWK Set key verifies with its own
      algorithm, never the one the token announces. A missing or invalid token gives an anonymous caller.
    </p>
    <app-code lang="properties"># One IdP, by its JWK Set — keys cached, re-fetched when it rotates them
granted.source=jwt
granted.jwt.preset=keycloak
granted.jwt.jwks-uri=https://sso.example.com/realms/acme/protocol/openid-connect/certs
granted.jwt.issuer=https://sso.example.com/realms/acme
granted.jwt.audience=orders-api</app-code>
    <app-code lang="properties"># Several OpenID Providers, each token routed by its iss
granted.source=jwt
granted.jwt.discovery-uris[0].uri=http://meerkat.canopy.svc:8080
# The cluster's own services, calling with their pod's token
granted.jwt.discovery-uris[1].issuer=https://kubernetes.default.svc.cluster.local
granted.jwt.discovery-uris[1].jwks-uri=https://kubernetes.default.svc/openid/v1/jwks
granted.jwt.discovery-uris[1].bearer-token-file=/var/run/secrets/kubernetes.io/serviceaccount/token
granted.jwt.discovery-uris[1].bypass=system:serviceaccount:canopy:*</app-code>
    <table>
      <thead><tr><th>Property</th><th>nestjs-granted</th><th>Notes</th></tr></thead>
      <tbody>
        <tr><td><code>granted.jwt.public-key</code> / <code>public-key-file</code></td><td><code>base64Key</code> / <code>pemFile</code></td><td>A PEM public key</td></tr>
        <tr><td><code>granted.jwt.algorithm</code></td><td><code>algorithm</code></td><td>With a PEM key, default <code>ES256</code>. With a JWK Set, an optional allowlist; <code>none</code> and HS* refused</td></tr>
        <tr><td><code>granted.jwt.jwks-uri</code></td><td><code>jwksUri</code></td><td>The IdP's JWK Set</td></tr>
        <tr><td><code>granted.jwt.discovery-uris[n].*</code></td><td><code>discoveryUris</code></td><td><code>uri</code>, or <code>issuer</code> + <code>jwks-uri</code>; <code>bearer-token-file</code>, <code>audience</code>, <code>bypass</code></td></tr>
        <tr><td><code>granted.jwt.jwks-cache-max-age</code> / <code>jwks-cooldown</code> / <code>jwks-timeout</code></td><td>the same</td><td>10 min / 30 s / 5 s</td></tr>
        <tr><td><code>granted.jwt.issuer</code> / <code>audience</code></td><td><code>issuer</code> / <code>audience</code></td><td>Not checked when unset</td></tr>
        <tr><td><code>granted.jwt.preset</code></td><td>the presets</td><td><code>rfc9068</code>, <code>azure-ad</code>, <code>keycloak</code>, <code>okta</code></td></tr>
        <tr><td><code>granted.jwt.username-claim</code> / <code>roles-claim</code> / <code>tenant-claim</code></td><td><code>usernameClaim</code> / <code>rolesClaim</code> / <code>tenantClaim</code></td><td>Dotted paths allowed</td></tr>
      </tbody>
    </table>
    <p>
      How each option behaves is described once, on the NestJS page:
      <a routerLink="/nestjs/info-providers">Where the identity comes from</a>.
    </p>

    <h3>Roles</h3>
    <app-code lang="properties">granted.role-hierarchy.ADMIN=MANAGER
granted.role-hierarchy.MANAGER=USER
granted.known-roles=ADMIN,MANAGER,USER</app-code>
    <p>An <code>ADMIN</code> passes <code>&#64;RolesAllowed("USER")</code>; any role outside <code>known-roles</code> is dropped, after the hierarchy is expanded.</p>

    <h3>Why did a request get a 403?</h3>
    <p>Every refusal is logged at <code>WARN</code>, the rule spelled as nestjs-granted names it:</p>
    <app-code lang="text">GET /stations denied: hasRole(FORECASTER) not met by 'bob' (roles: USER; tenant: acme)</app-code>
    <p>
      The caller gets the bare <code>&#123;"statusCode":403,"error":"Forbidden","message":"Forbidden resource"&#125;</code>.
      Where every caller is trusted, <code>granted.access-denied.details=true</code> writes the reason into the
      response too.
    </p>
  `,
})
export class QuarkusComponent {}
