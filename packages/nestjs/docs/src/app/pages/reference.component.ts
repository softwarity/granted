import { Component } from '@angular/core';
import { RouterLink } from '@angular/router';

@Component({
  selector: 'app-reference',
  imports: [RouterLink],
  template: `
    <h2>Options reference</h2>

    <h3><code>GrantedModule.forRoot(options)</code></h3>
    <table>
      <thead><tr><th>Option</th><th>Default</th><th></th></tr></thead>
      <tbody>
        <tr><td><code>apply</code></td><td><code>true</code></td><td><code>false</code> lets every request through; the decorators keep working.</td></tr>
        <tr><td><code>principalProvider</code></td><td>headers</td><td>Where the identity comes from: <a routerLink="/info-providers">providers</a>.</td></tr>
        <tr><td><code>roleHierarchy</code></td><td>—</td><td>A role → the roles it implies: <a routerLink="/roles">Roles</a>.</td></tr>
        <tr><td><code>knownRoles</code></td><td>all roles kept</td><td>The roles to keep: <a routerLink="/roles">Roles</a>.</td></tr>
      </tbody>
    </table>
    <div class="callout">
      Options are read once, at startup — there is no <code>forRootAsync</code>. Read your environment variables or
      files before, and pass the values.
    </div>

    <h3><code>new GrantedPrincipalProvider(options)</code> — headers</h3>
    <table>
      <thead><tr><th>Option</th><th>Default</th><th></th></tr></thead>
      <tbody>
        <tr><td><code>usernameHeader</code></td><td><code>'username'</code></td><td>Missing → <code>'anonymous'</code>.</td></tr>
        <tr><td><code>rolesHeader</code></td><td><code>'roles'</code></td><td>Missing → <code>[]</code>.</td></tr>
        <tr><td><code>tenantHeader</code></td><td><code>'tenant'</code></td><td>Missing → <code>undefined</code>.</td></tr>
        <tr><td><code>rolesFormat</code></td><td><code>'json'</code></td><td><code>'json'</code>: <code>["ADMIN","USER"]</code>. <code>'csv'</code>: <code>ADMIN, USER</code>.</td></tr>
      </tbody>
    </table>

    <h3><code>GrantedJwtPrincipalProvider</code> — JWT</h3>
    <p>
      <code>new GrantedJwtPrincipalProvider(options)</code>, or a preset that sets the claims:
      <code>.rfc9068()</code>, <code>.azureAd()</code>, <code>.keycloak()</code>, <code>.okta()</code> — see
      <a routerLink="/info-providers" fragment="jwt">A JWT</a>.
    </p>
    <table>
      <thead><tr><th>Option</th><th>Default</th><th></th></tr></thead>
      <tbody>
        <tr><td><code>pemFile</code> / <code>base64Key</code></td><td>—</td><td>Public key, as a file or inline PEM.</td></tr>
        <tr><td><code>algorithm</code></td><td><code>'ES256'</code> with a key; each key's own with a JWKS</td><td>With a JWKS, an optional allowlist: <code>['ES256', 'EdDSA']</code>.</td></tr>
        <tr><td><code>jwksUri</code></td><td>—</td><td>JWKS URL. Alongside <code>discoveryUris</code>, needs <code>issuer</code>.</td></tr>
        <tr><td><code>discoveryUris</code></td><td>—</td><td>IdP URLs, or <code>&#123; uri, bearerTokenFile?, audience?, bypass? &#125;</code>.</td></tr>
        <tr><td>↳ <code>bearerTokenFile</code></td><td>—</td><td>Token sent to this IdP only, when it wants one (the Kubernetes API server does). Re-read at each fetch.</td></tr>
        <tr><td>↳ <code>audience</code></td><td><code>audience</code></td><td>Accepted <code>aud</code> for this IdP's tokens.</td></tr>
        <tr><td>↳ <code>bypass</code></td><td>—</td><td><code>sub</code> patterns (<code>*</code> = anything) whose tokens from this IdP pass every <code>&#64;GrantedTo</code>.</td></tr>
        <tr><td><code>issuer</code></td><td>not checked</td><td>Accepted <code>iss</code>, with <code>pemFile</code> / <code>base64Key</code> / <code>jwksUri</code>.</td></tr>
        <tr><td><code>audience</code></td><td>not checked</td><td>Accepted <code>aud</code>.</td></tr>
        <tr><td><code>usernameClaim</code> / <code>rolesClaim</code> / <code>tenantClaim</code></td><td>see presets</td><td>Claim paths.</td></tr>
        <tr><td><code>jwksCacheMaxAge</code></td><td>10 min</td><td>Keys and documents older than this are re-fetched.</td></tr>
        <tr><td><code>jwksCooldown</code></td><td>30 s</td><td>At most one fetch per IdP in this delay.</td></tr>
        <tr><td><code>jwksTimeout</code></td><td>5 s</td><td>Timeout of a fetch.</td></tr>
      </tbody>
    </table>

    <h3>Rules</h3>
    <p><code>&#64;GrantedTo(...rules)</code> on a route or a controller — every rule must pass.</p>
    <table>
      <thead><tr><th>Rule</th><th>Passes when</th></tr></thead>
      <tbody>
        <tr><td><code>isAuthenticated()</code></td><td>the caller is known (not <code>anonymous</code>)</td></tr>
        <tr><td><code>hasRole('ADMIN')</code></td><td>the caller has the role, directly or <a routerLink="/roles">implied</a></td></tr>
        <tr><td><code>isUser('Param', 'userId')</code></td><td>the request value is the caller's username — <code>'Param'</code>, <code>'Query'</code> or <code>'Body'</code> (dotted path)</td></tr>
        <tr><td><code>isTenant('Param', 'tenantId')</code></td><td>the request value is the caller's tenant; refused when the caller has none</td></tr>
        <tr><td><code>and(a, b, …)</code></td><td>all pass</td></tr>
        <tr><td><code>or(a, b, …)</code></td><td>one passes</td></tr>
        <tr><td><code>not(a)</code></td><td><code>a</code> fails</td></tr>
        <tr><td><code>isTrue()</code> / <code>isFalse()</code></td><td>always / never — e.g. to lock a route</td></tr>
      </tbody>
    </table>
  `,
})
export class ReferenceComponent {}
