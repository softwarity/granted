import { Component } from '@angular/core';
import { RouterLink } from '@angular/router';
import { CodeComponent } from '../code/code.component';

@Component({
  selector: 'app-info-providers',
  imports: [CodeComponent, RouterLink],
  template: `
    <h2>Principal providers</h2>

    <p>
      An <strong>principal provider</strong> is the strategy that resolves the caller's identity from the
      request. It is set once via <code>forRoot(&#123; principalProvider &#125;)</code> and used by both the
      <a routerLink="/securing-endpoints">guard</a> (for <code>username</code> / <code>roles</code>) and
      the <a routerLink="/parameter-decorators">parameter decorators</a>. Two implementations ship with
      the library; you can also write your own.
    </p>

    <app-code lang="ts">interface IGrantedPrincipalProvider &#123;
  prepare?(request: IncomingMessage): Promise&lt;void&gt;; // optional async step, see Custom provider
  isBypassed?(request: Request): boolean;              // optional: pass every &#64;GrantedTo, see bypass

  getUsernameFromRequest(request: Request): string;
  getRolesFromRequest(request: Request): string[];
  getTenantFromRequest(request: Request): string | undefined;

  getUsernameFromIncomingMessage(msg: IncomingMessage): string;
  getRolesFromIncomingMessage(msg: IncomingMessage): string[];
  getTenantFromIncomingMessage(msg: IncomingMessage): string | undefined;
&#125;</app-code>

    <div class="callout">
      Two shapes per field — <code>Request</code> and <code>IncomingMessage</code> — because the guard
      runs against the Express <code>Request</code>, while parameter decorators run later in the
      pipeline against the raw <code>IncomingMessage</code>. A custom provider must implement both.
    </div>

    <h3>GrantedPrincipalProvider — from headers (default)</h3>
    <p>Used automatically when you don't pass an <code>principalProvider</code>.</p>
    <table>
      <thead><tr><th>Field</th><th>Default header</th><th>Parsing</th><th>Fallback</th></tr></thead>
      <tbody>
        <tr><td><code>username</code></td><td><code>username</code></td><td>raw string</td><td><code>'anonymous'</code></td></tr>
        <tr><td><code>roles</code></td><td><code>roles</code></td><td>JSON array, or CSV</td><td><code>[]</code></td></tr>
        <tr><td><code>tenant</code></td><td><code>tenant</code></td><td>raw string</td><td><code>undefined</code></td></tr>
      </tbody>
    </table>
    <app-code lang="ts">GrantedModule.forRoot(&#123; apply: true &#125;); // GrantedPrincipalProvider is implied</app-code>
    <p>
      A typical upstream (API gateway, OAuth2 proxy) sets these headers after authentication, e.g.
      <code>username: alice</code>, <code>roles: ["ADMIN","USER"]</code>.
    </p>

    <h4>Configurable header names &amp; roles format</h4>
    <p>
      Both the <strong>header names</strong> and the <strong>roles encoding</strong> are configurable.
      Header names default to <code>username</code> / <code>roles</code> / <code>tenant</code>; the roles
      header is a JSON array by default, or a trimmed comma-separated list with
      <code>rolesFormat: 'csv'</code>:
    </p>
    <app-code lang="ts">import &#123; GrantedModule, GrantedPrincipalProvider &#125; from '&#64;softwarity/nestjs-granted';

GrantedModule.forRoot(&#123;
  principalProvider: new GrantedPrincipalProvider(&#123;
    usernameHeader: 'x-user',   // default 'username'
    rolesHeader: 'x-roles',     // default 'roles'
    tenantHeader: 'x-tenant',   // default 'tenant'
    rolesFormat: 'csv',         // default 'json' — 'ROLE1, ROLE2' instead of ["ROLE1","ROLE2"]
  &#125;),
&#125;);</app-code>
    <p class="callout">These options are specific to the header provider — JWT identity comes from configurable claims (<code>rolesClaim</code>, etc.), and roles there are already an array.</p>

    <h3>GrantedJwtPrincipalProvider — from a verified JWT</h3>
    <p>
      Reads <code>Authorization: Bearer &lt;token&gt;</code>, verifies the token and maps its claims to
      <code>username</code> / <code>roles</code> / <code>tenant</code>. A missing or invalid token gives an
      <strong>anonymous</strong> request: your <code>&#64;GrantedTo</code> specs decide what it may reach.
    </p>
    <p>Pick the case that matches your setup:</p>
    <table>
      <thead><tr><th>Your setup</th><th>Use</th></tr></thead>
      <tbody>
        <tr><td>The IdP gave you a public key file</td><td><code>pemFile</code></td></tr>
        <tr><td>The IdP publishes a JWKS URL</td><td><code>jwksUri</code></td></tr>
        <tr><td>One or several IdPs, each with a <code>/.well-known/openid-configuration</code></td><td><code>discoveryUris</code></td></tr>
        <tr><td>The other services of your cluster must get through</td><td><code>discoveryUris</code> + <code>bypass</code></td></tr>
      </tbody>
    </table>

    <h4>A public key file</h4>
    <app-code lang="ts">GrantedModule.forRoot(&#123;
  apply: true,
  principalProvider: GrantedJwtPrincipalProvider.keycloak(&#123;
    pemFile: 'config/jwt_public_key.pem', // or base64Key: '-----BEGIN PUBLIC KEY-----…'
    algorithm: 'RS256',                   // default 'ES256'
  &#125;),
&#125;);</app-code>

    <h4>A JWKS URL</h4>
    <app-code lang="ts">GrantedJwtPrincipalProvider.keycloak(&#123;
  jwksUri: 'https://sso.example.com/realms/acme/protocol/openid-connect/certs',
&#125;);</app-code>
    <p>No algorithm to set, and nothing to redeploy when the IdP rotates its keys.</p>

    <h4>One or several IdPs, by their discovery URL</h4>
    <app-code lang="ts">new GrantedJwtPrincipalProvider(&#123;
  discoveryUris: [
    'https://sso.example.com/realms/acme', // '/.well-known/openid-configuration' is appended
    'http://partner-idp.iam:8080/.well-known/openid-configuration',
  ],
&#125;);</app-code>
    <p>
      Each token is checked with the keys of the IdP that issued it (its <code>iss</code>). A token from an IdP
      that isn't listed is anonymous. An internal URL is fine: the issuer is read from the document, not from
      the URL.
    </p>

    <h4>Let the services of your cluster through</h4>
    <p>
      Service A calls service B with its pod's service account token. B lets the services of its namespace
      through, whatever the <code>&#64;GrantedTo</code>, and keeps checking users as usual:
    </p>
    <app-code lang="ts">new GrantedJwtPrincipalProvider(&#123;
  discoveryUris: [
    &#123;
      uri: 'https://kubernetes.default.svc', // the cluster's API server signs the service account tokens
      bearerTokenFile: '/var/run/secrets/kubernetes.io/serviceaccount/token', // it serves its keys to an authenticated caller only
      bypass: ['system:serviceaccount:canopy:*'],
    &#125;,
    'https://sso.example.com/realms/acme', // users
  ],
&#125;);</app-code>
    <table>
      <thead><tr><th>Caller</th><th>Result on B</th></tr></thead>
      <tbody>
        <tr><td>A user, through the IdP</td><td><code>&#64;GrantedTo</code> checked as usual</td></tr>
        <tr><td>A service account of <code>canopy</code></td><td>passes every <code>&#64;GrantedTo</code> — <code>&#64;Username()</code> is <code>system:serviceaccount:canopy:orders</code></td></tr>
        <tr><td>Any other service account (another namespace, a third-party component)</td><td>checked as usual: authenticated, but without any role</td></tr>
      </tbody>
    </table>
    <p>On B's pod, trust the cluster CA, which signs the API server certificate:</p>
    <app-code lang="text">env:
  - name: NODE_EXTRA_CA_CERTS
    value: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt</app-code>
    <p>On A, send the pod's token — read it at each call, the kubelet rotates it:</p>
    <app-code lang="ts">const token = readFileSync('/var/run/secrets/kubernetes.io/serviceaccount/token', 'utf8').trim();
await fetch('http://billing/api/invoices', &#123; headers: &#123; authorization: \`Bearer \$&#123;token&#125;\` &#125; &#125;);</app-code>
    <div class="callout warn">
      <strong>Keep <code>bypass</code> to your own namespace:</strong> every pod of the cluster carries a token
      signed by the same API server. Outside a cluster the token file is missing: that entry logs a warning
      and its tokens stay anonymous; the other IdPs keep working.
    </div>

    <h4>Claims → identity</h4>
    <table>
      <thead><tr><th>Factory</th><th>username</th><th>roles</th><th>tenant</th></tr></thead>
      <tbody>
        <tr><td><code>GrantedJwtPrincipalProvider.rfc9068(...)</code></td><td><code>sub</code></td><td><code>roles</code></td><td><code>tenant</code></td></tr>
        <tr><td><code>GrantedJwtPrincipalProvider.azureAd(...)</code></td><td><code>preferred_username</code></td><td><code>roles</code></td><td><code>tid</code></td></tr>
        <tr><td><code>GrantedJwtPrincipalProvider.keycloak(...)</code></td><td><code>preferred_username</code></td><td><code>realm_access.roles</code></td><td><code>tenant</code></td></tr>
        <tr><td><code>GrantedJwtPrincipalProvider.okta(...)</code></td><td><code>sub</code></td><td><code>groups</code></td><td><code>tenant</code></td></tr>
        <tr><td><code>new GrantedJwtPrincipalProvider(...)</code></td><td><code>usernameClaim</code> (<code>sub</code>)</td><td><code>rolesClaim</code> (<code>roles</code>)</td><td><code>tenantClaim</code> (<code>tenant</code>)</td></tr>
      </tbody>
    </table>
    <p>
      Every claim is overridable, dotted paths included:
      <code>GrantedJwtPrincipalProvider.okta(&#123; jwksUri, usernameClaim: 'email' &#125;)</code>,
      <code>rolesClaim: 'realm_access.roles'</code>.
    </p>

    <h4>Refuse tokens issued for another API</h4>
    <p>
      The provider checks the signature and the expiry. Behind a gateway that already checks the rest, that's
      enough. Reachable without the gateway, or sharing an IdP with other apps? Check the audience, and the
      issuer with a key or a JWKS URL:
    </p>
    <app-code lang="ts">GrantedJwtPrincipalProvider.keycloak(&#123;
  jwksUri: 'https://sso.example.com/realms/acme/protocol/openid-connect/certs',
  issuer: 'https://sso.example.com/realms/acme',
  audience: 'orders-api', // a string, a RegExp, or a list
&#125;);</app-code>
    <p>
      With <code>discoveryUris</code>, the issuer comes from each document, and an entry can have its own
      audience: <code>&#123; uri, audience: 'internal' &#125;</code>.
    </p>

    <h4>Options</h4>
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
    <p>Good to know:</p>
    <ul>
      <li>A token signed by a key the provider doesn't know yet triggers one re-fetch: a key rotation needs no restart.</li>
      <li>If an IdP is down, the last known keys are kept and a warning is logged.</li>
      <li>The algorithm comes from the key, never from the token: <code>alg: none</code> and RSA/HMAC confusion are rejected.</li>
      <li>The token and the key material are never logged.</li>
    </ul>

    <h3>Custom provider</h3>
    <p>
      Implement <code>IGrantedPrincipalProvider</code> to read identity from anywhere — a different header
      scheme, a session store, a service-mesh header set, etc. Handle both <code>Request</code> and
      <code>IncomingMessage</code>:
    </p>
    <app-code lang="ts">import &#123; IGrantedPrincipalProvider &#125; from '&#64;softwarity/nestjs-granted';
import &#123; Request &#125; from 'express';
import &#123; IncomingMessage &#125; from 'http';

export class HeaderProvider implements IGrantedPrincipalProvider &#123;
  getUsernameFromRequest(req: Request): string &#123;
    return req.header('x-user') || 'anonymous';
  &#125;
  getRolesFromRequest(req: Request): string[] &#123;
    return JSON.parse(req.header('x-roles') || '[]');
  &#125;
  getTenantFromRequest(req: Request): string | undefined &#123;
    return req.header('x-tenant') || undefined;
  &#125;

  getUsernameFromIncomingMessage(msg: IncomingMessage): string &#123;
    return (msg.headers['x-user'] as string) || 'anonymous';
  &#125;
  getRolesFromIncomingMessage(msg: IncomingMessage): string[] &#123;
    return JSON.parse((msg.headers['x-roles'] as string) || '[]');
  &#125;
  getTenantFromIncomingMessage(msg: IncomingMessage): string | undefined &#123;
    return (msg.headers['x-tenant'] as string) || undefined;
  &#125;
&#125;</app-code>
    <app-code lang="ts">GrantedModule.forRoot(&#123; apply: true, principalProvider: new HeaderProvider() &#125;);</app-code>

    <h4>Asynchronous resolution — <code>prepare()</code></h4>
    <p>
      The getters are synchronous. If resolving the identity needs I/O — a remote key set, a session
      store… — also implement the optional <code>prepare(request)</code> hook. The guard awaits it once per
      request, before any getter is called — on open routes and with <code>apply: false</code> too, since the
      parameter decorators run after the guard. Store what the getters need on the request:
    </p>
    <app-code lang="ts">export class SessionProvider implements IGrantedPrincipalProvider &#123;
  constructor(private readonly sessions: SessionStore) &#123;&#125;

  async prepare(req: IncomingMessage): Promise&lt;void&gt; &#123;
    req['session'] = await this.sessions.find(req.headers['x-session-id'] as string);
  &#125;

  getUsernameFromRequest(req: Request): string &#123;
    return req['session']?.username || 'anonymous';
  &#125;
  // ...the other getters read req['session'] the same way
&#125;</app-code>
    <p>
      <code>GrantedJwtPrincipalProvider</code> uses this hook to fetch its JWKS. A <code>prepare()</code> that
      throws fails the request, so catch what should rather yield an anonymous caller.
    </p>
  `,
})
export class PrincipalProvidersComponent {}
