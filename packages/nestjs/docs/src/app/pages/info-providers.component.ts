import { Component } from '@angular/core';
import { RouterLink } from '@angular/router';
import { CodeComponent } from '../code/code.component';

@Component({
  selector: 'app-info-providers',
  imports: [CodeComponent, RouterLink],
  template: `
    <h2>Where the identity comes from</h2>
    <table>
      <thead><tr><th>Your setup</th><th>Use</th></tr></thead>
      <tbody>
        <tr><td>A gateway puts the user in HTTP headers</td><td><a routerLink="/info-providers" fragment="headers">Headers</a> — the default</td></tr>
        <tr><td>Requests carry <code>Authorization: Bearer &lt;JWT&gt;</code></td><td><a routerLink="/info-providers" fragment="jwt"><code>GrantedJwtPrincipalProvider</code></a></td></tr>
        <tr><td>Something else — a session, another scheme</td><td><a routerLink="/info-providers" fragment="custom">Your own provider</a></td></tr>
      </tbody>
    </table>

    <h3 id="headers">Headers from a gateway</h3>
    <p>
      Nothing to configure when your gateway sends <code>username</code>, <code>roles</code> (a JSON array) and
      <code>tenant</code>. Other names, or roles as a comma-separated list:
    </p>
    <app-code lang="ts">GrantedModule.forRoot(&#123;
  principalProvider: new GrantedPrincipalProvider(&#123;
    usernameHeader: 'x-user',
    rolesHeader: 'x-roles',
    tenantHeader: 'x-tenant',
    rolesFormat: 'csv', // 'ADMIN, USER' instead of ["ADMIN","USER"]
  &#125;),
&#125;);</app-code>
    <div class="callout warn">
      Only trust these headers when your service can't be reached without the gateway: anyone else could send
      them.
    </div>

    <h3 id="jwt">A JWT — <code>GrantedJwtPrincipalProvider</code></h3>
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

    <p>All the options: <a routerLink="/reference">Options reference</a>.</p>
    <p>Good to know:</p>
    <ul>
      <li>A token signed by a key the provider doesn't know yet triggers one re-fetch: a key rotation needs no restart.</li>
      <li>If an IdP is down, the last known keys are kept and a warning is logged.</li>
      <li>The algorithm comes from the key, never from the token: <code>alg: none</code> and RSA/HMAC confusion are rejected.</li>
      <li>The token and the key material are never logged.</li>
    </ul>

    <h3 id="custom">Your own provider</h3>
    <p>
      Implement <code>IGrantedPrincipalProvider</code>. Each value has two getters: one for the guard
      (<code>Request</code>), one for the parameter decorators (<code>IncomingMessage</code>).
    </p>
    <app-code lang="ts">export class SessionProvider implements IGrantedPrincipalProvider &#123;
  constructor(private readonly sessions: SessionStore) &#123;&#125;

  // Optional: awaited once per request, before the getters — the place for I/O.
  async prepare(req: IncomingMessage): Promise&lt;void&gt; &#123;
    req['session'] = await this.sessions.find(req.headers['x-session-id'] as string);
  &#125;

  getUsernameFromRequest(req: Request) &#123; return req['session']?.username ?? 'anonymous'; &#125;
  getRolesFromRequest(req: Request) &#123; return req['session']?.roles ?? []; &#125;
  getTenantFromRequest(req: Request) &#123; return req['session']?.tenant; &#125;

  getUsernameFromIncomingMessage(msg: IncomingMessage) &#123; return msg['session']?.username ?? 'anonymous'; &#125;
  getRolesFromIncomingMessage(msg: IncomingMessage) &#123; return msg['session']?.roles ?? []; &#125;
  getTenantFromIncomingMessage(msg: IncomingMessage) &#123; return msg['session']?.tenant; &#125;
&#125;</app-code>
    <app-code lang="ts">GrantedModule.forRoot(&#123; principalProvider: new SessionProvider(sessions) &#125;);</app-code>
    <p>
      A <code>prepare()</code> that throws fails the request: catch what should rather give an anonymous caller.
      To let a caller through every rule, also implement <code>isBypassed(request): boolean</code>.
    </p>
  `,
})
export class PrincipalProvidersComponent {}
