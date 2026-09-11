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
      Reads <code>Authorization: Bearer &lt;token&gt;</code>, verifies the signature with your public key —
      a PEM, or the keys your IdP publishes on its JWKS endpoint (see below) — and maps the configured claims to <code>username</code> / <code>roles</code> / <code>tenant</code>.
      Claim names support <strong>dotted paths</strong> for nested claims (e.g. Keycloak's
      <code>realm_access.roles</code>).
    </p>

    <h4>IdP presets</h4>
    <p>
      Since claim names differ between providers, the common ones ship as static factories — you only
      pass the key material:
    </p>
    <table>
      <thead><tr><th>Factory</th><th>username</th><th>roles</th><th>tenant</th></tr></thead>
      <tbody>
        <tr><td><code>GrantedJwtPrincipalProvider.rfc9068(...)</code></td><td><code>sub</code></td><td><code>roles</code></td><td><code>tenant</code></td></tr>
        <tr><td><code>GrantedJwtPrincipalProvider.azureAd(...)</code></td><td><code>preferred_username</code></td><td><code>roles</code></td><td><code>tid</code></td></tr>
        <tr><td><code>GrantedJwtPrincipalProvider.keycloak(...)</code></td><td><code>preferred_username</code></td><td><code>realm_access.roles</code></td><td><code>tenant</code></td></tr>
        <tr><td><code>GrantedJwtPrincipalProvider.okta(...)</code></td><td><code>sub</code></td><td><code>groups</code></td><td><code>tenant</code></td></tr>
      </tbody>
    </table>

    <app-code lang="ts">import &#123; GrantedModule, GrantedJwtPrincipalProvider &#125; from '&#64;softwarity/nestjs-granted';

&#64;Module(&#123;
  imports: [
    GrantedModule.forRoot(&#123;
      apply: true,
      principalProvider: GrantedJwtPrincipalProvider.keycloak(&#123;
        algorithm: 'RS256',
        pemFile: 'config/jwt_public_key.pem',
      &#125;),
    &#125;),
  ],
&#125;)
export class AppModule &#123;&#125;</app-code>

    <p>Any preset field can be overridden — e.g. read the username from <code>email</code> on Okta:</p>
    <app-code lang="ts">GrantedJwtPrincipalProvider.okta(&#123; pemFile: 'config/key.pem', usernameClaim: 'email' &#125;);</app-code>

    <h4>Keys from a JWKS endpoint — automatic rotation</h4>
    <p>
      Rather than a static PEM, point the provider at the JWK Set your IdP publishes — its
      <code>jwks_uri</code>, listed in <code>&lt;issuer&gt;/.well-known/openid-configuration</code> (often
      <code>/.well-known/jwks.json</code>). When the IdP rotates its signing key, the provider picks up the
      new one by itself: no restart, no PEM to redeploy.
    </p>
    <app-code lang="ts">GrantedJwtPrincipalProvider.keycloak(&#123;
  jwksUri: 'https://sso.example.com/realms/acme/protocol/openid-connect/certs',
&#125;);</app-code>
    <p>How the keys are handled:</p>
    <ul>
      <li><strong>Cached.</strong> The set is fetched on the first request carrying a token, then reused.</li>
      <li>
        <strong>Re-fetched on failure.</strong> When a token fails verification — typically because it is
        signed by a key rotated in after the last fetch — the set is re-fetched once and the token verified
        again. A token rejected on its dates, issuer or audience doesn't trigger a fetch: its key is known.
      </li>
      <li>
        <strong>Re-fetched when old.</strong> Keys older than <code>jwksCacheMaxAge</code> are re-fetched, so
        a key the IdP withdrew stops being accepted.
      </li>
      <li>
        <strong>Rate-limited.</strong> Never two fetches within <code>jwksCooldown</code>: tokens with forged
        <code>kid</code>s can't make the provider hammer the IdP. Concurrent requests share one fetch.
      </li>
      <li>
        <strong>Outage-tolerant.</strong> If a fetch fails (IdP down, timeout…), the last known keys are kept
        and a warning is logged.
      </li>
    </ul>
    <p>
      The key is picked by the token's <code>kid</code> header (every key is tried when it has none), with the
      configured <code>algorithm</code> — default <code>RS256</code>, set it to match your IdP (e.g.
      <code>ES256</code>). Only public signature keys are used: symmetric keys and
      <code>"use": "enc"</code> keys in the set are ignored.
    </p>
    <table>
      <thead><tr><th>Option</th><th>Default</th><th>Notes</th></tr></thead>
      <tbody>
        <tr><td><code>jwksUri</code></td><td>—</td><td>JWK Set URL. Can't be combined with <code>base64Key</code> / <code>pemFile</code>.</td></tr>
        <tr><td><code>jwksCacheMaxAge</code></td><td><code>600000</code> (10 min)</td><td>Age, in ms, after which cached keys are re-fetched.</td></tr>
        <tr><td><code>jwksCooldown</code></td><td><code>30000</code> (30 s)</td><td>Minimum delay, in ms, between two fetches.</td></tr>
        <tr><td><code>jwksTimeout</code></td><td><code>5000</code> (5 s)</td><td>Timeout, in ms, of a fetch.</td></tr>
      </tbody>
    </table>
    <div class="callout warn">
      <strong>Serve the JWKS over HTTPS.</strong> Whoever controls that response decides which tokens are
      valid.
    </div>

    <h4>Issuer and audience — optional</h4>
    <p>
      By default the provider checks the signature and the token's validity dates (<code>exp</code>,
      <code>nbf</code>), not who issued the token nor whom it is for — the gateway in front of the service
      usually does that. To check them here too, set <code>issuer</code> and/or <code>audience</code>; a token
      that doesn't match is treated as <strong>anonymous</strong>:
    </p>
    <app-code lang="ts">GrantedJwtPrincipalProvider.keycloak(&#123;
  jwksUri: 'https://sso.example.com/realms/acme/protocol/openid-connect/certs',
  issuer: 'https://sso.example.com/realms/acme', // or an array of accepted issuers
  audience: 'orders-api',                         // a string, a RegExp, or an array of them
&#125;);</app-code>
    <p>
      Worth it when the service can be reached without going through the gateway, or when the IdP signs
      other apps' tokens with the same keys — Microsoft Entra ID uses the same signing keys for every tenant.
    </p>
    <div class="callout">
      Both options need a key (<code>base64Key</code>, <code>pemFile</code> or <code>jwksUri</code>): an
      unverified token could claim any issuer, so the provider refuses the combination at construction.
    </div>

    <h4>Custom claim mapping</h4>
    <p>No preset fits? Use the constructor directly:</p>
    <table>
      <thead><tr><th>Option</th><th>Type</th><th>Notes</th></tr></thead>
      <tbody>
        <tr><td><code>algorithm</code></td><td><code>Algorithm</code></td><td>e.g. <code>'RS256'</code> (default), <code>'ES256'</code>, <code>'PS256'</code>.</td></tr>
        <tr><td><code>pemFile</code></td><td><code>string</code></td><td>Path to a PEM public key; read once at construction.</td></tr>
        <tr><td><code>base64Key</code></td><td><code>string</code></td><td>Inline PEM public key — alternative to <code>pemFile</code>.</td></tr>
        <tr><td><code>jwksUri</code></td><td><code>string</code></td><td>JWK Set URL — alternative to a PEM, with key rotation. See <em>Keys from a JWKS endpoint</em> above.</td></tr>
        <tr><td><code>issuer</code></td><td><code>string | string[]</code></td><td>Accepted <code>iss</code>. Not checked when unset.</td></tr>
        <tr><td><code>audience</code></td><td><code>string | RegExp | (string | RegExp)[]</code></td><td>Accepted <code>aud</code>. Not checked when unset.</td></tr>
        <tr><td><code>usernameClaim</code></td><td><code>string</code></td><td>Default <code>'sub'</code>. Dotted path allowed.</td></tr>
        <tr><td><code>rolesClaim</code></td><td><code>string</code></td><td>Default <code>'roles'</code>. Dotted path allowed.</td></tr>
        <tr><td><code>tenantClaim</code></td><td><code>string</code></td><td>Default <code>'tenant'</code>. Dotted path allowed.</td></tr>
      </tbody>
    </table>

    <app-code lang="ts">new GrantedJwtPrincipalProvider(&#123;
  algorithm: 'RS256',
  pemFile: 'config/jwt_public_key.pem',
  usernameClaim: 'sub',
  rolesClaim: 'realm_access.roles', // nested claim
  tenantClaim: 'tid',
&#125;);</app-code>

    <div class="callout warn">
      <strong>Verification failures are non-fatal.</strong> If the token is missing, malformed, or fails
      verification, the request is treated as <strong>anonymous</strong> (empty claims) — it is then up to
      your <code>&#64;GrantedTo</code> specs (e.g. <code>isAuthenticated()</code>) to reject it. The
      provider never logs the token or the key material; only a short warning with the failure reason.
    </div>

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
