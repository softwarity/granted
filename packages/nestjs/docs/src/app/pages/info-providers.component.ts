import { Component } from '@angular/core';
import { RouterLink } from '@angular/router';
import { CodeComponent } from '../code/code.component';

@Component({
  selector: 'app-info-providers',
  imports: [CodeComponent, RouterLink],
  template: `
    <h2>Info providers</h2>

    <p>
      An <strong>info provider</strong> is the strategy that resolves the caller's identity from the
      request. It is set once via <code>forRoot(&#123; infoProvider &#125;)</code> and used by both the
      <a routerLink="/securing-endpoints">guard</a> (for <code>username</code> / <code>roles</code>) and
      the <a routerLink="/parameter-decorators">parameter decorators</a>. Two implementations ship with
      the library; you can also write your own.
    </p>

    <app-code lang="ts">interface IGrantedInfoProvider &#123;
  getUsernameFromRequest(request: Request): string;
  getRolesFromRequest(request: Request): string[];
  getTenantFromRequest(request: Request): string | undefined;

  getUsernameFromIncomingMessage(msg: IncomingMessage): string;
  getRolesFromIncomingMessage(msg: IncomingMessage): string[];
  getTenantFromIncomingMessage(msg: IncomingMessage): string | undefined;
&#125;</app-code>

    <div class="callout">
      Two shapes per field — <code>Request</code> and <code>IncomingMessage</code> — because the guard
      runs against the Express <code>Request</code>, while parameter decorators run earlier in the
      pipeline against the raw <code>IncomingMessage</code>. A custom provider must implement both.
    </div>

    <h3>GrantedInfoProvider — from headers (default)</h3>
    <p>Used automatically when you don't pass an <code>infoProvider</code>.</p>
    <table>
      <thead><tr><th>Field</th><th>Source header</th><th>Default</th></tr></thead>
      <tbody>
        <tr><td><code>username</code></td><td><code>username</code></td><td><code>'anonymous'</code></td></tr>
        <tr><td><code>roles</code></td><td><code>roles</code> (JSON array)</td><td><code>[]</code></td></tr>
        <tr><td><code>tenant</code></td><td><code>tenant</code></td><td><code>undefined</code></td></tr>
      </tbody>
    </table>
    <app-code lang="ts">GrantedModule.forRoot(&#123; apply: true &#125;); // GrantedInfoProvider is implied</app-code>
    <p>
      A typical upstream (API gateway, OAuth2 proxy) sets these headers after authentication, e.g.
      <code>username: alice</code>, <code>roles: ["ADMIN","USER"]</code>.
    </p>

    <h4>roles header format: JSON or CSV</h4>
    <p>
      By default the <code>roles</code> header is a JSON array. If your gateway sends a comma-separated
      string instead (<code>roles: ADMIN, USER</code>), construct the provider with
      <code>rolesFormat: 'csv'</code> — values are split on commas and trimmed:
    </p>
    <app-code lang="ts">import &#123; GrantedModule, GrantedInfoProvider &#125; from '&#64;softwarity/nestjs-granted';

GrantedModule.forRoot(&#123;
  infoProvider: new GrantedInfoProvider(&#123; rolesFormat: 'csv' &#125;), // default: 'json'
&#125;);</app-code>
    <p class="callout">This option is specific to the header provider — JWT roles come from a claim, which is already an array (see <code>rolesClaim</code> below).</p>

    <h3>GrantedInfoJwtProvider — from a verified JWT</h3>
    <p>
      Reads <code>Authorization: Bearer &lt;token&gt;</code>, verifies the signature with your public key,
      and maps the configured claims to <code>username</code> / <code>roles</code> / <code>tenant</code>.
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
        <tr><td><code>GrantedInfoJwtProvider.rfc9068(...)</code></td><td><code>sub</code></td><td><code>roles</code></td><td><code>tenant</code></td></tr>
        <tr><td><code>GrantedInfoJwtProvider.azureAd(...)</code></td><td><code>preferred_username</code></td><td><code>roles</code></td><td><code>tid</code></td></tr>
        <tr><td><code>GrantedInfoJwtProvider.keycloak(...)</code></td><td><code>preferred_username</code></td><td><code>realm_access.roles</code></td><td><code>tenant</code></td></tr>
        <tr><td><code>GrantedInfoJwtProvider.okta(...)</code></td><td><code>sub</code></td><td><code>groups</code></td><td><code>tenant</code></td></tr>
      </tbody>
    </table>

    <app-code lang="ts">import &#123; GrantedModule, GrantedInfoJwtProvider &#125; from '&#64;softwarity/nestjs-granted';

&#64;Module(&#123;
  imports: [
    GrantedModule.forRoot(&#123;
      apply: true,
      infoProvider: GrantedInfoJwtProvider.keycloak(&#123;
        algorithm: 'RS256',
        pemFile: 'config/jwt_public_key.pem',
      &#125;),
    &#125;),
  ],
&#125;)
export class AppModule &#123;&#125;</app-code>

    <p>Any preset field can be overridden — e.g. read the username from <code>email</code> on Okta:</p>
    <app-code lang="ts">GrantedInfoJwtProvider.okta(&#123; pemFile: 'config/key.pem', usernameClaim: 'email' &#125;);</app-code>

    <h4>Custom claim mapping</h4>
    <p>No preset fits? Use the constructor directly:</p>
    <table>
      <thead><tr><th>Option</th><th>Type</th><th>Notes</th></tr></thead>
      <tbody>
        <tr><td><code>algorithm</code></td><td><code>Algorithm</code></td><td>e.g. <code>'RS256'</code> (default), <code>'ES256'</code>, <code>'PS256'</code>.</td></tr>
        <tr><td><code>pemFile</code></td><td><code>string</code></td><td>Path to a PEM public key; read once at construction.</td></tr>
        <tr><td><code>base64Key</code></td><td><code>string</code></td><td>Inline PEM public key — alternative to <code>pemFile</code>.</td></tr>
        <tr><td><code>usernameClaim</code></td><td><code>string</code></td><td>Default <code>'sub'</code>. Dotted path allowed.</td></tr>
        <tr><td><code>rolesClaim</code></td><td><code>string</code></td><td>Default <code>'roles'</code>. Dotted path allowed.</td></tr>
        <tr><td><code>tenantClaim</code></td><td><code>string</code></td><td>Default <code>'tenant'</code>. Dotted path allowed.</td></tr>
      </tbody>
    </table>

    <app-code lang="ts">new GrantedInfoJwtProvider(&#123;
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
      Implement <code>IGrantedInfoProvider</code> to read identity from anywhere — a different header
      scheme, a session store, a service-mesh header set, etc. Handle both <code>Request</code> and
      <code>IncomingMessage</code>:
    </p>
    <app-code lang="ts">import &#123; IGrantedInfoProvider &#125; from '&#64;softwarity/nestjs-granted';
import &#123; Request &#125; from 'express';
import &#123; IncomingMessage &#125; from 'http';

export class HeaderProvider implements IGrantedInfoProvider &#123;
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
    <app-code lang="ts">GrantedModule.forRoot(&#123; apply: true, infoProvider: new HeaderProvider() &#125;);</app-code>
  `,
})
export class InfoProvidersComponent {}
