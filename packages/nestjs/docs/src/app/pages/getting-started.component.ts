import { Component } from '@angular/core';
import { RouterLink } from '@angular/router';
import { CodeComponent } from '../code/code.component';

@Component({
  selector: 'app-getting-started',
  imports: [CodeComponent, RouterLink],
  styles: [
    `
      .features {
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
        gap: 12px;
        margin: 0 0 28px 0;
      }
      .feature-card {
        display: flex;
        flex-direction: column;
        gap: 6px;
        padding: 14px 16px;
        background-color: var(--bg-secondary);
        border: 1px solid var(--border-color);
        border-radius: 8px;
        text-decoration: none;
        transition: all 0.15s;
      }
      .feature-card:hover {
        border-color: var(--accent-purple);
        background-color: rgba(163, 113, 247, 0.1);
        text-decoration: none;
        transform: translateY(-1px);
      }
      .feature-icon {
        font-size: 1.3rem;
        line-height: 1;
      }
      .feature-title {
        font-weight: 600;
        color: var(--text-primary);
        font-size: 0.95rem;
      }
      .feature-desc {
        color: var(--text-secondary);
        font-size: 0.85rem;
        line-height: 1.45;
      }
      .feature-desc code {
        font-size: 0.85em;
      }
    `,
  ],
  template: `
    <h2>Getting started</h2>

    <p>
      <strong>&#64;softwarity/nestjs-granted</strong> adds <strong>RBAC authorization</strong> to your
      NestJS HTTP endpoints. You declare, per route, <em>who is allowed in</em> with a single
      <code>&#64;GrantedTo(...)</code> decorator, and you inject the caller's identity
      (<code>username</code>, <code>roles</code>, <code>tenant</code>) with parameter decorators.
      A global guard does the enforcement.
    </p>

    <div class="callout">
      <strong>Assumption:</strong> the caller is <em>already authenticated</em> upstream — by an API
      gateway, an OAuth2 proxy, or a sidecar — which forwards the identity either as plain HTTP headers
      or as a <code>Bearer</code> JWT. This library does <strong>not</strong> do login, sessions, or
      token issuance. It does authorization and identity injection, nothing more.
    </div>

    <h3>Features</h3>
    <section class="features">
      <a routerLink="/securing-endpoints" class="feature-card">
        <span class="feature-icon">🛡️</span>
        <span class="feature-title">Declarative guard</span>
        <span class="feature-desc">One <code>&#64;GrantedTo(...)</code> per route, enforced by a global guard.</span>
      </a>
      <a routerLink="/boolean-specs" class="feature-card">
        <span class="feature-icon">🧩</span>
        <span class="feature-title">Composable specs</span>
        <span class="feature-desc"><code>and</code>, <code>or</code>, <code>not</code>, <code>hasRole</code>, <code>isAuthenticated</code>, <code>isUser</code>, <code>isTenant</code>.</span>
      </a>
      <a routerLink="/ownership" class="feature-card">
        <span class="feature-icon">🔐</span>
        <span class="feature-title">Ownership / anti-IDOR</span>
        <span class="feature-desc"><code>isUser</code> &amp; <code>isTenant</code> check the targeted record is the caller's.</span>
      </a>
      <a routerLink="/parameter-decorators" class="feature-card">
        <span class="feature-icon">💉</span>
        <span class="feature-title">Parameter decorators</span>
        <span class="feature-desc">Inject <code>&#64;Username()</code>, <code>&#64;Roles()</code>, <code>&#64;Tenant()</code>.</span>
      </a>
      <a routerLink="/configuration" class="feature-card">
        <span class="feature-icon">🪜</span>
        <span class="feature-title">Role hierarchy</span>
        <span class="feature-desc">One role implies others (<code>ADMIN ⇒ MANAGER ⇒ USER</code>), expanded transitively.</span>
      </a>
      <a routerLink="/configuration" class="feature-card">
        <span class="feature-icon">🧹</span>
        <span class="feature-title">Known-roles filter</span>
        <span class="feature-desc">Keep only the roles your module owns; ignore a shared token's noise.</span>
      </a>
      <a routerLink="/info-providers" class="feature-card">
        <span class="feature-icon">🔑</span>
        <span class="feature-title">JWT + IdP presets</span>
        <span class="feature-desc">RFC 9068, Azure AD, Keycloak, Okta — or a custom claim mapping.</span>
      </a>
      <a routerLink="/info-providers" class="feature-card">
        <span class="feature-icon">📥</span>
        <span class="feature-title">Header or JWT</span>
        <span class="feature-desc">Pluggable provider; roles header as JSON or CSV.</span>
      </a>
    </section>

    <h3>Compatibility</h3>
    <ul>
      <li>Node.js &ge; 20</li>
      <li>NestJS &ge; 10 (tested with 10 and 11)</li>
      <li>Express platform (<code>&#64;nestjs/platform-express</code>)</li>
    </ul>

    <h3>1. Install</h3>
    <app-code lang="bash">npm install &#64;softwarity/nestjs-granted</app-code>
    <p>Peer deps you most likely already have:</p>
    <app-code lang="bash">npm install &#64;nestjs/common &#64;nestjs/core &#64;nestjs/platform-express rxjs reflect-metadata</app-code>

    <h3>2. Register the module</h3>
    <app-code lang="ts">import &#123; Module &#125; from '&#64;nestjs/common';
import &#123; GrantedModule &#125; from '&#64;softwarity/nestjs-granted';

&#64;Module(&#123;
  imports: [
    // apply: true enforces &#64;GrantedTo; set false to load the module but disable checks.
    GrantedModule.forRoot(&#123; apply: true &#125;),
  ],
&#125;)
export class AppModule &#123;&#125;</app-code>
    <p>
      <code>forRoot</code> registers a global guard (<code>APP_GUARD</code>) and a global interceptor
      (<code>APP_INTERCEPTOR</code>) — no further wiring per controller. With no options, it defaults to
      <code>&#123; apply: true &#125;</code> reading the identity from HTTP headers. See
      <a routerLink="/configuration">Configuration</a> for the full reference.
    </p>

    <h3>3. Inject the identity</h3>
    <app-code lang="ts">import &#123; Controller, Get &#125; from '&#64;nestjs/common';
import &#123; Username, Roles, Tenant &#125; from '&#64;softwarity/nestjs-granted';

&#64;Controller()
export class MeController &#123;
  &#64;Get('me')
  me(
    &#64;Username() username: string,
    &#64;Roles() roles: string[],
    &#64;Tenant() tenant: string | undefined,
  ) &#123;
    return &#123; username, roles, tenant &#125;;
  &#125;
&#125;</app-code>
    <p>Details on the <a routerLink="/parameter-decorators">Parameter decorators</a> page.</p>

    <h3>4. Secure an endpoint</h3>
    <app-code lang="ts">import &#123; Controller, Get &#125; from '&#64;nestjs/common';
import &#123; GrantedTo, and, isAuthenticated, hasRole &#125; from '&#64;softwarity/nestjs-granted';

&#64;Controller('admin')
export class AdminController &#123;
  &#64;Get('reports')
  &#64;GrantedTo(and(isAuthenticated(), hasRole('ADMIN')))
  reports() &#123;
    return /* ... */;
  &#125;
&#125;</app-code>
    <p>
      A route with <strong>no</strong> <code>&#64;GrantedTo</code> is open. A route with
      <code>&#64;GrantedTo(...)</code> passes only when <strong>every</strong> spec returns
      <code>true</code>. The full algebra (<code>and</code>, <code>or</code>, <code>not</code>,
      <code>hasRole</code>, <code>isAuthenticated</code>, <code>isUser</code>, …) lives on the
      <a routerLink="/boolean-specs">Boolean specifications</a> page.
    </p>

    <h3>Where identity comes from</h3>
    <p>
      By default the identity is read from request headers (<code>username</code>, <code>roles</code>,
      <code>tenant</code>). To decode it from a verified JWT instead, pass a
      <code>GrantedInfoJwtProvider</code> (with presets for Azure AD, Keycloak, Okta, RFC 9068) — or
      implement your own. See <a routerLink="/info-providers">Info providers</a>.
    </p>

    <h3>What's next</h3>
    <p>
      Read <a routerLink="/configuration">Configuration</a> for the module options,
      <a routerLink="/securing-endpoints">Securing endpoints</a> for the guard semantics and recipes,
      <a routerLink="/boolean-specs">Boolean specifications</a> for the full spec reference, or
      <a routerLink="/info-providers">Info providers</a> for header / JWT / custom identity sources.
    </p>
  `,
})
export class GettingStartedComponent {}
