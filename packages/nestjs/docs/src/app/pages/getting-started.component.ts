import { Component } from '@angular/core';
import { RouterLink } from '@angular/router';
import { CodeComponent } from '../code/code.component';

@Component({
  selector: 'app-getting-started',
  imports: [CodeComponent, RouterLink],
  styles: [
    `
      .cards {
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
        gap: 12px;
        margin: 0 0 28px 0;
      }
      .card {
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
      .card:hover {
        border-color: var(--accent-purple);
        background-color: rgba(163, 113, 247, 0.1);
        text-decoration: none;
        transform: translateY(-1px);
      }
      .card-icon {
        font-size: 1.6rem;
        line-height: 1;
        color: var(--accent-purple);
      }
      .card-title {
        font-weight: 600;
        color: var(--text-primary);
        font-size: 0.95rem;
      }
      .card-desc {
        color: var(--text-secondary);
        font-size: 0.85rem;
        line-height: 1.45;
      }
    `,
  ],
  template: `
    <h2>Getting started</h2>
    <p>
      <strong>&#64;softwarity/nestjs-granted</strong> decides, route by route, who may call your NestJS API.
      Put <code>&#64;GrantedTo(...)</code> on a route: a global guard checks it on every request. Your handlers
      read the caller with <code>&#64;Username()</code>, <code>&#64;Roles()</code> and <code>&#64;Tenant()</code>.
    </p>
    <div class="callout">
      It doesn't log anyone in. Something in front of your service — a gateway, an identity provider — has
      authenticated the caller and passes the identity on, as HTTP headers or as a JWT.
    </div>

    <h3>1. Install</h3>
    <app-code lang="bash">npm install &#64;softwarity/nestjs-granted</app-code>
    <p>Node.js ≥ 20 (≥ 20.19 or ≥ 22.12 with NestJS 12), NestJS 10 to 12, Express.</p>

    <h3>2. Register the module</h3>
    <app-code lang="ts">import &#123; Module &#125; from '&#64;nestjs/common';
import &#123; GrantedModule &#125; from '&#64;softwarity/nestjs-granted';

&#64;Module(&#123;
  imports: [GrantedModule.forRoot()],
&#125;)
export class AppModule &#123;&#125;</app-code>
    <p>
      The caller is read from the <code>username</code>, <code>roles</code> and <code>tenant</code> headers.
      Your requests carry a JWT instead? See <a routerLink="/info-providers">Where the identity comes from</a>.
    </p>

    <h3>3. Protect a route</h3>
    <app-code lang="ts">import &#123; Controller, Get &#125; from '&#64;nestjs/common';
import &#123; GrantedTo, hasRole, Username &#125; from '&#64;softwarity/nestjs-granted';

&#64;Controller('reports')
export class ReportsController &#123;
  &#64;Get()
  &#64;GrantedTo(hasRole('ADMIN'))
  list(&#64;Username() username: string) &#123;
    // only reached by an ADMIN
  &#125;
&#125;</app-code>
    <p>
      A route without <code>&#64;GrantedTo</code> is open. With it, the request gets a <code>403</code> unless every
      rule passes.
    </p>

    <h3>What do you want to do?</h3>
    <section class="cards">
      <a routerLink="/securing-endpoints" class="card">
        <span class="card-icon material-symbols-outlined">lock</span>
        <span class="card-title">Restrict a route</span>
        <span class="card-desc">To logged-in users, to a role, or to several conditions.</span>
      </a>
      <a routerLink="/securing-endpoints" class="card">
        <span class="card-icon material-symbols-outlined">verified_user</span>
        <span class="card-title">Users touch only their data</span>
        <span class="card-desc">Refuse a request naming someone else's id or tenant.</span>
      </a>
      <a routerLink="/parameter-decorators" class="card">
        <span class="card-icon material-symbols-outlined">badge</span>
        <span class="card-title">Read the caller</span>
        <span class="card-desc"><code>&#64;Username()</code>, <code>&#64;Roles()</code>, <code>&#64;Tenant()</code> in a handler.</span>
      </a>
      <a routerLink="/roles" class="card">
        <span class="card-icon material-symbols-outlined">account_tree</span>
        <span class="card-title">Shape the roles</span>
        <span class="card-desc">ADMIN implies USER; ignore the roles meant for other services.</span>
      </a>
      <a routerLink="/info-providers" class="card">
        <span class="card-icon material-symbols-outlined">key</span>
        <span class="card-title">Verify JWTs</span>
        <span class="card-desc">From a key file, a JWKS URL, or several identity providers.</span>
      </a>
      <a routerLink="/info-providers" class="card">
        <span class="card-icon material-symbols-outlined">hub</span>
        <span class="card-title">Let your services through</span>
        <span class="card-desc">The services of your cluster call each other with their pod's token.</span>
      </a>
      <a routerLink="/securing-endpoints" class="card">
        <span class="card-icon material-symbols-outlined">report</span>
        <span class="card-title">Understand a 403</span>
        <span class="card-desc">Log which rule refused the caller, without telling the caller.</span>
      </a>
      <a routerLink="/reference" class="card">
        <span class="card-icon material-symbols-outlined">settings</span>
        <span class="card-title">All the options</span>
        <span class="card-desc">Module, header provider and JWT provider.</span>
      </a>
    </section>
  `,
})
export class GettingStartedComponent {}
