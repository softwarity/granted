import { Component } from '@angular/core';
import { RouterLink } from '@angular/router';
import { CodeComponent } from '../code/code.component';

@Component({
  selector: 'app-parameter-decorators',
  imports: [CodeComponent, RouterLink],
  template: `
    <h2>Parameter decorators</h2>

    <p>
      Three parameter decorators inject the resolved identity into your route handlers. Order doesn't
      matter — resolution is by decorator, not by position. Each one delegates to the configured
      <a routerLink="/info-providers">principal provider</a>, so the <em>source</em> of the value (headers vs.
      JWT vs. custom) is decided once in <code>forRoot</code>, not at the call site.
    </p>

    <table>
      <thead>
        <tr><th>Decorator</th><th>Injects</th><th>Default provider source</th></tr>
      </thead>
      <tbody>
        <tr>
          <td><code>&#64;Username()</code></td>
          <td><code>string</code></td>
          <td>header <code>username</code> (fallback <code>'anonymous'</code>)</td>
        </tr>
        <tr>
          <td><code>&#64;Roles()</code></td>
          <td><code>string[]</code></td>
          <td>header <code>roles</code> (fallback <code>[]</code>)</td>
        </tr>
        <tr>
          <td><code>&#64;Tenant()</code></td>
          <td><code>string | undefined</code></td>
          <td>header <code>tenant</code> (fallback <code>undefined</code>)</td>
        </tr>
      </tbody>
    </table>

    <div class="callout">
      <code>&#64;Roles()</code> returns the <strong>processed</strong> roles — after
      <a routerLink="/configuration">role-hierarchy expansion and <code>knownRoles</code> filtering</a> —
      i.e. exactly the set the guard authorizes against, not the raw header/claim value.
    </div>

    <h3>Usage</h3>
    <app-code lang="ts">import &#123; Controller, Get &#125; from '&#64;nestjs/common';
import &#123; Username, Roles, Tenant &#125; from '&#64;softwarity/nestjs-granted';

&#64;Controller()
export class ProfileController &#123;
  &#64;Get('username')
  username(&#64;Username() userId: string): string &#123;
    return userId;
  &#125;

  &#64;Get('roles')
  roles(&#64;Roles() roles: string[]): string[] &#123;
    return roles;
  &#125;

  &#64;Get('tenant')
  tenant(&#64;Tenant() tenant: string | undefined): string | undefined &#123;
    return tenant;
  &#125;
&#125;</app-code>

    <h3>Combine with everything else</h3>
    <p>Inject identity and standard NestJS decorators side by side, with a guard on top:</p>
    <app-code lang="ts">&#64;Get('orders/:userId')
&#64;GrantedTo(or(hasRole('ADMIN'), isUser('Param', 'userId')))
findOrders(
  &#64;Param('userId') userId: string,
  &#64;Username() me: string,
  &#64;Roles() roles: string[],
) &#123;
  // me === userId here, unless the caller is an ADMIN
&#125;</app-code>

    <h3>Tenant — for data scoping, not authorization</h3>
    <p>
      <code>&#64;Tenant()</code> exposes the caller's tenant in a multi-tenant deployment. Use it to
      <strong>scope data access</strong> — roles say <em>which</em> actions are allowed, the tenant says
      <em>on which data</em>. It is never read by the <a routerLink="/securing-endpoints">guard</a>.
    </p>
    <app-code lang="ts">&#64;Get('invoices')
&#64;GrantedTo(and(isAuthenticated(), hasRole('ACCOUNTANT')))
listInvoices(&#64;Tenant() tenant: string | undefined) &#123;
  return this.invoices.find(&#123; where: &#123; tenantId: tenant &#125; &#125;);
&#125;</app-code>

    <div class="callout">
      <strong>How it works:</strong> the global interceptor attaches the configured provider onto the
      incoming message, and each decorator reads from it via
      <code>getXxxFromIncomingMessage(...)</code>. That's why decorators keep working even when the
      module is in <code>apply: false</code> mode — identity injection and enforcement are independent.
    </div>

    <h3>Changing the source</h3>
    <p>
      Want <code>&#64;Roles()</code> to come from a JWT claim (e.g. <code>groups</code>) instead of a
      header? You don't touch the handlers — you swap the provider in <code>forRoot</code>. See
      <a routerLink="/info-providers">Principal providers</a>.
    </p>
  `,
})
export class ParameterDecoratorsComponent {}
