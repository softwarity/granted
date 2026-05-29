import { Component } from '@angular/core';
import { RouterLink } from '@angular/router';
import { CodeComponent } from '../code/code.component';

@Component({
  selector: 'app-securing-endpoints',
  imports: [CodeComponent, RouterLink],
  template: `
    <h2>Securing endpoints</h2>

    <p>
      Authorization is expressed with the <code>&#64;GrantedTo(...)</code> method decorator. It attaches
      one or more <a routerLink="/boolean-specs">boolean specifications</a> to the route; the global
      <code>AppGuard</code> evaluates them on every request.
    </p>

    <app-code lang="ts">GrantedTo(...booleanSpecs: BooleanSpec[]): MethodDecorator</app-code>

    <h3>The rule</h3>
    <ul>
      <li>No <code>&#64;GrantedTo</code> on a handler → the route is <strong>open</strong>.</li>
      <li>
        <code>&#64;GrantedTo(a, b, c)</code> → the request passes only if <strong>every</strong> spec
        returns <code>true</code> (the arguments are implicitly <code>and</code>-ed).
      </li>
      <li>
        When the module is configured with <code>apply: false</code>, the guard short-circuits and lets
        everything through. See <a routerLink="/configuration">Configuration</a>.
      </li>
    </ul>

    <p>
      On rejection the guard's <code>canActivate</code> returns <code>false</code>, which NestJS turns
      into a <strong><code>403 Forbidden</code></strong>.
    </p>

    <h3>Basic — role gate</h3>
    <app-code lang="ts">&#64;Get('reports')
&#64;GrantedTo(and(isAuthenticated(), hasRole('ADMIN')))
reports() &#123; /* ... */ &#125;</app-code>

    <h3>Multiple arguments are AND-ed</h3>
    <p>These two forms are equivalent:</p>
    <app-code lang="ts">&#64;GrantedTo(isAuthenticated(), hasRole('ADMIN'))
// same as
&#64;GrantedTo(and(isAuthenticated(), hasRole('ADMIN')))</app-code>

    <h3>OR between roles</h3>
    <app-code lang="ts">&#64;Get('billing')
&#64;GrantedTo(and(isAuthenticated(), or(hasRole('ADMIN'), hasRole('ACCOUNTANT'))))
billing() &#123; /* ... */ &#125;</app-code>

    <h3>Owner-or-admin (resource ownership)</h3>
    <p>
      <code>isUser</code> compares the authenticated <code>username</code> with a value pulled from the
      request — a route param, a query param, or a dotted body path — to express
      <em>"you may only touch your own resource, unless you're an admin"</em>:
    </p>
    <app-code lang="ts">&#64;Patch('users/:userId/profile')
&#64;GrantedTo(or(hasRole('ADMIN'), isUser('Param', 'userId')))
updateProfile(&#64;Param('userId') userId: string) &#123; /* ... */ &#125;

&#64;Post('orders')
&#64;GrantedTo(or(hasRole('ADMIN'), isUser('Body', 'customer.id')))
createOrder() &#123; /* ... */ &#125;</app-code>

    <h3>Cross-tenant protection</h3>
    <p>
      In a multi-tenant API, <code>isTenant</code> ensures the tenant addressed by the request matches the
      caller's own tenant — admins excepted:
    </p>
    <app-code lang="ts">&#64;Get('tenants/:tenantId/invoices')
&#64;GrantedTo(and(isAuthenticated(), or(hasRole('ADMIN'), isTenant('Param', 'tenantId'))))
listInvoices(&#64;Tenant() tenant: string | undefined) &#123;
  // also scope the data: WHERE tenant_id = tenant
&#125;</app-code>

    <h3>Negation and constants</h3>
    <app-code lang="ts">// Everyone except a banned role
&#64;GrantedTo(and(isAuthenticated(), not(hasRole('SUSPENDED'))))

// Temporarily lock a route without deleting the handler
&#64;GrantedTo(isFalse())</app-code>

    <h3>Factoring common policies</h3>
    <p>Specs are plain values — build your own vocabulary once and reuse it:</p>
    <app-code lang="ts">// security/policies.ts
import &#123; and, or, hasRole, isAuthenticated, isUser &#125; from '&#64;softwarity/nestjs-granted';

export const adminOnly = and(isAuthenticated(), hasRole('ADMIN'));
export const ownerOrAdmin = (param: string) =&gt; or(hasRole('ADMIN'), isUser('Param', param));</app-code>
    <app-code lang="ts">&#64;Delete('users/:userId')
&#64;GrantedTo(ownerOrAdmin('userId'))
remove() &#123; /* ... */ &#125;</app-code>

    <div class="callout">
      <strong>What the guard reads:</strong> <code>username</code>, <code>roles</code>, and — through
      <code>isTenant</code> — <code>tenant</code>. The <code>tenant</code> check only verifies a
      <em>requested</em> tenant against the <em>claimed</em> one; you still scope <em>which data</em> an
      action touches at the data layer with the injected
      <a routerLink="/parameter-decorators"><code>&#64;Tenant()</code></a> value. If your IdP exposes
      authorities under a different claim (e.g. <code>groups</code>), map it to roles in the
      <a routerLink="/info-providers">provider</a> rather than gating on a separate channel.
    </div>
  `,
})
export class SecuringEndpointsComponent {}
