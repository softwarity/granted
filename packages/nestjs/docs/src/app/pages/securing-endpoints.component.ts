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

    <h3>Ownership: authenticated is not authorized</h3>
    <p>
      <code>hasRole</code> and <code>isAuthenticated</code> answer <em>"is this a valid, logged-in
      caller?"</em>. They do <strong>not</strong> answer <em>"does the specific record this request
      targets actually belong to that caller?"</em>. That gap is the most common API vulnerability —
      <strong>IDOR</strong> (Insecure Direct Object Reference): a perfectly authenticated user simply
      changes an id in the URL or the request body and operates on someone else's data.
    </p>

    <div class="callout danger">
      <strong>The attack.</strong> Your <code>POST /orders</code> is protected by
      <code>&#64;GrantedTo(isAuthenticated())</code>. Mallory is a legitimate, logged-in user. She forges
      the request body so the order is booked against <em>Alice's</em> account:
      <app-code lang="bash">curl -X POST https://api.example.com/orders \\
  -H 'authorization: Bearer &lt;mallory's valid token&gt;' \\
  -H 'content-type: application/json' \\
  -d '&#123; "customer": &#123; "id": "alice" &#125;, "items": [ ... ] &#125;'</app-code>
      Authentication passes — Mallory's token is real. Nothing checks that
      <code>body.customer.id</code> is <em>her own</em> id, so the order lands on Alice's account.
    </div>

    <p>
      <code>isUser</code> closes the gap: it pulls a value <strong>from the request itself</strong> — a
      route param, a query param, or a dotted body path — and requires it to equal the caller's
      <code>username</code>. The id Mallory is trying to write is checked against who she actually is.
    </p>
    <app-code lang="ts">// WRITE — the owner declared in the body must be the caller
&#64;Post('orders')
&#64;GrantedTo(and(isAuthenticated(), or(hasRole('ADMIN'), isUser('Body', 'customer.id'))))
createOrder() &#123; /* body.customer.id === caller, or caller is ADMIN */ &#125;

// READ / UPDATE — the resource owner in the URL must be the caller
&#64;Patch('users/:userId/profile')
&#64;GrantedTo(or(hasRole('ADMIN'), isUser('Param', 'userId')))
updateProfile(&#64;Param('userId') userId: string) &#123; /* ... */ &#125;</app-code>
    <p>
      Now Mallory's forged POST is rejected with <code>403</code> (<code>body.customer.id = 'alice'</code>
      ≠ <code>'mallory'</code>), and she can't read <code>/users/alice/profile</code> by swapping the id.
      Admins still pass, thanks to the <code>or(hasRole('ADMIN'), …)</code>.
    </p>

    <h3>Cross-tenant: the same attack, one level up</h3>
    <p>
      In a multi-tenant API the same forging happens against the <em>tenant</em>: a user of tenant
      <code>acme</code> changes the URL (or body) to point at tenant <code>globex</code>.
      <code>isTenant</code> is the exact analogue of <code>isUser</code>, comparing the
      <strong>requested</strong> tenant against the caller's <strong>claimed</strong> tenant (from the
      token / headers, never from the attacker-controlled payload):
    </p>
    <app-code lang="ts">&#64;Post('tenants/:tenantId/invoices')
&#64;GrantedTo(and(isAuthenticated(), or(hasRole('ADMIN'), isTenant('Param', 'tenantId'))))
createInvoice(&#64;Tenant() tenant: string | undefined) &#123;
  // guard already proved tenantId === caller's tenant;
  // still scope the data layer too: WHERE tenant_id = tenant
&#125;</app-code>
    <p>
      A request for <code>/tenants/globex/invoices</code> coming from an <code>acme</code> token is
      rejected before the handler runs.
    </p>

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
