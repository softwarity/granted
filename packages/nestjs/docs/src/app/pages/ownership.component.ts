import { Component } from '@angular/core';
import { RouterLink } from '@angular/router';
import { CodeComponent } from '../code/code.component';

@Component({
  selector: 'app-ownership',
  imports: [CodeComponent, RouterLink],
  template: `
    <h2>Resource ownership &amp; IDOR</h2>

    <p>
      This is the page to read if you take one thing away from the library.
      <a routerLink="/boolean-specs">Roles and <code>isAuthenticated</code></a> prove <strong>who the
      caller is</strong>. They say nothing about <strong>which record the request is allowed to
      touch</strong>. That missing check is the single most common API vulnerability —
      <strong>IDOR</strong> (Insecure Direct Object Reference, OWASP "Broken Object Level
      Authorization"): a perfectly valid, logged-in user changes an id in the URL or the request body
      and operates on <em>someone else's</em> data.
    </p>

    <p>
      <code>isUser</code> and <code>isTenant</code> exist for exactly this. Each reads a value
      <strong>from the request itself</strong> — a route param, a query param, or a dotted body path —
      and requires it to match the caller's identity (<code>username</code>) or
      <code>tenant</code>. In other words: <em>the thing you're trying to read, update, or create must
      be yours.</em>
    </p>

    <h3>isUser — "this record is mine"</h3>

    <p>
      Take a <code>POST /orders</code> endpoint guarded only by <code>isAuthenticated()</code>. Mallory
      is a legitimate, logged-in user. She doesn't break authentication — she <strong>forges the
      body</strong> so the order is booked against <em>Alice's</em> account:
    </p>

    <div class="callout danger">
      <strong>The attack — forging a write.</strong>
      <app-code lang="bash">curl -X POST https://api.example.com/orders \\
  -H 'authorization: Bearer &lt;mallory-valid-token&gt;' \\
  -H 'content-type: application/json' \\
  -d '&#123; "customer": &#123; "id": "alice" &#125;, "items": [ ... ] &#125;'</app-code>
      The token is real, so <code>isAuthenticated()</code> passes. Nothing checks that
      <code>body.customer.id</code> is <em>Mallory's own</em> id — the order lands on Alice's account.
    </div>

    <p>
      <code>isUser('Body', 'customer.id')</code> compares the id <strong>declared in the payload</strong>
      with the caller's real username. Mallory can only create orders for <code>'mallory'</code>:
    </p>

    <app-code lang="ts">// WRITE — the owner declared in the body must be the caller (admins excepted)
&#64;Post('orders')
&#64;GrantedTo(and(isAuthenticated(), or(hasRole('ADMIN'), isUser('Body', 'customer.id'))))
createOrder() &#123; /* reached only if body.customer.id === caller, or caller is ADMIN */ &#125;</app-code>

    <p>
      The same hole exists on reads and updates — the target id sits in the <strong>URL</strong> instead
      of the body. Without a check, Mallory reads Alice's profile just by typing her id:
    </p>

    <div class="callout danger">
      <strong>The attack — walking the ids (read IDOR).</strong>
      <app-code lang="bash">GET /users/alice/profile      # Mallory's token, Alice's id in the path
PATCH /users/alice/profile    # …and now editing it</app-code>
    </div>

    <app-code lang="ts">// READ / UPDATE — the resource owner in the URL must be the caller
&#64;Patch('users/:userId/profile')
&#64;GrantedTo(or(hasRole('ADMIN'), isUser('Param', 'userId')))
updateProfile(&#64;Param('userId') userId: string) &#123; /* userId === caller, or ADMIN */ &#125;</app-code>

    <p>
      Both forged requests now return <strong><code>403</code></strong>
      (<code>'alice'</code> ≠ <code>'mallory'</code>) <em>before the handler runs</em>. Admins still pass,
      thanks to the <code>or(hasRole('ADMIN'), …)</code> branch.
    </p>

    <h3>isTenant — "this tenant is mine"</h3>

    <p>
      In a multi-tenant API the exact same forging happens one level up — against the
      <strong>tenant</strong>. A user of tenant <code>acme</code> changes the URL (or body) to point at
      <code>globex</code> and reaches another customer's data:
    </p>

    <div class="callout danger">
      <strong>The attack — crossing tenants.</strong>
      <app-code lang="bash">POST /tenants/globex/invoices   # request carries an 'acme' token</app-code>
    </div>

    <p>
      <code>isTenant</code> is the precise analogue of <code>isUser</code>. It compares the
      <strong>requested</strong> tenant (from the URL/query/body — i.e. attacker-controlled) against the
      caller's <strong>claimed</strong> tenant (resolved by the
      <a routerLink="/info-providers">info provider</a> from the verified token or trusted headers —
      <em>never</em> the payload):
    </p>

    <app-code lang="ts">&#64;Post('tenants/:tenantId/invoices')
&#64;GrantedTo(and(isAuthenticated(), or(hasRole('ADMIN'), isTenant('Param', 'tenantId'))))
createInvoice(&#64;Tenant() tenant: string | undefined) &#123;
  // the guard already proved tenantId === caller's tenant
&#125;</app-code>

    <p>
      A request for <code>/tenants/globex/invoices</code> from an <code>acme</code> token is rejected.
      <code>isTenant</code> also <strong>denies</strong> when the caller carries no tenant at all, or when
      the requested value is absent — it fails closed.
    </p>

    <h3>Two layers, not one</h3>

    <div class="callout warn">
      <code>isUser</code> / <code>isTenant</code> guard the <strong>route boundary</strong>: they reject a
      request whose declared owner/tenant isn't the caller's. They are <strong>not</strong> a substitute
      for <strong>data-layer scoping</strong>. A <code>GET /orders</code> that lists records still needs a
      <code>WHERE owner = :caller</code> / <code>WHERE tenant_id = :tenant</code> clause — use the
      injected <a routerLink="/parameter-decorators"><code>&#64;Username()</code></a> and
      <code>&#64;Tenant()</code> values for that. Guard = "may you address this id?"; query = "which ids
      do you get back?".
    </div>

    <h3>Rules of thumb</h3>
    <ul>
      <li>Any id in the <strong>URL, query, or body</strong> that designates an owner or a tenant is
        attacker-controlled — pin it with <code>isUser</code> / <code>isTenant</code>.</li>
      <li>Pair it with an admin escape hatch: <code>or(hasRole('ADMIN'), isUser(...))</code>.</li>
      <li>Resolve identity and tenant from the <strong>verified token / trusted headers</strong>, never
        from the request body. The library already does this — the value compared against is never the
        payload.</li>
      <li>Still scope your queries at the data layer. The guard and the query answer two different
        questions.</li>
    </ul>
  `,
})
export class OwnershipComponent {}
