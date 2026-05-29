import { Component } from '@angular/core';
import { RouterLink } from '@angular/router';
import { CodeComponent } from '../code/code.component';

@Component({
  selector: 'app-boolean-specs',
  imports: [CodeComponent, RouterLink],
  template: `
    <h2>Boolean specifications</h2>

    <p>
      A <code>BooleanSpec</code> is a tiny, composable predicate over the current request and identity.
      They are the building blocks passed to <a routerLink="/securing-endpoints">
      <code>&#64;GrantedTo</code></a>. Every spec is a plain object, so you can store them in constants,
      pass them around, and compose them freely.
    </p>

    <app-code lang="ts">interface BooleanSpec &#123;
  id: string; // human-readable description, e.g. "and(isAuthenticated(),hasRole(ADMIN))"
  apply(request: Request, username: string, roles: string[], tenant?: string): boolean;
&#125;</app-code>

    <div class="callout">
      Each spec receives the Express <code>request</code>, plus the resolved <code>username</code>,
      <code>roles</code> and <code>tenant</code>. The <code>tenant</code> argument is optional, so custom
      specs written against the older three-parameter shape stay valid.
    </div>

    <h3>Reference</h3>
    <table>
      <thead>
        <tr><th>Spec</th><th>Passes when…</th></tr>
      </thead>
      <tbody>
        <tr>
          <td><code>isAuthenticated()</code></td>
          <td><code>username</code> is set and is not <code>'anonymous'</code>.</td>
        </tr>
        <tr>
          <td><code>hasRole(role: string)</code></td>
          <td>
            <code>roles</code> includes <code>role</code> — after
            <a routerLink="/configuration">hierarchy expansion</a>, so an implied role matches too.
          </td>
        </tr>
        <tr>
          <td><code>isUser(type, field)</code></td>
          <td>
            the request value at <code>field</code> equals <code>username</code>.
            <code>type</code> is <code>'Param'</code>, <code>'Query'</code> or <code>'Body'</code>;
            for <code>'Body'</code>, <code>field</code> may be a dotted path (e.g. <code>customer.id</code>).
          </td>
        </tr>
        <tr>
          <td><code>isTenant(type, field)</code></td>
          <td>
            the request value at <code>field</code> equals the caller's <code>tenant</code>. Same
            <code>type</code> / dotted-path rules as <code>isUser</code>. Denies when the caller has no
            tenant. Blocks cross-tenant access.
          </td>
        </tr>
        <tr>
          <td><code>and(...specs)</code></td>
          <td>every nested spec passes.</td>
        </tr>
        <tr>
          <td><code>or(...specs)</code></td>
          <td>at least one nested spec passes.</td>
        </tr>
        <tr>
          <td><code>not(spec)</code></td>
          <td>the nested spec does <em>not</em> pass.</td>
        </tr>
        <tr>
          <td><code>isTrue()</code></td>
          <td>always — an explicit "allow".</td>
        </tr>
        <tr>
          <td><code>isFalse()</code></td>
          <td>never — an explicit "deny" (lock a route).</td>
        </tr>
      </tbody>
    </table>

    <h3>Composing</h3>
    <app-code lang="ts">import &#123;
  and, or, not, hasRole, isAuthenticated, isUser,
&#125; from '&#64;softwarity/nestjs-granted';

// Authenticated AND (admin OR the resource owner)
and(
  isAuthenticated(),
  or(hasRole('ADMIN'), isUser('Param', 'userId')),
);

// Authenticated AND not suspended
and(isAuthenticated(), not(hasRole('SUSPENDED')));</app-code>

    <h3>isUser in detail</h3>
    <p>
      <code>isUser</code> answers the question role checks <em>can't</em>: not "is the caller logged
      in?" but "does the record this request points at belong to the caller?". It reads the target id
      <strong>straight from the request</strong> and compares it to the caller's <code>username</code> —
      closing the door on <strong>IDOR</strong>, where an authenticated user swaps an id in the URL or
      body to act on someone else's data (see the
      <a routerLink="/ownership">forged-POST scenario</a>).
    </p>
    <app-code lang="ts">isUser('Param', 'userId')        // request.params.userId === username
isUser('Query', 'owner')         // request.query.owner   === username
isUser('Body', 'customer.id')    // request.body.customer.id === username</app-code>
    <p>
      The compared value comes from whatever the client sent — so the check is precisely
      <em>"the thing you're trying to read/update/create is yours"</em>. For <code>'Body'</code>, a
      missing path resolves to a non-match (returns <code>false</code>) rather than throwing — a
      malformed or partial body can never accidentally grant access.
    </p>

    <h3>isTenant — block cross-tenant access</h3>
    <p>
      The multi-tenant counterpart of <code>isUser</code>: it matches a request value against the
      <em>caller's</em> tenant (resolved by the <a routerLink="/info-providers">principal provider</a>), to stop
      a user of tenant A from reaching another tenant's resources.
    </p>
    <app-code lang="ts">// admin can reach any tenant; everyone else only their own
&#64;Get('tenants/:tenantId/invoices')
&#64;GrantedTo(and(isAuthenticated(), or(hasRole('ADMIN'), isTenant('Param', 'tenantId'))))
listInvoices() &#123; /* ... */ &#125;</app-code>
    <p>
      <code>isTenant</code> <strong>denies</strong> when the caller carries no tenant, or when the
      requested value is absent. It is a route-boundary guard — keep applying data-layer scoping
      (<code>WHERE tenant_id = ?</code>) with the injected
      <a routerLink="/parameter-decorators"><code>&#64;Tenant()</code></a> value as well.
    </p>

    <h3>The <code>id</code> field</h3>
    <p>
      Every spec carries a readable <code>id</code> describing the composed expression — useful for
      logging or debugging an authorization decision:
    </p>
    <app-code lang="ts">and(isAuthenticated(), hasRole('ADMIN')).id;
// "and(isAuthenticated(),hasRole(ADMIN))"</app-code>

    <h3>Custom specs</h3>
    <p>
      A spec is just an object with an <code>id</code> and an <code>apply</code> function — write your own
      when the built-ins aren't enough (e.g. read a custom header or a query flag):
    </p>
    <app-code lang="ts">import &#123; BooleanSpec &#125; from '&#64;softwarity/nestjs-granted';
import &#123; Request &#125; from 'express';

export function hasScope(scope: string): BooleanSpec &#123;
  return &#123;
    id: \`hasScope(\$&#123;scope&#125;)\`,
    apply: (req: Request) =&gt; (req.header('x-scopes') ?? '').split(' ').includes(scope),
  &#125;;
&#125;</app-code>
  `,
})
export class BooleanSpecsComponent {}
