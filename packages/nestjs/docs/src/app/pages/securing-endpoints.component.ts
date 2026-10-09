import { Component } from '@angular/core';
import { RouterLink } from '@angular/router';
import { CodeComponent } from '../code/code.component';

@Component({
  selector: 'app-securing-endpoints',
  imports: [CodeComponent, RouterLink],
  template: `
    <h2>Protect your routes</h2>
    <p>
      Put <code>&#64;GrantedTo(...)</code> on a route or a controller. The request gets through only if every rule
      passes; otherwise it gets a <code>403</code>. A route without <code>&#64;GrantedTo</code> is open.
    </p>

    <h3>Logged-in users only</h3>
    <app-code lang="ts">&#64;Get('profile')
&#64;GrantedTo(isAuthenticated())
profile() &#123;&#125;</app-code>

    <h3>A role</h3>
    <app-code lang="ts">&#64;Get('reports')
&#64;GrantedTo(hasRole('ADMIN'))
reports() &#123;&#125;</app-code>
    <p>An implied role counts too: with <code>ADMIN ⇒ USER</code>, an ADMIN passes <code>hasRole('USER')</code>. See <a routerLink="/roles">Roles</a>.</p>

    <h3>One role among several</h3>
    <app-code lang="ts">&#64;GrantedTo(or(hasRole('ADMIN'), hasRole('ACCOUNTANT')))</app-code>

    <h3>Several conditions</h3>
    <app-code lang="ts">// the arguments must all pass
&#64;GrantedTo(isAuthenticated(), not(hasRole('SUSPENDED')))</app-code>

    <h3>A whole controller</h3>
    <app-code lang="ts">&#64;Controller('admin')
&#64;GrantedTo(isAuthenticated())   // every route of the controller
export class AdminController &#123;
  &#64;Get('stats')
  stats() &#123;&#125;                    // logged-in users

  &#64;Get('config')
  &#64;GrantedTo(hasRole('ADMIN'))  // logged-in users that are ADMIN
  config() &#123;&#125;
&#125;</app-code>
    <p>
      A method adds conditions to its controller's, it can't remove them. If a route must stay open, don't put
      <code>&#64;GrantedTo</code> on the class: put it on each route instead.
    </p>

    <h3>Users may only touch their own data</h3>
    <p>
      A logged-in user can change an id in the URL or in the body to reach someone else's data. Roles don't
      stop that. <code>isUser</code> compares that id with the caller:
    </p>
    <app-code lang="ts">// PATCH /users/alice/profile, sent by mallory → 403
&#64;Patch('users/:userId/profile')
&#64;GrantedTo(or(hasRole('ADMIN'), isUser('Param', 'userId')))
updateProfile() &#123;&#125;

// POST /orders &#123; "customer": &#123; "id": "alice" &#125; &#125;, sent by mallory → 403
&#64;Post('orders')
&#64;GrantedTo(or(hasRole('ADMIN'), isUser('Body', 'customer.id')))
createOrder() &#123;&#125;</app-code>
    <div class="callout warn">
      This checks the id a request names. A route that <em>lists</em> records (<code>GET /orders</code>) must still
      filter its query by the caller, with <a routerLink="/parameter-decorators"><code>&#64;Username()</code></a>.
    </div>

    <h3>Users may only touch their own tenant</h3>
    <app-code lang="ts">// POST /tenants/globex/invoices, sent by a user of acme → 403
&#64;Post('tenants/:tenantId/invoices')
&#64;GrantedTo(or(hasRole('ADMIN'), isTenant('Param', 'tenantId')))
createInvoice() &#123;&#125;</app-code>
    <p>A caller without a tenant is refused. Filter your queries with <a routerLink="/parameter-decorators"><code>&#64;Tenant()</code></a> as well.</p>

    <h3>Reuse a rule</h3>
    <app-code lang="ts">// security/rules.ts
export const ownerOrAdmin = (param: string) =&gt; or(hasRole('ADMIN'), isUser('Param', param));

// users.controller.ts
&#64;Delete('users/:userId')
&#64;GrantedTo(ownerOrAdmin('userId'))
remove() &#123;&#125;</app-code>

    <h3>Write your own rule</h3>
    <app-code lang="ts">import &#123; BooleanSpec &#125; from '&#64;softwarity/nestjs-granted';

export const hasScope = (scope: string): BooleanSpec =&gt; (&#123;
  id: \`hasScope(\$&#123;scope&#125;)\`, // shown in the 403 details
  apply: (request, username, roles, tenant) =&gt; (request.header('x-scopes') ?? '').split(' ').includes(scope),
&#125;);</app-code>

    <h3>All the rules</h3>
    <table>
      <thead><tr><th>Rule</th><th>Passes when</th></tr></thead>
      <tbody>
        <tr><td><code>isAuthenticated()</code></td><td>the caller is known (not <code>anonymous</code>)</td></tr>
        <tr><td><code>hasRole('ADMIN')</code></td><td>the caller has the role, directly or <a routerLink="/roles">implied</a></td></tr>
        <tr><td><code>isUser('Param', 'userId')</code></td><td>the request value is the caller's username — <code>'Param'</code>, <code>'Query'</code> or <code>'Body'</code> (dotted path)</td></tr>
        <tr><td><code>isTenant('Param', 'tenantId')</code></td><td>the request value is the caller's tenant; refused when the caller has none</td></tr>
        <tr><td><code>and(a, b, …)</code></td><td>all pass</td></tr>
        <tr><td><code>or(a, b, …)</code></td><td>one passes</td></tr>
        <tr><td><code>not(a)</code></td><td><code>a</code> fails</td></tr>
        <tr><td><code>isTrue()</code> / <code>isFalse()</code></td><td>always / never — e.g. to lock a route</td></tr>
      </tbody>
    </table>

    <h3 id="denied">Why did a request get a 403?</h3>
    <p>
      The caller gets a bare <code>403</code>, with nothing about your rules. The details are on the exception —
      <code>GrantedForbiddenException</code> — for you to log:
    </p>
    <app-code lang="ts">&#64;Catch(GrantedForbiddenException)
export class DenialFilter extends BaseExceptionFilter &#123;
  private readonly logger = new Logger('Access');
  catch(e: GrantedForbiddenException, host: ArgumentsHost) &#123;
    // e.g. denied: user=bob roles=[USER] rule=hasRole(ADMIN)
    this.logger.debug(\`denied: user=\$&#123;e.username&#125; roles=[\$&#123;e.roles&#125;] rule=\$&#123;e.deniedSpec&#125;\`);
    super.catch(e, host);
  &#125;
&#125;

// main.ts
app.useGlobalFilters(new DenialFilter(app.getHttpAdapter()));</app-code>
    <p>
      <code>deniedSpec</code> is the first rule that failed, <code>roles</code> the roles it was checked against
      (after <a routerLink="/roles">hierarchy and filtering</a>), plus <code>username</code> and <code>tenant</code>.
    </p>
    <div class="callout warn">Don't send these details back: they tell an attacker what to forge.</div>

    <h3>Turn the checks off, in development or tests</h3>
    <app-code lang="ts">GrantedModule.forRoot(&#123; apply: process.env['ENFORCE_RBAC'] !== 'false' &#125;)</app-code>
    <p>Every request gets through; <code>&#64;Username()</code> and the other decorators keep working.</p>
  `,
})
export class SecuringEndpointsComponent {}
