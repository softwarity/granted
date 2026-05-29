import { Component } from '@angular/core';
import { RouterLink } from '@angular/router';
import { CodeComponent } from '../code/code.component';

@Component({
  selector: 'app-configuration',
  imports: [CodeComponent, RouterLink],
  template: `
    <h2>Configuration</h2>

    <p>
      The module is configured once, at the root, via <code>GrantedModule.forRoot(options)</code>. It
      registers a global guard and a global interceptor, so every controller is covered without extra
      wiring.
    </p>

    <h3>Options</h3>
    <table>
      <thead>
        <tr><th>Option</th><th>Type</th><th>Default</th><th>Purpose</th></tr>
      </thead>
      <tbody>
        <tr>
          <td><code>apply</code></td>
          <td><code>boolean</code></td>
          <td><code>true</code></td>
          <td>
            Master switch. When <code>false</code>, the guard lets <strong>every</strong> request
            through regardless of <code>&#64;GrantedTo</code> — handy to disable enforcement per
            environment (local dev, tests) while keeping identity injection working.
          </td>
        </tr>
        <tr>
          <td><code>principalProvider</code></td>
          <td><code>IGrantedPrincipalProvider</code></td>
          <td><code>new GrantedPrincipalProvider()</code></td>
          <td>
            Strategy that resolves the caller's identity. Defaults to reading HTTP headers. Swap for
            <code>GrantedJwtPrincipalProvider</code> or a custom one — see
            <a routerLink="/info-providers">Principal providers</a>.
          </td>
        </tr>
        <tr>
          <td><code>knownRoles</code></td>
          <td><code>string[]</code></td>
          <td><em>(all)</em></td>
          <td>
            Roles this module knows about. When set, any resolved role outside the set is dropped — so a
            shared token carrying roles for other modules doesn't pollute this module's view. Leave
            undefined to keep every role.
          </td>
        </tr>
        <tr>
          <td><code>roleHierarchy</code></td>
          <td><code>Record&lt;string, string[]&gt;</code></td>
          <td><em>(none)</em></td>
          <td>
            A role mapped to the roles it implies, expanded transitively: holding a role grants its
            implied roles for both the guard and <code>&#64;Roles()</code>.
          </td>
        </tr>
      </tbody>
    </table>

    <h3>Known roles — keep your view clean</h3>
    <p>
      A gateway often issues one token whose <code>roles</code> span several services. Declare the roles
      <em>this</em> module cares about and the rest are silently dropped from both authorization and the
      injected <code>&#64;Roles()</code>:
    </p>
    <app-code lang="ts">GrantedModule.forRoot(&#123;
  knownRoles: ['ORDER_READ', 'ORDER_WRITE', 'ORDER_ADMIN'],
&#125;);
// token roles ['ORDER_WRITE', 'BILLING_ADMIN', 'CRM_USER'] → seen as ['ORDER_WRITE']</app-code>

    <h3>Role hierarchy — implied roles</h3>
    <p>
      Map a role to the roles it implies. Expansion is transitive and cycle-safe, applied
      <strong>before</strong> <code>knownRoles</code> filtering. With the hierarchy below, an
      <code>ORDER_ADMIN</code> automatically satisfies <code>hasRole('ORDER_WRITE')</code> and
      <code>hasRole('ORDER_READ')</code>:
    </p>
    <app-code lang="ts">GrantedModule.forRoot(&#123;
  roleHierarchy: &#123;
    ORDER_ADMIN: ['ORDER_WRITE'],
    ORDER_WRITE: ['ORDER_READ'],
  &#125;,
&#125;);
// caller holds ['ORDER_ADMIN'] → guard &amp; @Roles() see ['ORDER_ADMIN', 'ORDER_WRITE', 'ORDER_READ']</app-code>

    <h3>Minimal</h3>
    <app-code lang="ts">GrantedModule.forRoot()</app-code>
    <p>
      Equivalent to <code>forRoot(&#123; apply: true, principalProvider: new GrantedPrincipalProvider() &#125;)</code>
      — enforcement on, identity read from headers.
    </p>

    <h3>Disable enforcement per environment</h3>
    <p>
      Keep <code>&#64;GrantedTo</code> and the parameter decorators working, but let everything through —
      useful in a local or test profile:
    </p>
    <app-code lang="ts">GrantedModule.forRoot(&#123; apply: process.env['ENFORCE_RBAC'] !== 'false' &#125;)</app-code>

    <h3>Decode identity from a JWT</h3>
    <app-code lang="ts">import &#123; GrantedModule, GrantedJwtPrincipalProvider &#125; from '&#64;softwarity/nestjs-granted';

&#64;Module(&#123;
  imports: [
    GrantedModule.forRoot(&#123;
      apply: true,
      principalProvider: new GrantedJwtPrincipalProvider(&#123;
        algorithm: 'RS256',
        pemFile: 'config/jwt_public_key.pem',
      &#125;),
    &#125;),
  ],
&#125;)
export class AppModule &#123;&#125;</app-code>

    <div class="callout">
      <strong>No <code>forRootAsync</code> (yet).</strong> Options are resolved synchronously at module
      construction. If your public key or <code>apply</code> flag comes from async config, read it before
      bootstrap (e.g. load the PEM from disk, or read <code>process.env</code>) and pass the resolved
      value into <code>forRoot</code>.
    </div>

    <h3>What gets registered</h3>
    <p>Under the hood, <code>forRoot</code> provides three things in the module:</p>
    <ul>
      <li><code>APP_GUARD</code> → <code>AppGuard</code> — evaluates <code>&#64;GrantedTo</code> specs.</li>
      <li><code>APP_INTERCEPTOR</code> → <code>GlobalInterceptor</code> — attaches the resolved
        <code>principalProvider</code> to the request so parameter decorators can read it.</li>
      <li><code>'GRANTED_MODULE_OPTIONS'</code> — the resolved options, exported for advanced use.</li>
    </ul>
  `,
})
export class ConfigurationComponent {}
