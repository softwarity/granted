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
          <td><code>infoProvider</code></td>
          <td><code>IGrantedInfoProvider</code></td>
          <td><code>new GrantedInfoProvider()</code></td>
          <td>
            Strategy that resolves the caller's identity. Defaults to reading HTTP headers. Swap for
            <code>GrantedInfoJwtProvider</code> or a custom one — see
            <a routerLink="/info-providers">Info providers</a>.
          </td>
        </tr>
      </tbody>
    </table>

    <h3>Minimal</h3>
    <app-code lang="ts">GrantedModule.forRoot()</app-code>
    <p>
      Equivalent to <code>forRoot(&#123; apply: true, infoProvider: new GrantedInfoProvider() &#125;)</code>
      — enforcement on, identity read from headers.
    </p>

    <h3>Disable enforcement per environment</h3>
    <p>
      Keep <code>&#64;GrantedTo</code> and the parameter decorators working, but let everything through —
      useful in a local or test profile:
    </p>
    <app-code lang="ts">GrantedModule.forRoot(&#123; apply: process.env['ENFORCE_RBAC'] !== 'false' &#125;)</app-code>

    <h3>Decode identity from a JWT</h3>
    <app-code lang="ts">import &#123; GrantedModule, GrantedInfoJwtProvider &#125; from '&#64;softwarity/nestjs-granted';

&#64;Module(&#123;
  imports: [
    GrantedModule.forRoot(&#123;
      apply: true,
      infoProvider: new GrantedInfoJwtProvider(&#123;
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
        <code>infoProvider</code> to the request so parameter decorators can read it.</li>
      <li><code>'GRANTED_MODULE_OPTIONS'</code> — the resolved options, exported for advanced use.</li>
    </ul>
  `,
})
export class ConfigurationComponent {}
