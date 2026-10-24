import { Component } from '@angular/core';
import { RouterLink } from '@angular/router';
import { CodeComponent } from '../code/code.component';

@Component({
  selector: 'app-overview',
  imports: [CodeComponent, RouterLink],
  template: `
    <h2>Overview</h2>
    <p>
      <strong>granted</strong> decides, route by route, who may call your service. It doesn't log anyone in:
      something in front of your service — a gateway, an identity provider — has authenticated the caller and
      passes the identity on. granted reads it, checks what each route requires, and hands your code the caller.
    </p>
    <app-code lang="ts">// NestJS
&#64;Get('stations')
&#64;GrantedTo(hasRole('FORECASTER'))
list(&#64;Claim('territories', &#123; type: 'string', array: true &#125;) territories: string[]) &#123;
  return this.stations.find(&#123; where: &#123; territory: In(territories) &#125; &#125;);
&#125;</app-code>

    <h3>The model</h3>
    <table>
      <thead><tr><th></th><th>What it covers</th></tr></thead>
      <tbody>
        <tr>
          <td><strong>The caller</strong></td>
          <td>
            Read from the headers a gateway forwards (<code>username</code>, <code>roles</code>,
            <code>tenant</code>), or from a JWT verified with a key or the identity provider's JWKS. A missing or
            invalid token gives an anonymous caller, never an error.
          </td>
        </tr>
        <tr>
          <td><strong>Rules</strong></td>
          <td>
            Each route says what it requires — a role, being logged in, owning the record it names — and the
            rules combine with <code>and</code>, <code>or</code>, <code>not</code>. A request that fails one is
            refused with a <code>403</code>, and the reason is logged.
          </td>
        </tr>
        <tr>
          <td><strong>Roles</strong></td>
          <td>One role can imply others (<code>ADMIN</code> implies <code>USER</code>), and the roles meant for other services can be left out.</td>
        </tr>
        <tr>
          <td><strong>Claims</strong></td>
          <td>
            Roles decide <em>which actions</em> a caller may take; claims scope <em>which data</em> — the
            territories a tenant may touch, an amount it may not exceed.
          </td>
        </tr>
      </tbody>
    </table>

    <h3>Implementations</h3>
    <table>
      <thead><tr><th>Framework</th><th>Package</th><th>Status</th></tr></thead>
      <tbody>
        <tr>
          <td><a routerLink="/nestjs">NestJS</a></td>
          <td><code>&#64;softwarity/nestjs-granted</code> (npm)</td>
          <td>Available</td>
        </tr>
        <tr><td>Quarkus</td><td>—</td><td>In progress</td></tr>
        <tr><td>Go</td><td>—</td><td>Planned</td></tr>
      </tbody>
    </table>
    <div class="callout">
      Every implementation carries the same version: they implement the same behaviour, so two services on the
      same number — whatever their language — read the caller and decide the same way.
    </div>
  `,
})
export class OverviewComponent {}
