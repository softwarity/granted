import { Component } from '@angular/core';
import { RouterLink } from '@angular/router';
import { CodeComponent } from '../code/code.component';

@Component({
  selector: 'app-parameter-decorators',
  imports: [CodeComponent, RouterLink],
  template: `
    <h2>Read the caller</h2>
    <app-code lang="ts">&#64;Get('me')
me(&#64;Username() username: string, &#64;Roles() roles: string[], &#64;Tenant() tenant: string | undefined) &#123;
  return &#123; username, roles, tenant &#125;;
&#125;</app-code>
    <table>
      <thead><tr><th>Decorator</th><th>Gives</th><th>When the caller has none</th></tr></thead>
      <tbody>
        <tr><td><code>&#64;Username()</code></td><td><code>string</code></td><td><code>'anonymous'</code></td></tr>
        <tr><td><code>&#64;Roles()</code></td><td><code>string[]</code> — the roles the rules see, after <a routerLink="/roles">hierarchy and filtering</a></td><td><code>[]</code></td></tr>
        <tr><td><code>&#64;Tenant()</code></td><td><code>string | undefined</code></td><td><code>undefined</code></td></tr>
      </tbody>
    </table>
    <p>Where the values come from — headers, a JWT — is set once in <code>forRoot</code>: see <a routerLink="/info-providers">Where the identity comes from</a>.</p>

    <h3>Filter your data by caller</h3>
    <p>A rule refuses a request naming someone else's record. To return only the caller's records, filter the query:</p>
    <app-code lang="ts">&#64;Get('invoices')
&#64;GrantedTo(hasRole('ACCOUNTANT'))
list(&#64;Tenant() tenant: string) &#123;
  return this.invoices.find(&#123; where: &#123; tenantId: tenant &#125; &#125;);
&#125;</app-code>
  `,
})
export class ParameterDecoratorsComponent {}
