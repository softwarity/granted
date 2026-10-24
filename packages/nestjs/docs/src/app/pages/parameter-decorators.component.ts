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
        <tr><td><code>&#64;Claim(name, options?)</code></td><td>any other attribute of the caller — see below</td><td><code>undefined</code>, or <code>[]</code> for a list</td></tr>
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

    <h3>Any other claim — &#64;Claim</h3>
    <p>
      Roles decide <em>which</em> actions a caller may take; claims scope <em>which</em> data. When a tenant
      manages several territories and may only touch those, read them from the token — or from the gateway's
      headers — and filter by them:
    </p>
    <app-code lang="ts">&#64;Get('stations')
&#64;GrantedTo(hasRole('FORECASTER'))
list(&#64;Claim('territories', &#123; type: 'string', array: true &#125;) territories: string[]) &#123;
  return this.stations.find(&#123; where: &#123; territory: In(territories) &#125; &#125;);
&#125;</app-code>
    <p>
      The value comes from the same place as the rest of the identity: a claim of the <strong>verified</strong>
      JWT (dotted paths for nested claims, e.g. <code>'realm_access.territories'</code>), or the header of that
      name with the header provider — never from a header when the identity comes from a JWT.
    </p>
    <table>
      <thead><tr><th>Option</th><th>Type</th><th>Notes</th></tr></thead>
      <tbody>
        <tr><td><code>type</code></td><td><code>'string' | 'number' | 'boolean'</code></td><td>Expected type — of each element with <code>array</code>. Unchecked when unset.</td></tr>
        <tr><td><code>array</code></td><td><code>boolean</code></td><td>The value is a list. A single value is taken as a list of one.</td></tr>
        <tr><td><code>required</code></td><td><code>boolean</code></td><td>Refuse the request (403) when the claim is missing or doesn't have the expected type.</td></tr>
      </tbody>
    </table>
    <ul>
      <li>
        <strong>Strings are parsed.</strong> Headers only carry strings: with <code>array</code>, a JSON array
        (<code>["FR","GP"]</code>) or a comma-separated list (<code>FR, GP</code>); <code>number</code> and
        <code>boolean</code> convert strictly (<code>'5000'</code>, <code>'true'</code> / <code>'false'</code>).
        A string claim in a JWT is parsed the same way.
      </li>
      <li><strong>Missing</strong> gives <code>undefined</code> (<code>[]</code> with <code>array</code>, ready for an <code>IN (...)</code>).</li>
      <li>
        <strong>The wrong type</strong> — a number where strings are expected, a list where one value is — is
        treated as missing, with a warning naming the claim, never its value. In a list, only the elements of
        the wrong type are dropped (<code>['FR', 42, 'GP']</code> gives <code>['FR', 'GP']</code>), with a
        warning too; a list left empty counts as missing. A number or a boolean given as a string
        (<code>'42'</code>, <code>'true'</code>) converts: it isn't of the wrong type.
      </li>
      <li>Without options, the value is given as found.</li>
    </ul>
    <p>
      With <a routerLink="/info-providers">your own provider</a>, implement
      <code>getClaimFromIncomingMessage(msg, name)</code>, returning the value as found; without it, a route
      using <code>&#64;Claim</code> fails with an error naming the method.
    </p>
  `,
})
export class ParameterDecoratorsComponent {}
