import { Component } from '@angular/core';
import { MatTabsModule } from '@angular/material/tabs';
import { RouterLink } from '@angular/router';
import { BrandComponent } from '../brand/brand.component';
import { CodeComponent } from '../code/code.component';

@Component({
  selector: 'app-overview',
  imports: [CodeComponent, RouterLink, MatTabsModule, BrandComponent],
  styles: [
    `
      .tab-label {
        display: inline-flex;
        align-items: center;
        gap: 8px;
      }
    `,
  ],
  template: `
    <h2>Overview</h2>
    <p>
      <strong>granted</strong> decides, route by route, who may call your service. It doesn't log anyone in:
      something in front of your service — a gateway, an identity provider — has authenticated the caller and
      passes the identity on. granted reads it, checks what each route requires, and hands your code the caller.
    </p>
    <p>The same route — forecasters, each on the territories of their tenant — in the three implementations:</p>
    <mat-tab-group animationDuration="0ms" mat-stretch-tabs="false">
      <mat-tab>
        <ng-template mat-tab-label><span class="tab-label"><app-brand brand="nestjs" /> NestJS</span></ng-template>
        <app-code lang="ts">&#64;Get('stations')
&#64;GrantedTo(hasRole('FORECASTER'))
list(&#64;GrantedClaim('territories', &#123; type: 'string', array: true &#125;) territories: string[]) &#123;
  return this.stations.find(&#123; where: &#123; territory: In(territories) &#125; &#125;);
&#125;</app-code>
      </mat-tab>
      <mat-tab>
        <ng-template mat-tab-label><span class="tab-label"><app-brand brand="quarkus" /> Quarkus</span></ng-template>
        <app-code lang="java">&#64;GET
&#64;Path("stations")
&#64;RolesAllowed("FORECASTER")
public List&lt;Station&gt; list(&#64;GrantedClaim("territories") List&lt;String&gt; territories) &#123;
    return Station.list("territory in ?1", territories);
&#125;</app-code>
      </mat-tab>
      <mat-tab>
        <ng-template mat-tab-label><span class="tab-label"><app-brand brand="go" /> Go</span></ng-template>
        <app-code lang="go">mux.Handle("GET /stations", g.Require(granted.HasRole("FORECASTER"))(http.HandlerFunc(list)))

func list(w http.ResponseWriter, r *http.Request) &#123;
	territories := granted.Claims[string](r.Context(), "territories")
	stations, err := store.StationsIn(r.Context(), territories)
	…
&#125;</app-code>
      </mat-tab>
    </mat-tab-group>

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
        <tr>
          <td><a routerLink="/quarkus">Quarkus</a></td>
          <td><code>io.softwarity:quarkus-granted</code> (Maven Central)</td>
          <td>Available</td>
        </tr>
        <tr>
          <td><a routerLink="/go">Go</a></td>
          <td><code>github.com/softwarity/granted/go/v5</code></td>
          <td>Available</td>
        </tr>
      </tbody>
    </table>
    <div class="callout">
      Every implementation carries the same version: they implement the same behaviour, so two services on the
      same number — whatever their language — read the caller and decide the same way.
    </div>
  `,
})
export class OverviewComponent {}
