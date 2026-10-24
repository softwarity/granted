import { Component } from '@angular/core';
import { CodeComponent } from '../code/code.component';

@Component({
  selector: 'app-roles',
  imports: [CodeComponent],
  template: `
    <h2>Roles</h2>
    <p>
      Two options of <code>forRoot</code> adjust the caller's roles before any rule runs. They work whatever the
      roles come from — headers or a JWT — and <code>&#64;Roles()</code> gives the adjusted list.
    </p>

    <h3>A role implies others — <code>roleHierarchy</code></h3>
    <app-code lang="ts">GrantedModule.forRoot(&#123;
  roleHierarchy: &#123;
    ADMIN: ['MANAGER'],
    MANAGER: ['USER'],
  &#125;,
&#125;);
// a caller with ['ADMIN'] passes hasRole('MANAGER') and hasRole('USER')</app-code>
    <p>No need to list <code>ADMIN</code> next to <code>USER</code> in your rules.</p>

    <h3>Ignore the roles meant for other services — <code>knownRoles</code></h3>
    <p>A token often carries the roles of every service. Keep only yours:</p>
    <app-code lang="ts">GrantedModule.forRoot(&#123;
  knownRoles: ['ORDER_READ', 'ORDER_WRITE', 'ORDER_ADMIN'],
&#125;);
// token roles ['ORDER_WRITE', 'BILLING_ADMIN', 'CRM_USER'] → ['ORDER_WRITE']</app-code>
    <p>With both options, the hierarchy is applied first: an implied role is kept if it is known.</p>
  `,
})
export class RolesComponent {}
