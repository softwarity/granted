import { IGrantedPrincipalProvider } from '../services';

export class GrantedModuleOptions {
  /** Master switch. When `false`, the guard lets every request through. Defaults to `true`. */
  apply?: boolean;
  /** Strategy resolving the caller's identity. Defaults to a header-based `GrantedPrincipalProvider`. */
  principalProvider?: IGrantedPrincipalProvider;
  /**
   * Roles this module knows about. When set, any resolved role outside this set
   * is dropped — so a shared token carrying roles for other modules doesn't
   * pollute this module's view. Leave undefined to keep every role.
   */
  knownRoles?: string[];
  /**
   * Role hierarchy: a role mapped to the roles it implies. Expanded
   * transitively, so `{ ADMIN: ['MANAGER'], MANAGER: ['USER'] }` makes an
   * `ADMIN` implicitly a `MANAGER` and a `USER`. Leave undefined for no implication.
   */
  roleHierarchy?: Record<string, string[]>;
}
