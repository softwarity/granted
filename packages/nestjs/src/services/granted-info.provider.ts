import { Request } from 'express';
import { IncomingMessage } from 'http';
import { toRoleList } from '../security/roles.util';
import { IGrantedPrincipalProvider } from './igranted-info.provider';

export interface GrantedPrincipalProviderConfig {
  /**
   * How the roles header is encoded. Unset (the default), it is detected: a
   * value starting with `[` is a JSON array (`["ROLE1","ROLE2"]`), anything else
   * a comma-separated list (`ROLE1, ROLE2`). Set it to force one of them:
   *  - `'json'`: a JSON array only
   *  - `'csv'`: a comma-separated list only
   */
  rolesFormat?: 'json' | 'csv';
  /** Header carrying the username. Default `'username'`. */
  usernameHeader?: string;
  /** Header carrying the roles. Default `'roles'`. */
  rolesHeader?: string;
  /** Header carrying the tenant. Default `'tenant'`. */
  tenantHeader?: string;
}

/**
 * Default provider: reads the identity from plain HTTP headers, as typically
 * forwarded by an upstream API gateway or auth proxy. Header names are
 * configurable; defaults are `username`, `roles`, `tenant`.
 *
 *  - username header (fallback `'anonymous'`)
 *  - roles    header — JSON array or CSV, detected unless `rolesFormat` says (fallback `[]`)
 *  - tenant   header (optional, multi-tenant context)
 */
export class GrantedPrincipalProvider implements IGrantedPrincipalProvider {
  private readonly usernameHeader: string;
  private readonly rolesHeader: string;
  private readonly tenantHeader: string;

  constructor(private readonly config: GrantedPrincipalProviderConfig = {}) {
    this.usernameHeader = config.usernameHeader || 'username';
    this.rolesHeader = config.rolesHeader || 'roles';
    this.tenantHeader = config.tenantHeader || 'tenant';
  }

  getUsernameFromRequest(request: Request): string {
    return request.header(this.usernameHeader) || 'anonymous';
  }

  getRolesFromRequest(request: Request): string[] {
    return this.parseRoles(request.header(this.rolesHeader));
  }

  getTenantFromRequest(request: Request): string | undefined {
    return request.header(this.tenantHeader) || undefined;
  }

  getUsernameFromIncomingMessage(incomingMessage: IncomingMessage): string {
    return (this.readHeader(incomingMessage, this.usernameHeader) || 'anonymous') as string;
  }

  getRolesFromIncomingMessage(incomingMessage: IncomingMessage): string[] {
    return this.parseRoles(this.readHeader(incomingMessage, this.rolesHeader));
  }

  getTenantFromIncomingMessage(incomingMessage: IncomingMessage): string | undefined {
    return this.readHeader(incomingMessage, this.tenantHeader) || undefined;
  }

  /** The header of the same name, as a string — `@GrantedClaim` parses it. */
  getClaimFromIncomingMessage(incomingMessage: IncomingMessage, name: string): string | undefined {
    return this.readHeader(incomingMessage, name);
  }

  /** IncomingMessage header keys are lowercased by Node — normalise the lookup. */
  private readHeader(incomingMessage: IncomingMessage, name: string): string | undefined {
    return incomingMessage.headers[name.toLowerCase()] as string | undefined;
  }

  private parseRoles(raw?: string): string[] {
    return toRoleList(raw, this.config.rolesFormat);
  }
}
