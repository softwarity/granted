import { Request } from 'express';
import { IncomingMessage } from 'http';
import { IGrantedPrincipalProvider } from './igranted-info.provider';

export interface GrantedPrincipalProviderConfig {
  /**
   * How the `roles` header is encoded:
   *  - `'json'` (default): a JSON array, e.g. `["ROLE1","ROLE2"]`
   *  - `'csv'`: a comma-separated string, e.g. `ROLE1, ROLE2`
   */
  rolesFormat?: 'json' | 'csv';
}

/**
 * Default provider: reads the identity from plain HTTP headers, as typically
 * forwarded by an upstream API gateway or auth proxy.
 *
 *  - `username` header (fallback `'anonymous'`)
 *  - `roles`    header — JSON array or CSV depending on `rolesFormat` (fallback `[]`)
 *  - `tenant`   header (optional, multi-tenant context)
 */
export class GrantedPrincipalProvider implements IGrantedPrincipalProvider {
  constructor(private readonly config: GrantedPrincipalProviderConfig = {}) {}

  getUsernameFromRequest(request: Request): string {
    return request.header('username') || 'anonymous';
  }

  getRolesFromRequest(request: Request): string[] {
    return this.parseRoles(request.header('roles'));
  }

  getTenantFromRequest(request: Request): string | undefined {
    return request.header('tenant') || undefined;
  }

  getUsernameFromIncomingMessage(incomingMessage: IncomingMessage): string {
    return (incomingMessage.headers['username'] || 'anonymous') as string;
  }

  getRolesFromIncomingMessage(incomingMessage: IncomingMessage): string[] {
    return this.parseRoles(incomingMessage.headers['roles'] as string);
  }

  getTenantFromIncomingMessage(incomingMessage: IncomingMessage): string | undefined {
    return (incomingMessage.headers['tenant'] as string) || undefined;
  }

  private parseRoles(raw?: string): string[] {
    if (!raw) {
      return [];
    }
    if (this.config.rolesFormat === 'csv') {
      return raw
        .split(',')
        .map((role) => role.trim())
        .filter((role) => role.length > 0);
    }
    return JSON.parse(raw);
  }
}
