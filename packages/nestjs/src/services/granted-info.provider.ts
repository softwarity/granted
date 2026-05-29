import { Request } from 'express';
import { IncomingMessage } from 'http';
import { IGrantedInfoProvider } from './igranted-info.provider';

/**
 * Default provider: reads the identity from plain HTTP headers, as typically
 * forwarded by an upstream API gateway or auth proxy.
 *
 *  - `username` header (fallback `'anonymous'`)
 *  - `roles`    header, JSON-encoded array (fallback `[]`)
 *  - `tenant`   header (optional, multi-tenant context)
 */
export class GrantedInfoProvider implements IGrantedInfoProvider {
  getUsernameFromRequest(request: Request): string {
    return request.header('username') || 'anonymous';
  }

  getRolesFromRequest(request: Request): string[] {
    return JSON.parse(request.header('roles') || '[]');
  }

  getTenantFromRequest(request: Request): string | undefined {
    return request.header('tenant') || undefined;
  }

  getUsernameFromIncomingMessage(incomingMessage: IncomingMessage): string {
    return (incomingMessage.headers['username'] || 'anonymous') as string;
  }

  getRolesFromIncomingMessage(incomingMessage: IncomingMessage): string[] {
    return JSON.parse((incomingMessage.headers['roles'] as string) || '[]');
  }

  getTenantFromIncomingMessage(incomingMessage: IncomingMessage): string | undefined {
    return (incomingMessage.headers['tenant'] as string) || undefined;
  }
}
