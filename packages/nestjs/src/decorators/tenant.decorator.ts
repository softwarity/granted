import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { IncomingMessage } from 'http';
import { IGrantedPrincipalProvider } from '../services';

/**
 * Injects the caller's tenant identifier (multi-tenant context).
 *
 * The value is resolved by the configured {@link IGrantedPrincipalProvider}. It is
 * NOT used by the authorization guard — roles decide *which* actions are
 * allowed, the tenant scopes *which* data the action may touch (typically a
 * `WHERE tenant_id = ?` clause in your data layer).
 *
 * Returns `undefined` when no tenant is present on the request.
 */
export const Tenant = createParamDecorator((_config: void, ctx: ExecutionContext) => {
  const incomingMessage: IncomingMessage = ctx.switchToHttp().getRequest<IncomingMessage>();
  const grantedPrincipalProvider: IGrantedPrincipalProvider = incomingMessage['grantedPrincipalProvider'];
  return grantedPrincipalProvider.getTenantFromIncomingMessage(incomingMessage);
});
