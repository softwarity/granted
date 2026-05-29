import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { IncomingMessage } from 'http';
import { GrantedModuleOptions } from '../models/granted-module-options';
import { resolveRoles } from '../security/roles.util';
import { IGrantedInfoProvider } from '../services';

/**
 * Injects the caller's roles, after the module's hierarchy expansion and
 * known-roles filtering — i.e. the same set the guard authorizes against.
 */
export const Roles = createParamDecorator((_config: void, ctx: ExecutionContext) => {
  const incomingMessage: IncomingMessage = ctx.switchToHttp().getRequest<IncomingMessage>();
  const grantedInfoService: IGrantedInfoProvider = incomingMessage['grantedInfoService'];
  const options: GrantedModuleOptions = incomingMessage['grantedModuleOptions'] || {};
  const rawRoles = grantedInfoService.getRolesFromIncomingMessage(incomingMessage);
  return resolveRoles(rawRoles, options.roleHierarchy, options.knownRoles);
});
