import { CanActivate, ExecutionContext, Inject, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Request } from 'express';
import { GrantedModuleOptions } from '../models/granted-module-options';
import { BooleanSpec } from './boolean-spec';
import { resolveRoles } from './roles.util';
import { IGrantedPrincipalProvider } from '../services/igranted-info.provider';

@Injectable()
export class AppGuard implements CanActivate {
  private grantedPrincipalProvider: IGrantedPrincipalProvider;
  constructor(
    @Inject('GRANTED_MODULE_OPTIONS') private readonly options: GrantedModuleOptions,
    private reflector: Reflector,
  ) {
    this.grantedPrincipalProvider = options.principalProvider;
  }

  canActivate(context: ExecutionContext): boolean {
    const booleanSpecs: BooleanSpec[] = this.reflector.get<BooleanSpec[]>('booleanSpecs', context.getHandler());
    if (!booleanSpecs || !this.options.apply) {
      return true;
    }
    const request: Request = context.switchToHttp().getRequest();
    const rawRoles: string[] = this.grantedPrincipalProvider.getRolesFromRequest(request);
    const roles: string[] = resolveRoles(rawRoles, this.options.roleHierarchy, this.options.knownRoles);
    const username = this.grantedPrincipalProvider.getUsernameFromRequest(request);
    const tenant = this.grantedPrincipalProvider.getTenantFromRequest(request);
    return booleanSpecs.every((booleanSpec: BooleanSpec) => booleanSpec.apply(request, username, roles, tenant));
  }
}
