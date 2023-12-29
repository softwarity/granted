import { CanActivate, ExecutionContext, Inject, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Request } from 'express';
import { GrantedModuleOptions } from 'src/models/granted-module-options';
import { BooleanSpec } from './boolean-spec';
import { GrantedInfoProvider } from 'src/services/granted-info.provider';

@Injectable()
export class AppGuard implements CanActivate {
  private grantedInfoService: GrantedInfoProvider
  constructor(
    @Inject('GRANTED_MODULE_OPTIONS') private readonly options: GrantedModuleOptions,
    private reflector: Reflector
  ) {
    this.grantedInfoService = options.infoProvider;
  }

  canActivate(context: ExecutionContext): boolean {
    const booleanSpecs: BooleanSpec[] = this.reflector.get<BooleanSpec[]>('booleanSpecs', context.getHandler());
    if (!booleanSpecs || !this.options.apply) {
      return true;
    }
    const request: Request = context.switchToHttp().getRequest();
    const roles: string[] = this.grantedInfoService.getRolesFromRequest(request);
    const username = this.grantedInfoService.getUsernameFromRequest(request);
    return booleanSpecs.every((booleanSpec: BooleanSpec) => booleanSpec.apply(request, username, roles));
  }
}
