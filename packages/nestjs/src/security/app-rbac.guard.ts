import { CanActivate, ExecutionContext, Inject, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Request } from 'express';
import { GrantedModuleOptions } from 'src/models/granted-module-options';
import { BooleanSpec } from './boolean-spec';

@Injectable()
export class AppRbacGuard implements CanActivate {
  constructor(
    @Inject('GRANTED_MODULE_OPTIONS') private readonly options: GrantedModuleOptions,
    private reflector: Reflector
  ) {}

  canActivate(context: ExecutionContext): boolean {
    const booleanSpecs: BooleanSpec[] = this.reflector.get<BooleanSpec[]>('booleanSpecs', context.getHandler());
    if (!booleanSpecs || !this.options.apply) {
      return true;
    }
    const request: Request = context.switchToHttp().getRequest();
    const roles: string[] = JSON.parse(request.header('roles') || '[]');
    const username = request.header('username') ;
    return booleanSpecs.every((booleanSpec: BooleanSpec) => booleanSpec.apply(request, username, roles));
  }
}
