import { DynamicModule, Module } from '@nestjs/common';
import { GrantedModuleOptions } from './models/granted-module-options';
import { GrantedInfoProvider } from './services/granted-info.provider';
import { APP_GUARD, APP_INTERCEPTOR } from '@nestjs/core';
import { GlobalInterceptor } from './services/global.interceptor';
import { AppGuard } from './security/app.guard';

@Module({})
export class GrantedModule {
  static forRoot(options?: GrantedModuleOptions): DynamicModule {
    const opts: GrantedModuleOptions = {apply: true, infoProvider: GrantedInfoProvider, ...(options || {})};
    return {
      module: GrantedModule,
      providers: [
        { provide: 'GRANTED_MODULE_OPTIONS', useValue: opts }, 
        { provide: GrantedInfoProvider, useClass: opts.infoProvider }, 
        { provide: APP_INTERCEPTOR, useClass: GlobalInterceptor },
        { provide: APP_GUARD, useClass: AppGuard }
      ],
      exports: ['GRANTED_MODULE_OPTIONS']
    };
  }
}
