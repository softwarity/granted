import { DynamicModule, Inject, Module } from '@nestjs/common';
import { GrantedModuleOptions } from './models/granted-module-options';
import { GrantedPrincipalProvider } from './services/granted-info.provider';
import { APP_GUARD, APP_INTERCEPTOR } from '@nestjs/core';
import { GlobalInterceptor } from './services/global.interceptor';
import { AppGuard } from './security/app.guard';
import { writeOpenApi } from './security/openapi';

@Module({})
export class GrantedModule {
  // Instantiated by NestFactory.create(): every decorator applied, before SwaggerModule.createDocument().
  constructor(@Inject('GRANTED_MODULE_OPTIONS') options: GrantedModuleOptions) {
    writeOpenApi(options.openApiSecurityScheme);
  }

  static forRoot(options?: GrantedModuleOptions): DynamicModule {
    const opts: GrantedModuleOptions = { apply: true, principalProvider: new GrantedPrincipalProvider(), openApiSecurityScheme: 'bearer', ...(options || {}) };
    return {
      module: GrantedModule,
      providers: [
        { provide: 'GRANTED_MODULE_OPTIONS', useValue: opts },
        { provide: APP_INTERCEPTOR, useClass: GlobalInterceptor },
        { provide: APP_GUARD, useClass: AppGuard },
      ],
      exports: ['GRANTED_MODULE_OPTIONS'],
    };
  }
}
