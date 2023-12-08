import { DynamicModule, Module } from '@nestjs/common';
import { GrantedModuleOptions } from './models/granted-module-options';

@Module({})
export class GrantedModule {
  static forRoot(options?: GrantedModuleOptions): DynamicModule {
    const opts: GrantedModuleOptions = {apply: true, ...(options || {})};
    return {
      module: GrantedModule,
      providers: [
        { provide: 'GRANTED_MODULE_OPTIONS', useValue: opts }
      ],
      exports: ['GRANTED_MODULE_OPTIONS']
    };
  }
}
