import { Injectable, NestInterceptor, ExecutionContext, CallHandler, Inject } from '@nestjs/common';
import { IncomingMessage } from 'http';
import { Observable } from 'rxjs';
import { GrantedModuleOptions } from 'src/models/granted-module-options';

@Injectable()
export class GlobalInterceptor implements NestInterceptor {
    constructor(
        @Inject('GRANTED_MODULE_OPTIONS') private readonly options: GrantedModuleOptions,
    ) { }

    intercept(ctx: ExecutionContext, next: CallHandler): Observable<any> {
        const incomingMessage: IncomingMessage = ctx.switchToHttp().getRequest<IncomingMessage>();
        incomingMessage['grantedInfoService'] = this.options.infoProvider;
        return next.handle();
    }
}