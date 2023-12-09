import { Injectable, NestInterceptor, ExecutionContext, CallHandler, Inject } from '@nestjs/common';
import { IncomingMessage } from 'http';
import { Observable } from 'rxjs';
import { GrantedInfoProvider } from './granted-info.provider';

@Injectable()
export class GlobalInterceptor implements NestInterceptor {
    constructor(
        private readonly grantedInfoService: GrantedInfoProvider
    ) { }

    intercept(ctx: ExecutionContext, next: CallHandler): Observable<any> {
        const incomingMessage: IncomingMessage = ctx.switchToHttp().getRequest<IncomingMessage>();
        incomingMessage['grantedInfoService'] = this.grantedInfoService;
        return next.handle();
    }
}