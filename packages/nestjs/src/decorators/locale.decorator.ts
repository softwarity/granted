import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { IncomingMessage } from 'http';
import { IGrantedInfoProvider } from 'src/services';

export const Locale = createParamDecorator(
  (data: string, ctx: ExecutionContext) => {
    const incomingMessage: IncomingMessage = ctx.switchToHttp().getRequest<IncomingMessage>();
    const grantedInfoService: IGrantedInfoProvider = incomingMessage['grantedInfoService'];
    return grantedInfoService.getLocaleFromIncomingMessage(incomingMessage);
  },
);