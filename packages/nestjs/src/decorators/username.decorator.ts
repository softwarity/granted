import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { IncomingMessage } from 'http';
import { IGrantedPrincipalProvider } from '../services';

export const Username = createParamDecorator((config: void, ctx: ExecutionContext) => {
  const incomingMessage: IncomingMessage = ctx.switchToHttp().getRequest<IncomingMessage>();
  const grantedPrincipalProvider: IGrantedPrincipalProvider = incomingMessage['grantedPrincipalProvider'];
  return grantedPrincipalProvider.getUsernameFromIncomingMessage(incomingMessage);
});
