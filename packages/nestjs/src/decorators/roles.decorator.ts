import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { IncomingMessage } from 'http';

export const Roles = createParamDecorator(
  (config: void, ctx: ExecutionContext) => {
    const incomingMessage: IncomingMessage = ctx.switchToHttp().getRequest<IncomingMessage>();
    return JSON.parse(incomingMessage.headers['roles'] as string || '[]');
  },
);