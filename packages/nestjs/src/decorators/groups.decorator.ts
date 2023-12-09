import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { IncomingMessage } from 'http';
import { GrantedInfoProvider } from 'src/services/granted-info.provider';

export const Groups = createParamDecorator(
  (config: void, ctx: ExecutionContext) => {
    const incomingMessage: IncomingMessage = ctx.switchToHttp().getRequest<IncomingMessage>();
    const grantedInfoService: GrantedInfoProvider = incomingMessage['grantedInfoService'];
    return grantedInfoService.getGroupsFromIncomingMessage(incomingMessage);
  },
);