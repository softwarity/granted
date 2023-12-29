import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { IncomingMessage } from 'http';
import { IGrantedInfoProvider } from 'src/services';


export const Groups = createParamDecorator(
  (config: void, ctx: ExecutionContext) => {
    const incomingMessage: IncomingMessage = ctx.switchToHttp().getRequest<IncomingMessage>();
    const grantedInfoService: IGrantedInfoProvider = incomingMessage['grantedInfoService'];
    return grantedInfoService.getGroupsFromIncomingMessage(incomingMessage);
  },
);