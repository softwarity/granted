import { Request } from 'express';
import { IncomingMessage } from 'http';

export interface IGrantedPrincipalProvider {
  getUsernameFromRequest(request: Request): string;
  getRolesFromRequest(request: Request): string[];
  getTenantFromRequest(request: Request): string | undefined;

  getUsernameFromIncomingMessage(incomingMessage: IncomingMessage): string;
  getRolesFromIncomingMessage(incomingMessage: IncomingMessage): string[];
  getTenantFromIncomingMessage(incomingMessage: IncomingMessage): string | undefined;
}
