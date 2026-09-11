import { Request } from 'express';
import { IncomingMessage } from 'http';

export interface IGrantedPrincipalProvider {
  /**
   * Optional async step, awaited by the guard once per request before any
   * getter is called — the place for I/O (fetching a JWKS, a session lookup…).
   * Store what the getters need on the request: they stay synchronous.
   */
  prepare?(request: IncomingMessage): Promise<void>;

  getUsernameFromRequest(request: Request): string;
  getRolesFromRequest(request: Request): string[];
  getTenantFromRequest(request: Request): string | undefined;

  getUsernameFromIncomingMessage(incomingMessage: IncomingMessage): string;
  getRolesFromIncomingMessage(incomingMessage: IncomingMessage): string[];
  getTenantFromIncomingMessage(incomingMessage: IncomingMessage): string | undefined;
}
