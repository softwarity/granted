import { Request } from 'express';
import { IncomingMessage } from "http";

export interface IGrantedInfoProvider {
    getUsernameFromRequest(request: Request): string;
    getRolesFromRequest(request: Request): string[];
    getGroupsFromRequest(request: Request): string[];
    getLocaleFromRequest(request: Request): string;

    getUsernameFromIncomingMessage(incomingMessage: IncomingMessage): string;
    getRolesFromIncomingMessage(incomingMessage: IncomingMessage): string[];
    getGroupsFromIncomingMessage(incomingMessage: IncomingMessage): string[];
    getLocaleFromIncomingMessage(incomingMessage: IncomingMessage): string;
}
