import { Request } from 'express';
import { IncomingMessage } from "http";
import { IGrantedInfoProvider } from "./igranted-info.provider";

export class GrantedInfoProvider implements IGrantedInfoProvider {

    getUsernameFromRequest(request: Request): string {
        return request.header('username') || 'anonymous';
    }

    getRolesFromRequest(request: Request): string[] {
        return JSON.parse(request.header('roles') || '[]');
    }

    getGroupsFromRequest(request: Request): string[] {
        return JSON.parse(request.header('groups') || '[]');
    }

    getLocaleFromRequest(request: Request): string {
        return request.header('accept-language') || 'en';
    }

    getUsernameFromIncomingMessage(incomingMessage: IncomingMessage): string {
        return (incomingMessage.headers['username'] || 'anonymous') as string;
    }

    getRolesFromIncomingMessage(incomingMessage: IncomingMessage): string[] {
        return JSON.parse(incomingMessage.headers['roles'] as string || '[]')
    }

    getGroupsFromIncomingMessage(incomingMessage: IncomingMessage): string[] {
        return JSON.parse(incomingMessage.headers['groups'] as string || '[]')
    }

    getLocaleFromIncomingMessage(incomingMessage: IncomingMessage): string {
        return incomingMessage.headers['accept-language'] || 'en';
    }
}
