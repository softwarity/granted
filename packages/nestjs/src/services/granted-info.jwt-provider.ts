import { Request } from 'express';
import { IncomingMessage } from "http";
import { IGrantedInfoProvider } from "./igranted-info.provider";
import { verify, decode, Algorithm } from 'jsonwebtoken';

export class GrantedInfoJwtProvider implements IGrantedInfoProvider {

    decoded?: any;

    constructor(private base64Key?: string, private algorithm?: Algorithm) { // 'RS256'
    }

    getUsernameFromRequest(request: Request): string {
        this.initFromRequest(request);
        return this.decoded.sub || 'anonymous';
    }

    getRolesFromRequest(request: Request): string[] {
        this.initFromRequest(request);
        return this.decoded.roles || [];
    }

    getGroupsFromRequest(request: Request): string[] {
        this.initFromRequest(request);
        return this.decoded.groups || [];
    }

    getLocaleFromRequest(request: Request): string {
        return request.header('accept-language') || 'en';
    }

    getUsernameFromIncomingMessage(incomingMessage: IncomingMessage): string {
        this.initFromIncomingMessage(incomingMessage);
        return this.decoded.sub || 'anonymous';
    }
    getRolesFromIncomingMessage(incomingMessage: IncomingMessage): string[] {
        this.initFromIncomingMessage(incomingMessage);
        return this.decoded.roles || [];
    }

    getGroupsFromIncomingMessage(incomingMessage: IncomingMessage): string[] {
        this.initFromIncomingMessage(incomingMessage);
        return this.decoded.groups || [];
    }

    getLocaleFromIncomingMessage(incomingMessage: IncomingMessage): string {
        return incomingMessage.headers['accept-language'] || 'en';
    }

    private initFromRequest(request: Request): void {
        if (!this.decoded) {
            const authHeader = this.getAuthHeaderFromRequest(request);
            const token = this.getJwtFromAuthHeader(authHeader);
            this.decoded = this.decodeJwt(token) || {};
        }
    }

    private initFromIncomingMessage(incomingMessage: IncomingMessage): void {
        if (!this.decoded) {
            const authHeader = this.getAuthHeaderIncomingMessage(incomingMessage);
            const token = this.getJwtFromAuthHeader(authHeader);
            this.decoded = this.decodeJwt(token) || {};
        }
    }

    private getAuthHeaderIncomingMessage(incomingMessage: IncomingMessage): string {
        return incomingMessage.headers['authorization'] as string;
    }

    private getAuthHeaderFromRequest(request: Request): string {
        return request.header('authorization');
    }
    private getJwtFromAuthHeader(authHeader: string): string {
        return !!authHeader ? authHeader.split(' ')[1] : null; // Le JWT est généralement après le préfixe 'Bearer'
    }

    private decodeJwt(token: string): any {
        if (!this.base64Key || !this.algorithm) {
            return decode(token);
        }
        try {
            return verify(token, this.base64Key, { algorithms: [this.algorithm] });
        } catch (err) {
            console.error(err);
            return {};
        }
    }
}
