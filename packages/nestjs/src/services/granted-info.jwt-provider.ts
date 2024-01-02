import { Request } from 'express';
import * as fs from 'fs';
import { IncomingMessage } from "http";
import { Algorithm, decode, verify } from 'jsonwebtoken';
import { IGrantedInfoProvider } from "./igranted-info.provider";

export class GrantedInfoJwtProvider implements IGrantedInfoProvider {

    base64Key: string;
    algorithm: Algorithm;

    constructor(conf: {pemFile?: string, base64Key?: string, algorithm?: Algorithm}) { // 'RS256'
        this.base64Key = conf.base64Key;
        this.algorithm = conf.algorithm || 'RS256';
        if (conf.pemFile) {
            this.base64Key = fs.readFileSync(conf.pemFile, 'utf8');
        }
    }

    getUsernameFromRequest(request: Request): string {
        const jwt = this.initFromRequest(request);
        return jwt['sub'] || 'anonymous';
    }

    getRolesFromRequest(request: Request): string[] {
        const jwt =this.initFromRequest(request);
        return jwt['roles'] || [];
    }

    getGroupsFromRequest(request: Request): string[] {
        const jwt =this.initFromRequest(request);
        return jwt['groups'] || [];
    }

    getLocaleFromRequest(request: Request): string {
        return request.header('accept-language') || 'en';
    }

    getUsernameFromIncomingMessage(incomingMessage: IncomingMessage): string {
        const jwt =this.initFromIncomingMessage(incomingMessage);
        return jwt['sub'] || 'anonymous';
    }
    getRolesFromIncomingMessage(incomingMessage: IncomingMessage): string[] {
        const jwt =this.initFromIncomingMessage(incomingMessage);
        return jwt['roles'] || [];
    }

    getGroupsFromIncomingMessage(incomingMessage: IncomingMessage): string[] {
        const jwt =this.initFromIncomingMessage(incomingMessage);
        return jwt['groups'] || [];
    }

    getLocaleFromIncomingMessage(incomingMessage: IncomingMessage): string {
        return incomingMessage.headers['accept-language'] || 'en';
    }

    private initFromRequest(request: Request): void {
        if (!request['jwt']) {
            const authHeader = this.getAuthHeaderFromRequest(request);
            const token = this.getJwtFromAuthHeader(authHeader);
            request['jwt'] = this.decodeJwt(token) || {};
        }
        return request['jwt'];
    }

    private initFromIncomingMessage(incomingMessage: IncomingMessage): void {
        if (!incomingMessage['jwt']) {
            const authHeader = this.getAuthHeaderIncomingMessage(incomingMessage);
            const token = this.getJwtFromAuthHeader(authHeader);
            incomingMessage['jwt'] = this.decodeJwt(token) || {};
        }
        return incomingMessage['jwt'];
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
            console.log(`Error while decoding JWT.`);
            console.log(`Token: ${token}`);
            console.log(`Algorithm: ${this.algorithm}`);
            console.log(`Public Key: ${this.base64Key}`);
            
            console.error(err);
            return {};
        }
    }
}
