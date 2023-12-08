import { Request } from "express";
export interface BooleanSpec {
    id: string,
    apply(request: Request, username: string, roles: string[]): boolean;
}
// AndSpec
export function and(...booleanSpecs: BooleanSpec[]): BooleanSpec {
    return {id: `and(${booleanSpecs.map(booleanSpec => booleanSpec.id).join(',')})`, apply: (request: Request, username: string, roles: string[]): boolean => {
        return booleanSpecs.every((booleanSpec: BooleanSpec) => booleanSpec.apply(request, username, roles));
    }};
}
// IsTrueSpec
export function isTrue(): BooleanSpec {
    return {id: `isTrue()`, apply: (request: Request, username: string, roles: string[]): boolean => true};
}
// HasRoleSpec
export function hasRole(role: string): BooleanSpec {
    return {id: `hasRole(${role})`, apply: (request: Request, username: string, roles: string[]): boolean => roles.includes(role)};
}
// IsAuthenticatedSpec
export function isAuthenticated(): BooleanSpec {
    return {id: `isAuthenticated()`, apply: (request: Request, username: string, roles: string[]): boolean => !!username && username !== 'anonymous'};
}
// IsFalseSpec
export function isFalse(): BooleanSpec {
    return {id: `isFalse()`, apply: (request: Request, username: string, roles: string[]): boolean => false};
}
// NotSpec
export function not(booleanSpec: BooleanSpec): BooleanSpec {
    return {id: `not(${booleanSpec.id})`,apply: (request: Request, username: string, roles: string[]): boolean => !booleanSpec.apply(request, username, roles)};
}
// OrSpec
export function or(...booleanSpecs: BooleanSpec[]): BooleanSpec {
    return {id: `or(${booleanSpecs.map(booleanSpec => booleanSpec.id).join(',')})`, apply: (request: Request, username: string, roles: string[]): boolean => {
        return booleanSpecs.some((booleanSpec: BooleanSpec) => booleanSpec.apply(request, username, roles));
    }};
}
// IsUserSpec
export function isUser(type: 'Param' | 'Query' | 'Body', field: string): BooleanSpec {
    return {id: `isUser(${type}, ${field})`, apply: (request: Request, username: string, roles: string[]): boolean => {
        let user: string = '';
        if (type === 'Param') {
            user = request.params[field];
        } else if (type === 'Query') {
            user = request.query[field] as string;
        } else if (type === 'Body') {
            const fields: string[] = field.split('.');
            try {
                user = fields.reduce((curr: any, f: string) => curr[f], request.body)
            } catch(e) {
                return false;
            }
        }
        return username === user;
    }};
}