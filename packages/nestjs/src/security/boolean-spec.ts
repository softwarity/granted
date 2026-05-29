import { Request } from 'express';
export interface BooleanSpec {
  id: string;
  apply(request: Request, username: string, roles: string[], tenant?: string): boolean;
}
// AndSpec
export function and(...booleanSpecs: BooleanSpec[]): BooleanSpec {
  return {
    id: `and(${booleanSpecs.map((booleanSpec) => booleanSpec.id).join(',')})`,
    apply: (request: Request, username: string, roles: string[], tenant?: string): boolean => {
      return booleanSpecs.every((booleanSpec: BooleanSpec) => booleanSpec.apply(request, username, roles, tenant));
    },
  };
}
// IsTrueSpec
export function isTrue(): BooleanSpec {
  return { id: `isTrue()`, apply: (request: Request, username: string, roles: string[]): boolean => true };
}
// HasRoleSpec
export function hasRole(role: string): BooleanSpec {
  return { id: `hasRole(${role})`, apply: (request: Request, username: string, roles: string[]): boolean => roles.includes(role) };
}
// IsAuthenticatedSpec
export function isAuthenticated(): BooleanSpec {
  return { id: `isAuthenticated()`, apply: (request: Request, username: string, roles: string[]): boolean => !!username && username !== 'anonymous' };
}
// IsFalseSpec
export function isFalse(): BooleanSpec {
  return { id: `isFalse()`, apply: (request: Request, username: string, roles: string[]): boolean => false };
}
// NotSpec
export function not(booleanSpec: BooleanSpec): BooleanSpec {
  return { id: `not(${booleanSpec.id})`, apply: (request: Request, username: string, roles: string[], tenant?: string): boolean => !booleanSpec.apply(request, username, roles, tenant) };
}
// OrSpec
export function or(...booleanSpecs: BooleanSpec[]): BooleanSpec {
  return {
    id: `or(${booleanSpecs.map((booleanSpec) => booleanSpec.id).join(',')})`,
    apply: (request: Request, username: string, roles: string[], tenant?: string): boolean => {
      return booleanSpecs.some((booleanSpec: BooleanSpec) => booleanSpec.apply(request, username, roles, tenant));
    },
  };
}

/**
 * Reads a value from the request: a route param, a query param, or a (dotted)
 * body path. Returns `undefined` when the path is absent or unreadable.
 */
function requestValue(request: Request, type: 'Param' | 'Query' | 'Body', field: string): string | undefined {
  if (type === 'Param') {
    return request.params[field] as string;
  }
  if (type === 'Query') {
    return request.query[field] as string;
  }
  // type === 'Body' — support dotted paths (e.g. 'customer.id')
  try {
    return field.split('.').reduce((curr: any, f: string) => curr[f], request.body);
  } catch {
    return undefined;
  }
}

// IsUserSpec
export function isUser(type: 'Param' | 'Query' | 'Body', field: string): BooleanSpec {
  return {
    id: `isUser(${type}, ${field})`,
    apply: (request: Request, username: string): boolean => username === requestValue(request, type, field),
  };
}

// IsTenantSpec — the request value must match the caller's tenant.
// Prevents cross-tenant access (e.g. a user of tenant A hitting /tenants/B/...).
export function isTenant(type: 'Param' | 'Query' | 'Body', field: string): BooleanSpec {
  return {
    id: `isTenant(${type}, ${field})`,
    apply: (request: Request, username: string, roles: string[], tenant?: string): boolean => {
      const value = requestValue(request, type, field);
      // No tenant on the caller, or no value to compare against → deny.
      return !!tenant && tenant === value;
    },
  };
}
