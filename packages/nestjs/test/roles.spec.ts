import { GrantedPrincipalProvider } from '../src/services/granted-info.provider';
import { expandRoles, resolveRoles } from '../src/security/roles.util';

function reqWithHeaders(headers: Record<string, string>) {
  return { header: (name: string) => headers[name.toLowerCase()], headers } as any;
}

describe('GrantedPrincipalProvider — roles format', () => {
  it('parses a JSON array by default', () => {
    const provider = new GrantedPrincipalProvider();
    expect(provider.getRolesFromRequest(reqWithHeaders({ roles: '["ADMIN","USER"]' }))).toEqual(['ADMIN', 'USER']);
  });

  it('parses a CSV string when rolesFormat is csv', () => {
    const provider = new GrantedPrincipalProvider({ rolesFormat: 'csv' });
    expect(provider.getRolesFromRequest(reqWithHeaders({ roles: 'ADMIN, USER , ACCOUNTANT' }))).toEqual(['ADMIN', 'USER', 'ACCOUNTANT']);
  });

  it('csv: trims blanks and ignores empty segments', () => {
    const provider = new GrantedPrincipalProvider({ rolesFormat: 'csv' });
    expect(provider.getRolesFromRequest(reqWithHeaders({ roles: ' ADMIN ,,  , USER ' }))).toEqual(['ADMIN', 'USER']);
  });

  it('returns [] when the header is absent (both formats)', () => {
    expect(new GrantedPrincipalProvider().getRolesFromRequest(reqWithHeaders({}))).toEqual([]);
    expect(new GrantedPrincipalProvider({ rolesFormat: 'csv' }).getRolesFromRequest(reqWithHeaders({}))).toEqual([]);
  });

  it('csv format also applies to IncomingMessage', () => {
    const provider = new GrantedPrincipalProvider({ rolesFormat: 'csv' });
    expect(provider.getRolesFromIncomingMessage({ headers: { roles: 'A,B' } } as any)).toEqual(['A', 'B']);
  });
});

describe('GrantedPrincipalProvider — custom header names', () => {
  const provider = new GrantedPrincipalProvider({
    usernameHeader: 'x-user',
    rolesHeader: 'x-roles',
    tenantHeader: 'x-tenant',
  });

  it('reads from the configured headers (Request)', () => {
    const req = reqWithHeaders({ 'x-user': 'alice', 'x-roles': '["ADMIN"]', 'x-tenant': 'acme' });
    expect(provider.getUsernameFromRequest(req)).toBe('alice');
    expect(provider.getRolesFromRequest(req)).toEqual(['ADMIN']);
    expect(provider.getTenantFromRequest(req)).toBe('acme');
  });

  it('reads from the configured headers (IncomingMessage, lowercased keys)', () => {
    const msg = { headers: { 'x-user': 'bob', 'x-roles': '["USER"]', 'x-tenant': 'globex' } } as any;
    expect(provider.getUsernameFromIncomingMessage(msg)).toBe('bob');
    expect(provider.getRolesFromIncomingMessage(msg)).toEqual(['USER']);
    expect(provider.getTenantFromIncomingMessage(msg)).toBe('globex');
  });

  it('ignores the default header names when custom ones are set', () => {
    const req = reqWithHeaders({ username: 'alice', roles: '["ADMIN"]' });
    expect(provider.getUsernameFromRequest(req)).toBe('anonymous');
    expect(provider.getRolesFromRequest(req)).toEqual([]);
  });

  it('combines custom header names with csv format', () => {
    const csv = new GrantedPrincipalProvider({ rolesHeader: 'x-roles', rolesFormat: 'csv' });
    expect(csv.getRolesFromRequest(reqWithHeaders({ 'x-roles': 'A, B' }))).toEqual(['A', 'B']);
  });
});

describe('expandRoles — hierarchy', () => {
  const hierarchy = { ADMIN: ['MANAGER'], MANAGER: ['USER'] };

  it('returns the roles unchanged when no hierarchy is given', () => {
    expect(expandRoles(['USER']).sort()).toEqual(['USER']);
  });

  it('expands transitively', () => {
    expect(expandRoles(['ADMIN'], hierarchy).sort()).toEqual(['ADMIN', 'MANAGER', 'USER']);
  });

  it('expands a mid-level role partially', () => {
    expect(expandRoles(['MANAGER'], hierarchy).sort()).toEqual(['MANAGER', 'USER']);
  });

  it('is cycle-safe', () => {
    const cyclic = { A: ['B'], B: ['A'] };
    expect(expandRoles(['A'], cyclic).sort()).toEqual(['A', 'B']);
  });

  it('dedupes', () => {
    expect(expandRoles(['ADMIN', 'USER'], hierarchy).sort()).toEqual(['ADMIN', 'MANAGER', 'USER']);
  });
});

describe('resolveRoles — hierarchy + knownRoles', () => {
  const hierarchy = { ADMIN: ['MANAGER'], MANAGER: ['USER'] };

  it('filters out roles unknown to the module', () => {
    expect(resolveRoles(['ADMIN', 'OTHER_MODULE_ROLE'], undefined, ['ADMIN', 'USER']).sort()).toEqual(['ADMIN']);
  });

  it('expands then filters (implied roles survive if known)', () => {
    expect(resolveRoles(['ADMIN', 'FOREIGN'], hierarchy, ['ADMIN', 'MANAGER', 'USER']).sort()).toEqual(['ADMIN', 'MANAGER', 'USER']);
  });

  it('keeps everything when knownRoles is undefined', () => {
    expect(resolveRoles(['ADMIN', 'FOREIGN'], hierarchy).sort()).toEqual(['ADMIN', 'FOREIGN', 'MANAGER', 'USER']);
  });
});
