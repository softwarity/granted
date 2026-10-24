import * as jwt from 'jsonwebtoken';
import { resolveRoles } from '../src/security/roles.util';
import { GrantedPrincipalProvider } from '../src/services/granted-info.provider';
import { GrantedJwtPrincipalProvider } from '../src/services/granted-info.jwt-provider';

/** Express-style Request stub backed by a header map. */
function reqWithHeaders(headers: Record<string, string>) {
  return { header: (name: string) => headers[name.toLowerCase()], headers } as any;
}

describe('roles, whatever their encoding', () => {
  let warn: jest.SpyInstance;

  beforeEach(() => {
    warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
  });

  afterEach(() => jest.restoreAllMocks());

  describe('in a JWT claim', () => {
    const secret = 'test-secret';
    const provider = new GrantedJwtPrincipalProvider({ base64Key: secret, algorithm: 'HS256' });
    const rolesOf = (roles: unknown) => provider.getRolesFromRequest(reqWithHeaders({ authorization: `Bearer ${jwt.sign({ sub: 'alice', roles }, secret, { algorithm: 'HS256' })}` }));

    it('splits a comma-separated string', () => {
      expect(rolesOf('ADMIN, USER')).toEqual(['ADMIN', 'USER']);
    });

    it('never turns a string into its characters — a one-letter role must not pass', () => {
      expect(resolveRoles(rolesOf('ADMIN'), undefined, undefined)).toEqual(['ADMIN']);
      expect(resolveRoles(rolesOf('ADMIN'), undefined, ['A'])).toEqual([]);
    });

    it('keeps the strings of a list and drops anything else', () => {
      expect(rolesOf(['ADMIN', 42, { role: 'USER' }, 'USER'])).toEqual(['ADMIN', 'USER']);
    });

    it('gives no role for a claim that is neither a list nor a string', () => {
      expect(rolesOf({ ADMIN: true })).toEqual([]);
      expect(rolesOf(42)).toEqual([]);
    });
  });

  describe('in a gateway header', () => {
    const rolesOf = (value: string, rolesFormat?: 'json' | 'csv') => new GrantedPrincipalProvider({ rolesFormat }).getRolesFromRequest(reqWithHeaders({ roles: value }));

    it('reads a JSON array or a comma-separated list, detected', () => {
      expect(rolesOf('["ADMIN","USER"]')).toEqual(['ADMIN', 'USER']);
      expect(rolesOf('ADMIN, USER')).toEqual(['ADMIN', 'USER']);
      expect(rolesOf('ADMIN')).toEqual(['ADMIN']);
    });

    it('gives no role for malformed JSON, with a warning that never shows the value — instead of failing the request', () => {
      expect(rolesOf('["ADMIN",')).toEqual([]);
      expect(rolesOf('["ADMIN",', 'json')).toEqual([]);
      const logged = warn.mock.calls.flat().join(' ');
      expect(logged).toContain('roles');
      expect(logged).not.toContain('ADMIN');
    });

    it('keeps rolesFormat as a way to force one encoding', () => {
      expect(rolesOf('["ADMIN"]', 'csv')).toEqual(['["ADMIN"]']);
      expect(rolesOf('ADMIN, USER', 'json')).toEqual([]);
    });
  });
});
