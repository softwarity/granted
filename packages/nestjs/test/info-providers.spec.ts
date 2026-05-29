import * as jwt from 'jsonwebtoken';
import { GrantedInfoProvider } from '../src/services/granted-info.provider';
import { GrantedInfoJwtProvider } from '../src/services/granted-info.jwt-provider';

/** Express-style Request stub backed by a header map. */
function reqWithHeaders(headers: Record<string, string>) {
  return {
    header: (name: string) => headers[name.toLowerCase()],
    headers,
  } as any;
}

/** Raw IncomingMessage stub. */
function msgWithHeaders(headers: Record<string, string>) {
  return { headers } as any;
}

describe('GrantedInfoProvider (headers)', () => {
  const provider = new GrantedInfoProvider();

  it('reads username, roles and tenant from headers', () => {
    const req = reqWithHeaders({
      username: 'alice',
      roles: '["ADMIN","USER"]',
      tenant: 'acme',
    });
    expect(provider.getUsernameFromRequest(req)).toBe('alice');
    expect(provider.getRolesFromRequest(req)).toEqual(['ADMIN', 'USER']);
    expect(provider.getTenantFromRequest(req)).toBe('acme');
  });

  it('falls back to anonymous / [] / undefined', () => {
    const req = reqWithHeaders({});
    expect(provider.getUsernameFromRequest(req)).toBe('anonymous');
    expect(provider.getRolesFromRequest(req)).toEqual([]);
    expect(provider.getTenantFromRequest(req)).toBeUndefined();
  });

  it('works against a raw IncomingMessage', () => {
    const msg = msgWithHeaders({ username: 'bob', roles: '["USER"]', tenant: 'globex' });
    expect(provider.getUsernameFromIncomingMessage(msg)).toBe('bob');
    expect(provider.getRolesFromIncomingMessage(msg)).toEqual(['USER']);
    expect(provider.getTenantFromIncomingMessage(msg)).toBe('globex');
  });
});

describe('GrantedInfoJwtProvider', () => {
  const secret = 'test-secret';

  function bearer(payload: object) {
    const token = jwt.sign(payload, secret, { algorithm: 'HS256' });
    return reqWithHeaders({ authorization: `Bearer ${token}` });
  }

  it('maps the default claims (sub, roles)', () => {
    const provider = new GrantedInfoJwtProvider({ base64Key: secret, algorithm: 'HS256' });
    const req = bearer({ sub: 'alice', roles: ['ADMIN'] });
    expect(provider.getUsernameFromRequest(req)).toBe('alice');
    expect(provider.getRolesFromRequest(req)).toEqual(['ADMIN']);
  });

  it('honours a configurable rolesClaim (e.g. groups)', () => {
    const provider = new GrantedInfoJwtProvider({ base64Key: secret, algorithm: 'HS256', rolesClaim: 'groups' });
    const req = bearer({ sub: 'alice', groups: ['team-a', 'team-b'] });
    expect(provider.getRolesFromRequest(req)).toEqual(['team-a', 'team-b']);
  });

  it('honours configurable usernameClaim and tenantClaim', () => {
    const provider = new GrantedInfoJwtProvider({
      base64Key: secret,
      algorithm: 'HS256',
      usernameClaim: 'preferred_username',
      tenantClaim: 'tid',
    });
    const req = bearer({ preferred_username: 'alice@acme', tid: 'acme' });
    expect(provider.getUsernameFromRequest(req)).toBe('alice@acme');
    expect(provider.getTenantFromRequest(req)).toBe('acme');
  });

  it('yields anonymous on a failed verification (wrong key)', () => {
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
    const provider = new GrantedInfoJwtProvider({ base64Key: 'other-secret', algorithm: 'HS256' });
    const req = bearer({ sub: 'alice', roles: ['ADMIN'] });
    expect(provider.getUsernameFromRequest(req)).toBe('anonymous');
    expect(provider.getRolesFromRequest(req)).toEqual([]);
    expect(warn).toHaveBeenCalled();
    warn.mockRestore();
  });

  describe('presets', () => {
    it('keycloak reads roles from the nested realm_access.roles path', () => {
      const provider = GrantedInfoJwtProvider.keycloak({ base64Key: secret, algorithm: 'HS256' });
      const req = bearer({ preferred_username: 'alice', realm_access: { roles: ['offline_access', 'admin'] } });
      expect(provider.getUsernameFromRequest(req)).toBe('alice');
      expect(provider.getRolesFromRequest(req)).toEqual(['offline_access', 'admin']);
    });

    it('azureAd maps preferred_username + tid', () => {
      const provider = GrantedInfoJwtProvider.azureAd({ base64Key: secret, algorithm: 'HS256' });
      const req = bearer({ preferred_username: 'alice@acme', roles: ['Reader'], tid: 'acme' });
      expect(provider.getUsernameFromRequest(req)).toBe('alice@acme');
      expect(provider.getRolesFromRequest(req)).toEqual(['Reader']);
      expect(provider.getTenantFromRequest(req)).toBe('acme');
    });

    it('okta maps authorities from groups', () => {
      const provider = GrantedInfoJwtProvider.okta({ base64Key: secret, algorithm: 'HS256' });
      const req = bearer({ sub: 'alice', groups: ['Everyone', 'Admins'] });
      expect(provider.getRolesFromRequest(req)).toEqual(['Everyone', 'Admins']);
    });

    it('lets a preset field be overridden', () => {
      const provider = GrantedInfoJwtProvider.okta({ base64Key: secret, algorithm: 'HS256', usernameClaim: 'email' });
      const req = bearer({ email: 'alice@acme', groups: ['Admins'] });
      expect(provider.getUsernameFromRequest(req)).toBe('alice@acme');
    });
  });

  it('never logs the token or the key on failure', () => {
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
    const provider = new GrantedInfoJwtProvider({ base64Key: 'other-secret', algorithm: 'HS256' });
    const token = jwt.sign({ sub: 'alice' }, secret, { algorithm: 'HS256' });
    provider.getUsernameFromRequest(reqWithHeaders({ authorization: `Bearer ${token}` }));
    const logged = warn.mock.calls.flat().join(' ');
    expect(logged).not.toContain(token);
    expect(logged).not.toContain('other-secret');
    warn.mockRestore();
  });
});
