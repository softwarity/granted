import { generateKeyPairSync, KeyObject } from 'crypto';
import * as jwt from 'jsonwebtoken';
import { GrantedPrincipalProvider } from '../src/services/granted-info.provider';
import { GrantedJwtPrincipalProvider } from '../src/services/granted-info.jwt-provider';

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

describe('GrantedPrincipalProvider (headers)', () => {
  const provider = new GrantedPrincipalProvider();

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

describe('GrantedJwtPrincipalProvider', () => {
  const secret = 'test-secret';

  function bearer(payload: object) {
    const token = jwt.sign(payload, secret, { algorithm: 'HS256' });
    return reqWithHeaders({ authorization: `Bearer ${token}` });
  }

  it('maps the default claims (sub, roles)', () => {
    const provider = new GrantedJwtPrincipalProvider({ base64Key: secret, algorithm: 'HS256' });
    const req = bearer({ sub: 'alice', roles: ['ADMIN'] });
    expect(provider.getUsernameFromRequest(req)).toBe('alice');
    expect(provider.getRolesFromRequest(req)).toEqual(['ADMIN']);
  });

  it('honours a configurable rolesClaim (e.g. groups)', () => {
    const provider = new GrantedJwtPrincipalProvider({ base64Key: secret, algorithm: 'HS256', rolesClaim: 'groups' });
    const req = bearer({ sub: 'alice', groups: ['team-a', 'team-b'] });
    expect(provider.getRolesFromRequest(req)).toEqual(['team-a', 'team-b']);
  });

  it('honours configurable usernameClaim and tenantClaim', () => {
    const provider = new GrantedJwtPrincipalProvider({
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
    const provider = new GrantedJwtPrincipalProvider({ base64Key: 'other-secret', algorithm: 'HS256' });
    const req = bearer({ sub: 'alice', roles: ['ADMIN'] });
    expect(provider.getUsernameFromRequest(req)).toBe('anonymous');
    expect(provider.getRolesFromRequest(req)).toEqual([]);
    expect(warn).toHaveBeenCalled();
    warn.mockRestore();
  });

  describe('presets', () => {
    it('keycloak reads roles from the nested realm_access.roles path', () => {
      const provider = GrantedJwtPrincipalProvider.keycloak({ base64Key: secret, algorithm: 'HS256' });
      const req = bearer({ preferred_username: 'alice', realm_access: { roles: ['offline_access', 'admin'] } });
      expect(provider.getUsernameFromRequest(req)).toBe('alice');
      expect(provider.getRolesFromRequest(req)).toEqual(['offline_access', 'admin']);
    });

    it('azureAd maps preferred_username + tid', () => {
      const provider = GrantedJwtPrincipalProvider.azureAd({ base64Key: secret, algorithm: 'HS256' });
      const req = bearer({ preferred_username: 'alice@acme', roles: ['Reader'], tid: 'acme' });
      expect(provider.getUsernameFromRequest(req)).toBe('alice@acme');
      expect(provider.getRolesFromRequest(req)).toEqual(['Reader']);
      expect(provider.getTenantFromRequest(req)).toBe('acme');
    });

    it('okta maps authorities from groups', () => {
      const provider = GrantedJwtPrincipalProvider.okta({ base64Key: secret, algorithm: 'HS256' });
      const req = bearer({ sub: 'alice', groups: ['Everyone', 'Admins'] });
      expect(provider.getRolesFromRequest(req)).toEqual(['Everyone', 'Admins']);
    });

    it('lets a preset field be overridden', () => {
      const provider = GrantedJwtPrincipalProvider.okta({ base64Key: secret, algorithm: 'HS256', usernameClaim: 'email' });
      const req = bearer({ email: 'alice@acme', groups: ['Admins'] });
      expect(provider.getUsernameFromRequest(req)).toBe('alice@acme');
    });
  });

  it('defaults to ES256 with a PEM key', () => {
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
    const pem = (key: KeyObject) => key.export({ type: 'spki', format: 'pem' }) as string;
    const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const withToken = (token: string) => reqWithHeaders({ authorization: `Bearer ${token}` });
    const es256 = jwt.sign({ sub: 'alice' }, ec.privateKey, { algorithm: 'ES256' });
    const rs256 = jwt.sign({ sub: 'alice' }, rsa.privateKey, { algorithm: 'RS256' });
    expect(new GrantedJwtPrincipalProvider({ base64Key: pem(ec.publicKey) }).getUsernameFromRequest(withToken(es256))).toBe('alice');
    // An RSA key no longer works by default: RS256 has to be asked for.
    expect(new GrantedJwtPrincipalProvider({ base64Key: pem(rsa.publicKey) }).getUsernameFromRequest(withToken(rs256))).toBe('anonymous');
    expect(new GrantedJwtPrincipalProvider({ base64Key: pem(rsa.publicKey), algorithm: 'RS256' }).getUsernameFromRequest(withToken(rs256))).toBe('alice');
    warn.mockRestore();
  });

  it('accepts a list of algorithms', () => {
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
    const req = bearer({ sub: 'alice' });
    expect(new GrantedJwtPrincipalProvider({ base64Key: secret, algorithm: ['HS384', 'HS256'] }).getUsernameFromRequest(req)).toBe('alice');
    expect(new GrantedJwtPrincipalProvider({ base64Key: secret, algorithm: ['HS384', 'HS512'] }).getUsernameFromRequest(bearer({ sub: 'alice' }))).toBe('anonymous');
    warn.mockRestore();
  });

  describe('issuer & audience', () => {
    const claims = { sub: 'alice', iss: 'https://gateway.acme', aud: 'orders-api' };

    it('are not checked when unset', () => {
      const provider = new GrantedJwtPrincipalProvider({ base64Key: secret, algorithm: 'HS256' });
      expect(provider.getUsernameFromRequest(bearer({ ...claims, iss: 'https://elsewhere', aud: 'billing-api' }))).toBe('alice');
    });

    it('accept a token matching one of the issuers and audiences', () => {
      const provider = new GrantedJwtPrincipalProvider({ base64Key: secret, algorithm: 'HS256', issuer: ['https://idp.acme', 'https://gateway.acme'], audience: /^orders-/ });
      expect(provider.getUsernameFromRequest(bearer(claims))).toBe('alice');
    });

    it('yield anonymous on an unexpected issuer or audience', () => {
      const warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
      const provider = new GrantedJwtPrincipalProvider({ base64Key: secret, algorithm: 'HS256', issuer: 'https://gateway.acme', audience: ['orders-api'] });
      expect(provider.getUsernameFromRequest(bearer({ ...claims, iss: 'https://evil.example' }))).toBe('anonymous');
      expect(provider.getUsernameFromRequest(bearer({ ...claims, aud: 'billing-api' }))).toBe('anonymous');
      expect(warn.mock.calls.flat().join(' ')).toMatch(/issuer invalid[\s\S]*audience invalid/);
      warn.mockRestore();
    });

    it('need a key — an unverified token could claim anything', () => {
      expect(() => new GrantedJwtPrincipalProvider({ issuer: 'https://gateway.acme' })).toThrow('need a key');
    });
  });

  it('never logs the token or the key on failure', () => {
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
    const provider = new GrantedJwtPrincipalProvider({ base64Key: 'other-secret', algorithm: 'HS256' });
    const token = jwt.sign({ sub: 'alice' }, secret, { algorithm: 'HS256' });
    provider.getUsernameFromRequest(reqWithHeaders({ authorization: `Bearer ${token}` }));
    const logged = warn.mock.calls.flat().join(' ');
    expect(logged).not.toContain(token);
    expect(logged).not.toContain('other-secret');
    warn.mockRestore();
  });
});
