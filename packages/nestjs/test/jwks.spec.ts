import { generateKeyPairSync, KeyObject } from 'crypto';
import { createServer } from 'http';
import { AddressInfo } from 'net';
import * as jwt from 'jsonwebtoken';
import { GrantedJwtPrincipalProvider, GrantedJwtPrincipalProviderConfig } from '../src/services/granted-info.jwt-provider';

interface SigningKey {
  kid: string;
  privateKey: KeyObject;
  jwk: Record<string, unknown>;
}

function rsaKey(kid: string): SigningKey {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return { kid, privateKey, jwk: { ...publicKey.export({ format: 'jwk' }), kid, use: 'sig', alg: 'RS256' } };
}

function reqWithToken(token: string) {
  const headers = { authorization: `Bearer ${token}` };
  return { header: (name: string) => headers[name.toLowerCase()], headers } as any;
}

describe('GrantedJwtPrincipalProvider — JWKS', () => {
  const keyA = rsaKey('key-a');
  const keyB = rsaKey('key-b');
  const outsider = rsaKey('outsider');

  // Local IdP stub: serves a mutable JWK Set and counts the fetches.
  let published: Record<string, unknown>[];
  let status: number;
  let fetches: number;
  const server = createServer((req, res) => {
    if (req.url === '/hang') {
      return; // never answers — exercises jwksTimeout
    }
    fetches++;
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ keys: published }));
  });
  let baseUrl: string;

  // Clock offset, to cross the cooldown and cache max age without waiting.
  const realNow = Date.now.bind(Date);
  let elapsed: number;
  const advance = (ms: number) => (elapsed += ms);
  let warn: jest.SpyInstance;

  beforeAll((done) => {
    server.listen(0, '127.0.0.1', () => {
      baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
      done();
    });
  });

  afterAll((done) => {
    server.closeAllConnections();
    server.close(done);
  });

  beforeEach(() => {
    published = [keyA.jwk];
    status = 200;
    fetches = 0;
    elapsed = 0;
    jest.spyOn(Date, 'now').mockImplementation(() => realNow() + elapsed);
    warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
  });

  afterEach(() => jest.restoreAllMocks());

  function provider(conf: GrantedJwtPrincipalProviderConfig = {}) {
    return new GrantedJwtPrincipalProvider({ jwksUri: `${baseUrl}/jwks.json`, ...conf });
  }

  function sign(key: SigningKey, payload: object = { sub: 'alice', roles: ['ADMIN'] }, options: jwt.SignOptions = { keyid: key.kid }) {
    return jwt.sign(payload, key.privateKey, { algorithm: 'RS256', ...options });
  }

  /** Goes through prepare() first, as the guard does. */
  async function usernameOf(p: GrantedJwtPrincipalProvider, token: string): Promise<string> {
    const req = reqWithToken(token);
    await p.prepare(req);
    return p.getUsernameFromRequest(req);
  }

  it('verifies a token signed by a key of the set, fetching the set only once', async () => {
    const p = provider();
    const req = reqWithToken(sign(keyA));
    await p.prepare(req);
    expect(p.getUsernameFromRequest(req)).toBe('alice');
    expect(p.getRolesFromIncomingMessage(req)).toEqual(['ADMIN']);
    expect(await usernameOf(p, sign(keyA))).toBe('alice');
    expect(fetches).toBe(1);
  });

  it('re-fetches the set when a token is signed by a key rotated in since the last fetch', async () => {
    const p = provider();
    expect(await usernameOf(p, sign(keyA))).toBe('alice');
    published = [keyA.jwk, keyB.jwk];
    advance(31_000);
    expect(await usernameOf(p, sign(keyB))).toBe('alice');
    expect(fetches).toBe(2);
  });

  it('re-fetches at most once per cooldown, however many unknown kids come in', async () => {
    const p = provider();
    expect(await usernameOf(p, sign(keyA))).toBe('alice');
    advance(31_000);
    for (const kid of ['forged-1', 'forged-2', 'forged-3']) {
      expect(await usernameOf(p, sign(outsider, { sub: 'mallory' }, { keyid: kid }))).toBe('anonymous');
    }
    expect(fetches).toBe(2);
  });

  it('shares a single fetch between concurrent requests', async () => {
    const p = provider();
    const names = await Promise.all([1, 2, 3].map(() => usernameOf(p, sign(keyA))));
    expect(names).toEqual(['alice', 'alice', 'alice']);
    expect(fetches).toBe(1);
  });

  it('re-fetches the set once jwksCacheMaxAge has elapsed, dropping withdrawn keys', async () => {
    const p = provider({ jwksCacheMaxAge: 60_000 });
    expect(await usernameOf(p, sign(keyA))).toBe('alice');
    published = [keyB.jwk];
    advance(61_000);
    expect(await usernameOf(p, sign(keyA))).toBe('anonymous');
    expect(fetches).toBe(2);
  });

  it('keeps the last known keys when a fetch fails', async () => {
    const p = provider({ jwksCacheMaxAge: 60_000 });
    expect(await usernameOf(p, sign(keyA))).toBe('alice');
    status = 503;
    advance(61_000);
    expect(await usernameOf(p, sign(keyA))).toBe('alice');
    expect(fetches).toBe(2);
    expect(warn.mock.calls.flat().join(' ')).toContain('JWKS fetch failed');
  });

  it('does not re-fetch for an expired token — its key is known', async () => {
    const p = provider();
    expect(await usernameOf(p, sign(keyA))).toBe('alice');
    advance(31_000);
    const expired = sign(keyA, { sub: 'alice', exp: Math.floor(Date.now() / 1000) - 60 });
    expect(await usernameOf(p, expired)).toBe('anonymous');
    expect(fetches).toBe(1);
    expect(warn.mock.calls.flat().join(' ')).toContain('jwt expired');
  });

  it('does not re-fetch for a token rejected on its audience — its key is known', async () => {
    const p = provider({ audience: 'orders-api' });
    expect(await usernameOf(p, sign(keyA, { sub: 'alice', aud: 'orders-api' }))).toBe('alice');
    advance(31_000);
    expect(await usernameOf(p, sign(keyA, { sub: 'alice', aud: 'billing-api' }))).toBe('anonymous');
    expect(fetches).toBe(1);
    expect(warn.mock.calls.flat().join(' ')).toContain('jwt audience invalid');
  });

  it('tries every key when the token carries no kid', async () => {
    published = [keyA.jwk, keyB.jwk];
    expect(await usernameOf(provider(), sign(keyB, { sub: 'alice' }, {}))).toBe('alice');
  });

  it('ignores symmetric and encryption keys published in the set', async () => {
    const secret = 'shared-secret';
    published = [
      { kty: 'oct', k: Buffer.from(secret).toString('base64url'), kid: 'hmac' },
      { ...keyB.jwk, use: 'enc' },
    ];
    const hs256 = provider({ algorithm: 'HS256' });
    expect(await usernameOf(hs256, jwt.sign({ sub: 'mallory' }, secret, { algorithm: 'HS256', keyid: 'hmac' }))).toBe('anonymous');
    expect(await usernameOf(provider(), sign(keyB))).toBe('anonymous');
  });

  it('yields anonymous when the JWKS endpoint times out', async () => {
    const p = new GrantedJwtPrincipalProvider({ jwksUri: `${baseUrl}/hang`, jwksTimeout: 100 });
    expect(await usernameOf(p, sign(keyA))).toBe('anonymous');
    expect(warn.mock.calls.flat().join(' ')).toContain('JWKS fetch failed');
  });

  it('never falls back to an unverified decode, even when a getter runs without prepare()', async () => {
    const p = provider();
    expect(p.getUsernameFromRequest(reqWithToken(sign(keyA)))).toBe('anonymous');
    expect(fetches).toBe(0);
    // Once the keys are cached, a getter can verify on its own.
    await usernameOf(p, sign(keyA));
    expect(p.getUsernameFromRequest(reqWithToken(sign(keyA)))).toBe('alice');
  });

  it('treats a request without a token as anonymous, without fetching or logging', async () => {
    const p = provider();
    const req = { header: () => undefined, headers: {} } as any;
    await p.prepare(req);
    expect(p.getUsernameFromRequest(req)).toBe('anonymous');
    expect(fetches).toBe(0);
    expect(warn).not.toHaveBeenCalled();
  });

  it('never logs the token', async () => {
    const token = sign(outsider, { sub: 'mallory' });
    await usernameOf(provider(), token);
    expect(warn.mock.calls.flat().join(' ')).not.toContain(token);
  });

  it('works through the presets', async () => {
    const p = GrantedJwtPrincipalProvider.keycloak({ jwksUri: `${baseUrl}/jwks.json` });
    expect(await usernameOf(p, sign(keyA, { preferred_username: 'alice', realm_access: { roles: ['admin'] } }))).toBe('alice');
  });

  it('rejects jwksUri combined with a PEM key', () => {
    expect(() => new GrantedJwtPrincipalProvider({ jwksUri: `${baseUrl}/jwks.json`, base64Key: 'pem' })).toThrow('jwksUri cannot be combined');
  });
});
