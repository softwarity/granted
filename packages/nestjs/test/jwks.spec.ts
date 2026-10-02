import { generateKeyPairSync, KeyObject, sign as signBytes } from 'crypto';
import { createServer } from 'http';
import { AddressInfo } from 'net';
import * as jwt from 'jsonwebtoken';
import { GrantedJwtPrincipalProvider, GrantedJwtPrincipalProviderConfig, JwtAlgorithm } from '../src/services/granted-info.jwt-provider';

interface SigningKey {
  kid: string;
  alg: JwtAlgorithm;
  privateKey: KeyObject;
  publicKey: KeyObject;
  jwk: Record<string, unknown>;
}

function signingKey(kid: string, alg: JwtAlgorithm, { privateKey, publicKey }: { privateKey: KeyObject; publicKey: KeyObject }): SigningKey {
  return { kid, alg, privateKey, publicKey, jwk: { ...publicKey.export({ format: 'jwk' }), kid, use: 'sig', alg } };
}

function rsaKey(kid: string): SigningKey {
  return signingKey(kid, 'RS256', generateKeyPairSync('rsa', { modulusLength: 2048 }));
}

function ecKey(kid: string): SigningKey {
  return signingKey(kid, 'ES256', generateKeyPairSync('ec', { namedCurve: 'P-256' }));
}

function edKey(kid: string): SigningKey {
  return signingKey(kid, 'EdDSA', generateKeyPairSync('ed25519'));
}

/** The same key, published without `alg` — as Microsoft Entra ID does. */
function withoutAlg({ alg: _alg, ...jwk }: Record<string, unknown>): Record<string, unknown> {
  return jwk;
}

const base64url = (value: object) => Buffer.from(JSON.stringify(value)).toString('base64url');

/** `jsonwebtoken` can't sign EdDSA: the token is assembled by hand. */
function signEdDsa(key: SigningKey, payload: object): string {
  const signed = `${base64url({ alg: 'EdDSA', typ: 'JWT', kid: key.kid })}.${base64url(payload)}`;
  return `${signed}.${signBytes(null, Buffer.from(signed), key.privateKey).toString('base64url')}`;
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
    if (key.alg === 'EdDSA') {
      return signEdDsa(key, payload);
    }
    return jwt.sign(payload, key.privateKey, { algorithm: key.alg, ...options });
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
    expect(await usernameOf(provider(), jwt.sign({ sub: 'mallory' }, secret, { algorithm: 'HS256', keyid: 'hmac' }))).toBe('anonymous');
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

  describe('algorithm', () => {
    const ec = ecKey('key-ec');
    const ed = edKey('key-ed');
    const warnings = () => warn.mock.calls.flat().join(' ');

    beforeEach(() => {
      published = [keyA.jwk, ec.jwk, ed.jwk];
    });

    it('verifies RS256, ES256 and EdDSA tokens against the same set, with no algorithm configured', async () => {
      const p = provider();
      expect(await usernameOf(p, sign(keyA, { sub: 'rsa' }))).toBe('rsa');
      expect(await usernameOf(p, sign(ec, { sub: 'ec' }))).toBe('ec');
      expect(await usernameOf(p, sign(ed, { sub: 'ed' }))).toBe('ed');
      expect(fetches).toBe(1);
      expect(warn).not.toHaveBeenCalled();
    });

    it('rejects a token whose kid is not in the set', async () => {
      expect(await usernameOf(provider(), sign(keyA, { sub: 'alice' }, { keyid: 'unknown' }))).toBe('anonymous');
      expect(warnings()).toContain('no JWKS key matches the token');
    });

    it('rejects a token announcing another algorithm than its key', async () => {
      const p = provider();
      // Each of these would verify if the token's `alg` were trusted.
      const rs384 = jwt.sign({ sub: 'mallory' }, keyA.privateKey, { algorithm: 'RS384', keyid: keyA.kid });
      const hs256 = jwt.sign({ sub: 'mallory' }, keyA.publicKey.export({ type: 'spki', format: 'pem' }), { algorithm: 'HS256', keyid: keyA.kid });
      const unsigned = jwt.sign({ sub: 'mallory' }, null, { algorithm: 'none', keyid: keyA.kid });
      for (const token of [rs384, hs256, unsigned]) {
        warn.mockClear();
        expect(await usernameOf(p, token)).toBe('anonymous');
        expect(warnings()).toContain('invalid algorithm');
      }
    });

    it('used as an allowlist, rejects the keys of any other algorithm', async () => {
      const p = provider({ algorithm: ['RS256', 'EdDSA'] });
      expect(await usernameOf(p, sign(keyA))).toBe('alice');
      expect(await usernameOf(p, sign(ed))).toBe('alice');
      expect(await usernameOf(p, sign(ec))).toBe('anonymous');
      expect(warnings()).toContain('invalid algorithm');
      expect(await usernameOf(provider({ algorithm: 'ES256' }), sign(ec))).toBe('alice');
      expect(await usernameOf(provider({ algorithm: 'ES256' }), sign(keyA))).toBe('anonymous');
    });

    it('refuses none and HS* at construction, and EdDSA without a JWKS', () => {
      expect(() => provider({ algorithm: 'HS256' })).toThrow('HS256 cannot be used with jwksUri');
      expect(() => provider({ algorithm: ['RS256', 'none'] })).toThrow('none cannot be used with jwksUri');
      expect(() => provider({ algorithm: [] })).toThrow('empty list');
      expect(() => new GrantedJwtPrincipalProvider({ base64Key: 'pem', algorithm: 'EdDSA' })).toThrow('only supported with jwksUri');
    });

    it('infers the algorithm of a key published without alg from its type', async () => {
      published = [keyA.jwk, ec.jwk, ed.jwk].map(withoutAlg);
      const p = provider();
      expect(await usernameOf(p, sign(keyA))).toBe('alice');
      expect(await usernameOf(p, sign(ec))).toBe('alice');
      expect(await usernameOf(p, sign(ed))).toBe('alice');
      // An RSA key without alg is taken as RS256, whatever the token says.
      expect(await usernameOf(p, jwt.sign({ sub: 'alice' }, keyA.privateKey, { algorithm: 'RS384', keyid: keyA.kid }))).toBe('anonymous');
    });

    it('lets the allowlist choose the algorithm of a key published without alg', async () => {
      published = [withoutAlg(keyA.jwk)];
      const ps256 = jwt.sign({ sub: 'alice' }, keyA.privateKey, { algorithm: 'PS256', keyid: keyA.kid });
      expect(await usernameOf(provider(), ps256)).toBe('anonymous');
      expect(await usernameOf(provider({ algorithm: 'PS256' }), ps256)).toBe('alice');
      expect(await usernameOf(provider({ algorithm: 'PS256' }), sign(keyA))).toBe('anonymous');
    });

    it('ignores a key whose alg its type cannot verify', async () => {
      published = [
        { ...keyA.jwk, alg: 'ES256' },
        { ...ec.jwk, alg: 'HS256' },
      ];
      expect(await usernameOf(provider(), sign(keyA))).toBe('anonymous');
      expect(await usernameOf(provider(), sign(ec))).toBe('anonymous');
    });

    describe('EdDSA', () => {
      it('rejects a tampered token', async () => {
        const [header, , signature] = sign(ed, { sub: 'alice' }).split('.');
        expect(await usernameOf(provider(), `${header}.${base64url({ sub: 'mallory' })}.${signature}`)).toBe('anonymous');
        expect(warnings()).toContain('invalid signature');
      });

      it('rejects a token signed by another Ed25519 key', async () => {
        const forged = signEdDsa({ ...edKey('other'), kid: ed.kid }, { sub: 'mallory' });
        expect(await usernameOf(provider(), forged)).toBe('anonymous');
      });

      it('checks the validity dates, without re-fetching — the key is known', async () => {
        const p = provider();
        const now = Math.floor(Date.now() / 1000);
        expect(await usernameOf(p, sign(ed, { sub: 'alice', nbf: now - 60, exp: now + 60 }))).toBe('alice');
        advance(31_000);
        expect(await usernameOf(p, sign(ed, { sub: 'alice', exp: now - 60 }))).toBe('anonymous');
        expect(await usernameOf(p, sign(ed, { sub: 'alice', nbf: now + 600 }))).toBe('anonymous');
        expect(fetches).toBe(1);
        expect(warnings()).toMatch(/jwt expired[\s\S]*jwt not active/);
      });

      it('checks issuer and audience when configured', async () => {
        const p = provider({ issuer: ['https://idp.acme', 'https://gateway.acme'], audience: /^orders-/ });
        const claims = { sub: 'alice', iss: 'https://gateway.acme', aud: ['billing-api', 'orders-api'] };
        expect(await usernameOf(p, sign(ed, claims))).toBe('alice');
        expect(await usernameOf(p, sign(ed, { ...claims, iss: 'https://evil.example' }))).toBe('anonymous');
        expect(await usernameOf(p, sign(ed, { ...claims, aud: 'billing-api' }))).toBe('anonymous');
        expect(await usernameOf(p, sign(ed, { sub: 'alice' }))).toBe('anonymous');
        expect(warnings()).toMatch(/issuer invalid[\s\S]*audience invalid/);
      });
    });
  });
});
