import { generateKeyPairSync } from 'crypto';
import { ArgumentsHost, Catch, Controller, Get, INestApplication } from '@nestjs/common';
import { BaseExceptionFilter } from '@nestjs/core';
import { Test } from '@nestjs/testing';
import { createServer, IncomingMessage } from 'http';
import { AddressInfo } from 'net';
import * as jwt from 'jsonwebtoken';
import request from 'supertest';
import { Claim, GrantedClaim } from '../src/decorators/granted-claim.decorator';
import { GrantedTo } from '../src/decorators/granted-to.decorator';
import { GrantedModule } from '../src/granted.module';
import { isAuthenticated } from '../src/security/boolean-spec';
import { GrantedPrincipalProvider } from '../src/services/granted-info.provider';
import { GrantedJwtPrincipalProvider } from '../src/services/granted-info.jwt-provider';
import { IGrantedPrincipalProvider } from '../src/services/igranted-info.provider';

@Controller()
class ClaimController {
  @Get('raw')
  raw(@GrantedClaim('realm_access.territories') value: unknown) {
    return { value };
  }

  @Get('territories')
  territories(@GrantedClaim('territories', { type: 'string', array: true }) value: string[]) {
    return { value };
  }

  @Get('max-amount')
  maxAmount(@GrantedClaim('maxAmount', { type: 'number' }) value: number) {
    return { value };
  }

  @Get('codes')
  codes(@GrantedClaim('codes', { type: 'number', array: true }) value: number[]) {
    return { value };
  }

  @Get('auditor')
  auditor(@GrantedClaim('auditor', { type: 'boolean' }) value: boolean) {
    return { value };
  }

  @Get('legacy')
  legacy(@Claim('territories', { type: 'string', array: true }) value: string[]) {
    return { value };
  }

  @Get('required')
  @GrantedTo(isAuthenticated())
  required(@GrantedClaim('territories', { type: 'string', array: true, required: true }) value: string[]) {
    return { value };
  }
}

async function appWith(principalProvider: IGrantedPrincipalProvider, setup?: (app: INestApplication) => void): Promise<INestApplication> {
  const moduleRef = await Test.createTestingModule({ imports: [GrantedModule.forRoot({ principalProvider })], controllers: [ClaimController] }).compile();
  const app = moduleRef.createNestApplication({ logger: false });
  setup?.(app);
  await app.init();
  return app;
}

/** `undefined` doesn't survive JSON: an absent value comes back as `{}`. */
async function claim(app: INestApplication, path: string, headers: Record<string, string> = {}): Promise<unknown> {
  const res = await request(app.getHttpServer()).get(path).set(headers);
  expect(res.status).toBe(200);
  return res.body.value;
}

describe('@GrantedClaim', () => {
  let warn: jest.SpyInstance;

  beforeEach(() => {
    warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
  });

  afterEach(() => jest.restoreAllMocks());

  describe('from a JWT', () => {
    const secret = 'test-secret';
    const bearer = (payload: object) => ({ authorization: `Bearer ${jwt.sign(payload, secret, { algorithm: 'HS256' })}` });
    let app: INestApplication;

    beforeAll(async () => {
      app = await appWith(new GrantedJwtPrincipalProvider({ base64Key: secret, algorithm: 'HS256' }));
    });

    afterAll(() => app.close());

    it('reads a nested claim by its dotted path, as is', async () => {
      expect(await claim(app, '/raw', bearer({ sub: 'alice', realm_access: { territories: ['FR', 'GP'] } }))).toEqual(['FR', 'GP']);
    });

    it('reads a list, a number and a boolean', async () => {
      const token = bearer({ sub: 'alice', territories: ['FR', 'GP'], maxAmount: 5000, codes: [1, 2], auditor: true });
      expect(await claim(app, '/territories', token)).toEqual(['FR', 'GP']);
      expect(await claim(app, '/max-amount', token)).toBe(5000);
      expect(await claim(app, '/codes', token)).toEqual([1, 2]);
      expect(await claim(app, '/auditor', token)).toBe(true);
    });

    it('still answers to its former name, @Claim', async () => {
      expect(await claim(app, '/legacy', bearer({ sub: 'alice', territories: ['FR', 'GP'] }))).toEqual(['FR', 'GP']);
    });

    it('takes a single value as a list of one', async () => {
      expect(await claim(app, '/territories', bearer({ sub: 'alice', territories: 'FR' }))).toEqual(['FR']);
    });

    it('yields undefined, or [] for a list, when the claim is missing', async () => {
      const token = bearer({ sub: 'alice' });
      expect(await claim(app, '/max-amount', token)).toBeUndefined();
      expect(await claim(app, '/territories', token)).toEqual([]);
      expect(warn).not.toHaveBeenCalled();
    });

    it('ignores a value of the wrong type, with a warning that never shows it', async () => {
      const token = bearer({ sub: 'alice', territories: [41, 42], maxAmount: 'a-lot', auditor: 'yes' });
      expect(await claim(app, '/territories', token)).toEqual([]);
      expect(await claim(app, '/max-amount', token)).toBeUndefined();
      expect(await claim(app, '/auditor', token)).toBeUndefined();
      const logged = warn.mock.calls.flat().join(' ');
      expect(logged).toContain("claim 'territories' is not of the expected type (string[])");
      expect(logged).toContain("claim 'maxAmount' is not of the expected type (number)");
      expect(logged).not.toMatch(/a-lot|yes|41|42/);
    });

    it('drops only the elements of the wrong type from a list, with a warning that never shows them', async () => {
      expect(await claim(app, '/territories', bearer({ sub: 'alice', territories: ['FR', 42, 'GP'] }))).toEqual(['FR', 'GP']);
      expect(await claim(app, '/codes', bearer({ sub: 'alice', codes: [1, 'two', 3] }))).toEqual([1, 3]);
      const logged = warn.mock.calls.flat().join(' ');
      expect(logged).toContain("claim 'territories': 1 element(s) not of the expected type (string) ignored");
      expect(logged).toContain("claim 'codes': 1 element(s) not of the expected type (number) ignored");
      expect(logged).not.toMatch(/42|two/);
    });

    it('converts a number or a boolean given as a string — it is not of the wrong type', async () => {
      const token = bearer({ sub: 'alice', codes: ['1', 2], maxAmount: '5000', auditor: 'false' });
      expect(await claim(app, '/codes', token)).toEqual([1, 2]);
      expect(await claim(app, '/max-amount', token)).toBe(5000);
      expect(await claim(app, '/auditor', token)).toBe(false);
      expect(warn).not.toHaveBeenCalled();
    });

    it('refuses a list where a single value is expected', async () => {
      expect(await claim(app, '/max-amount', bearer({ sub: 'alice', maxAmount: [1, 2] }))).toBeUndefined();
    });

    it('answers 403 when a required claim is missing or invalid', async () => {
      const call = (payload: object) => request(app.getHttpServer()).get('/required').set(bearer(payload));
      expect((await call({ sub: 'alice', territories: ['FR'] })).body).toEqual({ value: ['FR'] });
      expect((await call({ sub: 'alice' })).status).toBe(403);
      expect((await call({ sub: 'alice', territories: [42] })).status).toBe(403);
      expect((await call({ sub: 'alice', territories: ['FR', 42] })).body).toEqual({ value: ['FR'] });
    });

    it('reads nothing from a token that fails verification', async () => {
      const forged = { authorization: `Bearer ${jwt.sign({ sub: 'mallory', territories: ['FR'] }, 'other-secret', { algorithm: 'HS256' })}` };
      expect(await claim(app, '/territories', forged)).toEqual([]);
    });

    it('never reads a header of the same name', async () => {
      expect(await claim(app, '/territories', { ...bearer({ sub: 'alice' }), territories: 'FR' })).toEqual([]);
    });
  });

  describe('from a JWKS-verified JWT, read after prepare()', () => {
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const server = createServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ keys: [{ ...publicKey.export({ format: 'jwk' }), kid: 'k1', use: 'sig', alg: 'ES256' }] }));
    });
    let app: INestApplication;

    beforeAll(async () => {
      await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
      const jwksUri = `http://127.0.0.1:${(server.address() as AddressInfo).port}/jwks.json`;
      app = await appWith(new GrantedJwtPrincipalProvider({ jwksUri }));
    });

    afterAll(async () => {
      await app.close();
      server.closeAllConnections();
      await new Promise((resolve) => server.close(resolve));
    });

    it('reads the claims of the verified token', async () => {
      const token = jwt.sign({ sub: 'alice', territories: ['FR', 'GP'] }, privateKey, { algorithm: 'ES256', keyid: 'k1' });
      expect(await claim(app, '/territories', { authorization: `Bearer ${token}` })).toEqual(['FR', 'GP']);
    });
  });

  describe('from gateway headers', () => {
    let app: INestApplication;

    beforeAll(async () => {
      app = await appWith(new GrantedPrincipalProvider());
    });

    afterAll(() => app.close());

    it('reads the header of the same name, as is without options', async () => {
      expect(await claim(app, '/raw', { 'realm_access.territories': 'FR' })).toBe('FR');
    });

    it('parses a list given as JSON or as CSV', async () => {
      expect(await claim(app, '/territories', { territories: '["FR","GP"]' })).toEqual(['FR', 'GP']);
      expect(await claim(app, '/territories', { territories: 'FR, GP ,' })).toEqual(['FR', 'GP']);
      expect(await claim(app, '/codes', { codes: '1, 2' })).toEqual([1, 2]);
      expect(await claim(app, '/codes', { codes: '[1, "2"]' })).toEqual([1, 2]);
    });

    it('converts numbers and booleans strictly', async () => {
      expect(await claim(app, '/max-amount', { maxAmount: '5000' })).toBe(5000);
      expect(await claim(app, '/auditor', { auditor: 'false' })).toBe(false);
      expect(await claim(app, '/max-amount', { maxAmount: 'a-lot' })).toBeUndefined();
      expect(await claim(app, '/auditor', { auditor: '1' })).toBeUndefined();
      expect(await claim(app, '/codes', { codes: '1, two' })).toEqual([1]);
      expect(await claim(app, '/codes', { codes: 'one, two' })).toEqual([]);
    });

    it('ignores a malformed JSON list', async () => {
      expect(await claim(app, '/territories', { territories: '["FR",' })).toEqual([]);
      expect(await claim(app, '/territories', { territories: '[ {"a": 1} ]' })).toEqual([]);
      expect(warn).toHaveBeenCalledTimes(2);
    });

    it('treats an empty header as missing', async () => {
      expect(await claim(app, '/territories', { territories: '' })).toEqual([]);
      expect(await claim(app, '/max-amount', { maxAmount: '' })).toBeUndefined();
      expect(warn).not.toHaveBeenCalled();
    });

    it('answers 403 when a required claim is missing', async () => {
      const res = await request(app.getHttpServer()).get('/required').set('username', 'alice');
      expect(res.status).toBe(403);
    });
  });

  it('fails clearly with a provider that does not implement getClaimFromIncomingMessage', async () => {
    const provider: IGrantedPrincipalProvider = {
      getUsernameFromRequest: () => 'alice',
      getRolesFromRequest: () => [],
      getTenantFromRequest: () => undefined,
      getUsernameFromIncomingMessage: (_msg: IncomingMessage) => 'alice',
      getRolesFromIncomingMessage: () => [],
      getTenantFromIncomingMessage: () => undefined,
    };
    const thrown: unknown[] = [];
    @Catch()
    class Recorder extends BaseExceptionFilter {
      catch(exception: unknown, host: ArgumentsHost) {
        thrown.push(exception);
        super.catch(exception, host);
      }
    }
    const app = await appWith(provider, (nest) => nest.useGlobalFilters(new Recorder(nest.getHttpAdapter())));
    const res = await request(app.getHttpServer()).get('/territories');
    await app.close();
    expect(res.status).toBe(500);
    expect(String(thrown[0])).toContain("@GrantedClaim('territories') needs a principal provider implementing getClaimFromIncomingMessage");
  });
});
