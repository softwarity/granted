import { BaseExceptionFilter, Reflector } from '@nestjs/core';
import { ArgumentsHost, Catch, Controller, ExecutionContext, ForbiddenException, Get, INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { AppGuard } from '../src/security/app.guard';
import { GrantedTo } from '../src/decorators/granted-to.decorator';
import { GrantedModuleOptions } from '../src/models/granted-module-options';
import { GrantedPrincipalProvider } from '../src/services/granted-info.provider';
import { and, hasRole, isAuthenticated, isUser, or } from '../src/security/boolean-spec';
import { GrantedModule } from '../src/granted.module';
import { GrantedForbiddenException } from '../src/security/granted-forbidden.exception';

// Class-level baseline + method-level tightening.
@GrantedTo(isAuthenticated())
class SampleController {
  @GrantedTo(hasRole('ADMIN'))
  adminRoute() {}

  // No own decorator → only the class-level spec applies.
  memberRoute() {}
}

function reqWithHeaders(headers: Record<string, string>) {
  return { header: (n: string) => headers[n.toLowerCase()], headers, params: {}, query: {}, body: {} } as any;
}

function ctx(handler: unknown, cls: unknown, headers: Record<string, string>): ExecutionContext {
  return {
    getHandler: () => handler,
    getClass: () => cls,
    switchToHttp: () => ({ getRequest: () => reqWithHeaders(headers) }),
  } as unknown as ExecutionContext;
}

function guard(options: Partial<GrantedModuleOptions> = {}): AppGuard {
  const opts: GrantedModuleOptions = { apply: true, principalProvider: new GrantedPrincipalProvider(), ...options };
  return new AppGuard(opts as GrantedModuleOptions, new Reflector());
}

describe('AppGuard — class + method @GrantedTo merge', () => {
  const proto = SampleController.prototype;

  it('requires BOTH class and method specs on a decorated method', async () => {
    const g = guard();
    // authenticated + ADMIN → allowed
    expect(await g.canActivate(ctx(proto.adminRoute, SampleController, { username: 'alice', roles: '["ADMIN"]' }))).toBe(true);
    // authenticated but missing ADMIN → method spec fails
    await expect(g.canActivate(ctx(proto.adminRoute, SampleController, { username: 'alice', roles: '[]' }))).rejects.toBeInstanceOf(GrantedForbiddenException);
    // has ADMIN but anonymous → class spec fails
    await expect(g.canActivate(ctx(proto.adminRoute, SampleController, { roles: '["ADMIN"]' }))).rejects.toBeInstanceOf(GrantedForbiddenException);
  });

  it('applies the class-level spec to a method without its own decorator', async () => {
    const g = guard();
    expect(await g.canActivate(ctx(proto.memberRoute, SampleController, { username: 'alice' }))).toBe(true);
    await expect(g.canActivate(ctx(proto.memberRoute, SampleController, {}))).rejects.toBeInstanceOf(GrantedForbiddenException); // anonymous
  });

  it('is open when neither class nor method declares specs', async () => {
    class Plain {
      route() {}
    }
    expect(await guard().canActivate(ctx(Plain.prototype.route, Plain, {}))).toBe(true);
  });

  it('lets everything through when apply is false', async () => {
    const g = guard({ apply: false });
    expect(await g.canActivate(ctx(proto.adminRoute, SampleController, {}))).toBe(true);
  });
});

describe('AppGuard — provider prepare() hook', () => {
  /** Resolves the identity asynchronously, as a provider fetching a JWKS does. */
  class AsyncProvider extends GrantedPrincipalProvider {
    prepare = jest.fn(async (request: any) => {
      await new Promise((resolve) => setImmediate(resolve));
      request.headers.username = 'alice';
    });
  }

  it('awaits prepare() before evaluating the specs', async () => {
    const g = guard({ principalProvider: new AsyncProvider() });
    expect(await g.canActivate(ctx(SampleController.prototype.memberRoute, SampleController, {}))).toBe(true);
  });

  it('runs prepare() on open routes and with apply: false too, for the parameter decorators', async () => {
    class Plain {
      route() {}
    }
    const principalProvider = new AsyncProvider();
    await guard({ principalProvider }).canActivate(ctx(Plain.prototype.route, Plain, {}));
    await guard({ principalProvider, apply: false }).canActivate(ctx(SampleController.prototype.adminRoute, SampleController, {}));
    expect(principalProvider.prepare).toHaveBeenCalledTimes(2);
  });
});

describe('AppGuard — GrantedForbiddenException', () => {
  const proto = SampleController.prototype;

  async function denial(promise: Promise<boolean>): Promise<GrantedForbiddenException> {
    try {
      await promise;
    } catch (e) {
      return e as GrantedForbiddenException;
    }
    throw new Error('expected the guard to deny');
  }

  it('carries the failed spec and the identity it was evaluated against', async () => {
    const g = guard({ roleHierarchy: { MANAGER: ['USER'] } });
    const e = await denial(g.canActivate(ctx(proto.adminRoute, SampleController, { username: 'bob', roles: '["MANAGER"]', tenant: 'acme' })));
    expect(e).toBeInstanceOf(ForbiddenException);
    expect(e.deniedSpec).toBe('hasRole(ADMIN)');
    expect(e.username).toBe('bob');
    expect(e.roles).toEqual(['MANAGER', 'USER']); // resolved roles, not the raw header
    expect(e.tenant).toBe('acme');
  });

  it('reports a composed spec whole', async () => {
    class Composed {
      @GrantedTo(and(isAuthenticated(), or(hasRole('ADMIN'), isUser('Param', 'userId'))))
      route() {}
    }
    const e = await denial(guard().canActivate(ctx(Composed.prototype.route, Composed, { username: 'bob' })));
    expect(e.deniedSpec).toBe('and(isAuthenticated(),or(hasRole(ADMIN),isUser(Param, userId)))');
  });

  it('keeps the response body NestJS sends for a guard returning false', async () => {
    const e = await denial(guard().canActivate(ctx(proto.adminRoute, SampleController, {})));
    expect(e.getStatus()).toBe(403);
    expect(e.getResponse()).toEqual({ statusCode: 403, message: 'Forbidden resource', error: 'Forbidden' });
  });
});

describe('AppGuard — 403 over HTTP', () => {
  @Controller('admin')
  @GrantedTo(isAuthenticated())
  class AdminController {
    @Get('config')
    @GrantedTo(hasRole('ADMIN'))
    config() {
      return 'ok';
    }
  }

  /** What a host app does to log denials in its own format. */
  @Catch(GrantedForbiddenException)
  class DenialFilter extends BaseExceptionFilter {
    static caught: GrantedForbiddenException[] = [];
    catch(exception: GrantedForbiddenException, host: ArgumentsHost) {
      DenialFilter.caught.push(exception);
      super.catch(exception, host);
    }
  }

  let app: INestApplication;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({ imports: [GrantedModule.forRoot()], controllers: [AdminController] }).compile();
    app = moduleRef.createNestApplication();
    app.useGlobalFilters(new DenialFilter(app.getHttpAdapter()));
    await app.init();
  });

  afterAll(() => app.close());

  it('answers a bare 403 and hands the details to the host filter', async () => {
    const res = await request(app.getHttpServer()).get('/admin/config').set('username', 'bob').set('roles', '["USER"]');
    expect(res.status).toBe(403);
    expect(res.body).toEqual({ statusCode: 403, message: 'Forbidden resource', error: 'Forbidden' });
    expect(DenialFilter.caught).toHaveLength(1);
    expect(DenialFilter.caught[0]).toMatchObject({ deniedSpec: 'hasRole(ADMIN)', username: 'bob', roles: ['USER'] });
  });

  it('lets a granted call through', async () => {
    const res = await request(app.getHttpServer()).get('/admin/config').set('username', 'alice').set('roles', '["ADMIN"]');
    expect(res.status).toBe(200);
  });
});
