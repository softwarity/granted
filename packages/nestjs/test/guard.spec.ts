import { Reflector } from '@nestjs/core';
import { ExecutionContext } from '@nestjs/common';
import { AppGuard } from '../src/security/app.guard';
import { GrantedTo } from '../src/decorators/granted-to.decorator';
import { GrantedModuleOptions } from '../src/models/granted-module-options';
import { GrantedPrincipalProvider } from '../src/services/granted-info.provider';
import { hasRole, isAuthenticated } from '../src/security/boolean-spec';

// Class-level baseline + method-level tightening.
@GrantedTo(isAuthenticated())
class SampleController {
  @GrantedTo(hasRole('ADMIN'))
  adminRoute() {}

  // No own decorator → only the class-level spec applies.
  memberRoute() {}
}

function reqWithHeaders(headers: Record<string, string>) {
  return { header: (n: string) => headers[n.toLowerCase()], headers } as any;
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
    expect(await g.canActivate(ctx(proto.adminRoute, SampleController, { username: 'alice', roles: '[]' }))).toBe(false);
    // has ADMIN but anonymous → class spec fails
    expect(await g.canActivate(ctx(proto.adminRoute, SampleController, { roles: '["ADMIN"]' }))).toBe(false);
  });

  it('applies the class-level spec to a method without its own decorator', async () => {
    const g = guard();
    expect(await g.canActivate(ctx(proto.memberRoute, SampleController, { username: 'alice' }))).toBe(true);
    expect(await g.canActivate(ctx(proto.memberRoute, SampleController, {}))).toBe(false); // anonymous
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
