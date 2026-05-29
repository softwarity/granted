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

  it('requires BOTH class and method specs on a decorated method', () => {
    const g = guard();
    // authenticated + ADMIN → allowed
    expect(g.canActivate(ctx(proto.adminRoute, SampleController, { username: 'alice', roles: '["ADMIN"]' }))).toBe(true);
    // authenticated but missing ADMIN → method spec fails
    expect(g.canActivate(ctx(proto.adminRoute, SampleController, { username: 'alice', roles: '[]' }))).toBe(false);
    // has ADMIN but anonymous → class spec fails
    expect(g.canActivate(ctx(proto.adminRoute, SampleController, { roles: '["ADMIN"]' }))).toBe(false);
  });

  it('applies the class-level spec to a method without its own decorator', () => {
    const g = guard();
    expect(g.canActivate(ctx(proto.memberRoute, SampleController, { username: 'alice' }))).toBe(true);
    expect(g.canActivate(ctx(proto.memberRoute, SampleController, {}))).toBe(false); // anonymous
  });

  it('is open when neither class nor method declares specs', () => {
    class Plain {
      route() {}
    }
    expect(guard().canActivate(ctx(Plain.prototype.route, Plain, {}))).toBe(true);
  });

  it('lets everything through when apply is false', () => {
    const g = guard({ apply: false });
    expect(g.canActivate(ctx(proto.adminRoute, SampleController, {}))).toBe(true);
  });
});
