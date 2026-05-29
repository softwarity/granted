import { Request } from 'express';
import { and, hasRole, isAuthenticated, isFalse, isTrue, isTenant, isUser, not, or } from '../src/security/boolean-spec';

/** Minimal Request stub — only the fields the specs actually read. */
function req(overrides: Partial<Request> = {}): Request {
  return {
    params: {},
    query: {},
    body: {},
    ...overrides,
  } as unknown as Request;
}

describe('boolean-spec', () => {
  describe('isTrue / isFalse', () => {
    it('isTrue always passes', () => {
      expect(isTrue().apply(req(), 'anonymous', [])).toBe(true);
    });

    it('isFalse always fails', () => {
      expect(isFalse().apply(req(), 'alice', ['ADMIN'])).toBe(false);
    });
  });

  describe('hasRole', () => {
    it('passes when the role is present', () => {
      expect(hasRole('ADMIN').apply(req(), 'alice', ['ADMIN'])).toBe(true);
    });

    it('fails when the role is missing', () => {
      expect(hasRole('ADMIN').apply(req(), 'alice', ['USER'])).toBe(false);
    });
  });

  describe('isAuthenticated', () => {
    it('passes for a named user', () => {
      expect(isAuthenticated().apply(req(), 'alice', [])).toBe(true);
    });

    it('fails for anonymous', () => {
      expect(isAuthenticated().apply(req(), 'anonymous', [])).toBe(false);
    });

    it('fails for an empty username', () => {
      expect(isAuthenticated().apply(req(), '', [])).toBe(false);
    });
  });

  describe('not', () => {
    it('inverts the wrapped spec', () => {
      expect(not(isTrue()).apply(req(), 'alice', [])).toBe(false);
      expect(not(isFalse()).apply(req(), 'alice', [])).toBe(true);
    });
  });

  describe('and', () => {
    it('passes only when every spec passes', () => {
      const spec = and(isAuthenticated(), hasRole('ADMIN'));
      expect(spec.apply(req(), 'alice', ['ADMIN'])).toBe(true);
      expect(spec.apply(req(), 'alice', ['USER'])).toBe(false);
      expect(spec.apply(req(), 'anonymous', ['ADMIN'])).toBe(false);
    });
  });

  describe('or', () => {
    it('passes when at least one spec passes', () => {
      const spec = or(hasRole('ADMIN'), hasRole('SUPERUSER'));
      expect(spec.apply(req(), 'alice', ['SUPERUSER'])).toBe(true);
      expect(spec.apply(req(), 'alice', ['USER'])).toBe(false);
    });
  });

  describe('isUser', () => {
    it('matches a route param', () => {
      const r = req({ params: { userId: 'alice' } as any });
      expect(isUser('Param', 'userId').apply(r, 'alice', [])).toBe(true);
      expect(isUser('Param', 'userId').apply(r, 'bob', [])).toBe(false);
    });

    it('matches a query param', () => {
      const r = req({ query: { owner: 'alice' } as any });
      expect(isUser('Query', 'owner').apply(r, 'alice', [])).toBe(true);
    });

    it('matches a nested body field', () => {
      const r = req({ body: { author: { id: 'alice' } } });
      expect(isUser('Body', 'author.id').apply(r, 'alice', [])).toBe(true);
      expect(isUser('Body', 'author.id').apply(r, 'bob', [])).toBe(false);
    });

    it('returns false when the body path is missing', () => {
      const r = req({ body: {} });
      expect(isUser('Body', 'author.id').apply(r, 'alice', [])).toBe(false);
    });
  });

  describe('isTenant', () => {
    it('matches the caller tenant against a route param', () => {
      const r = req({ params: { tenantId: 'acme' } as any });
      expect(isTenant('Param', 'tenantId').apply(r, 'alice', [], 'acme')).toBe(true);
      expect(isTenant('Param', 'tenantId').apply(r, 'alice', [], 'globex')).toBe(false);
    });

    it('matches against a query param and a nested body path', () => {
      const rq = req({ query: { tenant: 'acme' } as any });
      expect(isTenant('Query', 'tenant').apply(rq, 'alice', [], 'acme')).toBe(true);
      const rb = req({ body: { org: { id: 'acme' } } });
      expect(isTenant('Body', 'org.id').apply(rb, 'alice', [], 'acme')).toBe(true);
    });

    it('denies when the caller has no tenant', () => {
      const r = req({ params: { tenantId: 'acme' } as any });
      expect(isTenant('Param', 'tenantId').apply(r, 'alice', [], undefined)).toBe(false);
    });

    it('denies when the requested value is missing', () => {
      const r = req({ params: {} as any });
      expect(isTenant('Param', 'tenantId').apply(r, 'alice', [], 'acme')).toBe(false);
    });
  });

  describe('tenant forwarding through combinators', () => {
    it('and/or/not pass the tenant down to nested specs', () => {
      const r = req({ params: { tenantId: 'acme' } as any });
      const spec = and(isAuthenticated(), or(hasRole('ADMIN'), isTenant('Param', 'tenantId')));
      expect(spec.apply(r, 'alice', ['USER'], 'acme')).toBe(true); // owner of tenant
      expect(spec.apply(r, 'alice', ['USER'], 'globex')).toBe(false); // wrong tenant, not admin
      expect(spec.apply(r, 'alice', ['ADMIN'], 'globex')).toBe(true); // admin bypasses tenant
      expect(not(isTenant('Param', 'tenantId')).apply(r, 'alice', [], 'globex')).toBe(true);
    });
  });

  describe('id description', () => {
    it('produces a readable composite id', () => {
      expect(and(isAuthenticated(), hasRole('ADMIN')).id).toBe('and(isAuthenticated(),hasRole(ADMIN))');
    });
  });
});
