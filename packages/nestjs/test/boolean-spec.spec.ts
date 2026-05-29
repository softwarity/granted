import { Request } from 'express';
import { and, hasRole, isAuthenticated, isFalse, isTrue, isUser, not, or } from '../src/security/boolean-spec';

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

  describe('id description', () => {
    it('produces a readable composite id', () => {
      expect(and(isAuthenticated(), hasRole('ADMIN')).id).toBe('and(isAuthenticated(),hasRole(ADMIN))');
    });
  });
});
