import { createPublicKey, KeyObject, verify as verifySignature } from 'crypto';
import { Request } from 'express';
import * as fs from 'fs';
import { IncomingMessage } from 'http';
import { Algorithm, decode, JsonWebTokenError, Jwt, JwtPayload, NotBeforeError, TokenExpiredError, verify, VerifyOptions } from 'jsonwebtoken';
import { IGrantedPrincipalProvider } from './igranted-info.provider';

/** `jsonwebtoken`'s algorithms, plus EdDSA — only with `jwksUri`, where Node's `crypto` verifies it. */
export type JwtAlgorithm = Algorithm | 'EdDSA';

/** Key material, signature algorithm and expected issuer / audience — what a preset can't infer. */
export interface JwtKeyConfig {
  /** Public key (PEM) used to verify the token signature. */
  base64Key?: string;
  /** Path to a PEM public key file — read once at construction. */
  pemFile?: string;
  /**
   * URL of the JWK Set publishing the IdP's signing keys, e.g.
   * `https://idp.example.com/.well-known/jwks.json`. Keys are fetched on first
   * use, cached, and re-fetched when a token fails verification — so a key
   * rotation needs no restart. Each key verifies with its own algorithm, so
   * `algorithm` isn't needed. Can't be combined with `base64Key` / `pemFile`.
   */
  jwksUri?: string;
  /** Age (ms) after which cached JWKS keys are re-fetched. Defaults to 10 minutes. */
  jwksCacheMaxAge?: number;
  /**
   * Minimum delay (ms) between two JWKS fetches, so tokens with forged `kid`s
   * can't make the provider hammer the IdP. Defaults to 30 seconds.
   */
  jwksCooldown?: number;
  /** Timeout (ms) of a JWKS fetch. Defaults to 5 seconds. */
  jwksTimeout?: number;
  /**
   * With a PEM key (`base64Key` / `pemFile`): the signature algorithm. Defaults to `'ES256'`.
   *
   * With `jwksUri`: optional. Each key verifies with the algorithm the JWK Set
   * gives it — never the one the token announces — so the IdP can change
   * algorithm without any change here. When set, it is an allowlist: a token
   * signed with another algorithm is rejected. Only asymmetric algorithms
   * (RS*, PS*, ES*, EdDSA) are accepted with a JWKS.
   */
  algorithm?: JwtAlgorithm | JwtAlgorithm[];
  /**
   * Accepted `iss` value(s). Not checked when unset — e.g. behind a gateway
   * that already validated the token. Needs a key (`base64Key`, `pemFile` or `jwksUri`).
   */
  issuer?: string | string[];
  /**
   * Accepted `aud` value(s), as strings or patterns. Not checked when unset.
   * Needs a key (`base64Key`, `pemFile` or `jwksUri`).
   */
  audience?: string | RegExp | (string | RegExp)[];
}

/**
 * Maps token claims to identity fields. Each claim accepts a dotted path, so
 * nested claims work too (e.g. Keycloak's `'realm_access.roles'`).
 */
export interface JwtClaimMapping {
  /** Claim mapped to the username. Defaults to `'sub'`. */
  usernameClaim?: string;
  /** Claim mapped to the roles array. Defaults to `'roles'`. */
  rolesClaim?: string;
  /** Claim mapped to the tenant identifier. Defaults to `'tenant'`. */
  tenantClaim?: string;
}

export type GrantedJwtPrincipalProviderConfig = JwtKeyConfig & JwtClaimMapping;

/** Claim mappings for well-known identity providers. Override any field as needed. */
export const JWT_CLAIM_PRESETS = {
  /** RFC 9068 "JWT Profile for OAuth 2.0 Access Tokens" + SCIM (`roles`). */
  rfc9068: { usernameClaim: 'sub', rolesClaim: 'roles', tenantClaim: 'tenant' },
  /** Microsoft Entra ID (Azure AD): UPN in `preferred_username`, tenant in `tid`. */
  azureAd: { usernameClaim: 'preferred_username', rolesClaim: 'roles', tenantClaim: 'tid' },
  /** Keycloak: realm roles live under `realm_access.roles`. */
  keycloak: { usernameClaim: 'preferred_username', rolesClaim: 'realm_access.roles', tenantClaim: 'tenant' },
  /** Okta: authorities exposed as `groups`. */
  okta: { usernameClaim: 'sub', rolesClaim: 'groups', tenantClaim: 'tenant' },
} as const satisfies Record<string, Required<JwtClaimMapping>>;

interface JwksKey {
  kid?: string;
  key: KeyObject;
  /** Algorithms this key verifies with — set from the JWK Set, never from a token. */
  algorithms: JwtAlgorithm[];
}

/** What a JWKS key may verify: asymmetric signatures only — never `none`, never a shared-secret HS*. */
const JWKS_ALGORITHMS: JwtAlgorithm[] = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512', 'EdDSA'];

const EC_CURVE_ALGORITHMS: Record<string, JwtAlgorithm> = { prime256v1: 'ES256', secp384r1: 'ES384', secp521r1: 'ES512' };

/** Algorithms a key of this type can verify, the one assumed for a JWK without `alg` first. */
function keyAlgorithms(key: KeyObject): JwtAlgorithm[] {
  switch (key.asymmetricKeyType) {
    case 'rsa':
      return ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'];
    case 'ec':
      return [EC_CURVE_ALGORITHMS[key.asymmetricKeyDetails?.namedCurve]].filter(Boolean);
    case 'ed25519':
    case 'ed448':
      return ['EdDSA'];
    default:
      return [];
  }
}

/**
 * Claims are only checked once the signature is valid: a token rejected for
 * its dates, issuer or audience did match the key, so no other key can do better.
 */
function signatureMatched(err: unknown): boolean {
  return err instanceof TokenExpiredError || err instanceof NotBeforeError || (err instanceof JsonWebTokenError && /^jwt (audience|issuer) invalid/.test(err.message));
}

/**
 * Resolves the identity from a verified JWT carried in the
 * `Authorization: Bearer <token>` header.
 *
 * Use the constructor for a fully custom claim mapping, or one of the static
 * presets ({@link GrantedJwtPrincipalProvider.rfc9068}, `.azureAd`, `.keycloak`,
 * `.okta`) which pre-fill the mapping so you only pass key material: a PEM key
 * (`base64Key` / `pemFile`) or the IdP's JWK Set (`jwksUri`).
 *
 * A token that is missing, malformed, or fails verification yields an
 * anonymous request (empty claims) — it is then up to the `@GrantedTo` specs
 * to reject it.
 */
export class GrantedJwtPrincipalProvider implements IGrantedPrincipalProvider {
  base64Key: string;
  jwksUri: string;
  jwksCacheMaxAge: number;
  jwksCooldown: number;
  jwksTimeout: number;
  algorithm: JwtAlgorithm | JwtAlgorithm[];
  issuer: string | string[];
  audience: string | RegExp | (string | RegExp)[];
  usernameClaim: string;
  rolesClaim: string;
  tenantClaim: string;

  /** `algorithm` as a list. Undefined with a JWKS and no allowlist: each key's own algorithm is accepted. */
  private algorithms: JwtAlgorithm[] | undefined;
  private jwks: JwksKey[] = [];
  /** Last successful JWKS fetch — drives `jwksCacheMaxAge`. */
  private jwksFetchedAt = 0;
  /** Last JWKS fetch attempt, successful or not — drives `jwksCooldown`. */
  private jwksAttemptedAt = 0;
  /** Fetch in progress, shared by concurrent requests. */
  private jwksFetch: Promise<JwksKey[]> | undefined;

  constructor(conf: GrantedJwtPrincipalProviderConfig) {
    if (conf.jwksUri && (conf.base64Key || conf.pemFile)) {
      throw new Error('[nestjs-granted] jwksUri cannot be combined with base64Key or pemFile');
    }
    if ((conf.issuer || conf.audience) && !(conf.base64Key || conf.pemFile || conf.jwksUri)) {
      // An unverified token's claims can say anything: checking them would only look secure.
      throw new Error('[nestjs-granted] issuer and audience need a key to verify the token: base64Key, pemFile or jwksUri');
    }
    this.base64Key = conf.base64Key;
    this.jwksUri = conf.jwksUri;
    this.jwksCacheMaxAge = conf.jwksCacheMaxAge ?? 600_000;
    this.jwksCooldown = conf.jwksCooldown ?? 30_000;
    this.jwksTimeout = conf.jwksTimeout ?? 5_000;
    // The default is for a PEM key only: with a JWKS, each key brings its own algorithm.
    this.algorithm = conf.algorithm || (conf.jwksUri ? undefined : 'ES256');
    this.algorithms = this.algorithm ? [this.algorithm].flat() : undefined;
    if (this.algorithms?.length === 0) {
      throw new Error('[nestjs-granted] algorithm is an empty list: no token could be verified');
    }
    if (conf.jwksUri) {
      // A JWK Set publishes public keys: `none` and the shared-secret HS* have no place here.
      const refused = (this.algorithms || []).filter((alg) => !JWKS_ALGORITHMS.includes(alg));
      if (refused.length) {
        throw new Error(`[nestjs-granted] algorithm ${refused.join(', ')} cannot be used with jwksUri, which accepts ${JWKS_ALGORITHMS.join(', ')}`);
      }
    } else if (this.algorithms.includes('EdDSA')) {
      throw new Error('[nestjs-granted] EdDSA is only supported with jwksUri');
    }
    this.issuer = conf.issuer;
    this.audience = conf.audience;
    this.usernameClaim = conf.usernameClaim || 'sub';
    this.rolesClaim = conf.rolesClaim || 'roles';
    this.tenantClaim = conf.tenantClaim || 'tenant';
    if (conf.pemFile) {
      this.base64Key = fs.readFileSync(conf.pemFile, 'utf8');
    }
  }

  /** Preset for RFC 9068 / SCIM access tokens. */
  static rfc9068(conf: JwtKeyConfig & JwtClaimMapping): GrantedJwtPrincipalProvider {
    return new GrantedJwtPrincipalProvider({ ...JWT_CLAIM_PRESETS.rfc9068, ...conf });
  }

  /** Preset for Microsoft Entra ID (Azure AD). */
  static azureAd(conf: JwtKeyConfig & JwtClaimMapping): GrantedJwtPrincipalProvider {
    return new GrantedJwtPrincipalProvider({ ...JWT_CLAIM_PRESETS.azureAd, ...conf });
  }

  /** Preset for Keycloak (realm roles under `realm_access.roles`). */
  static keycloak(conf: JwtKeyConfig & JwtClaimMapping): GrantedJwtPrincipalProvider {
    return new GrantedJwtPrincipalProvider({ ...JWT_CLAIM_PRESETS.keycloak, ...conf });
  }

  /** Preset for Okta (authorities as `groups`). */
  static okta(conf: JwtKeyConfig & JwtClaimMapping): GrantedJwtPrincipalProvider {
    return new GrantedJwtPrincipalProvider({ ...JWT_CLAIM_PRESETS.okta, ...conf });
  }

  /**
   * Awaited by the guard before any getter runs. Only a JWKS needs I/O: PEM keys
   * and unsigned tokens are still resolved lazily by the getters.
   */
  async prepare(request: IncomingMessage): Promise<void> {
    if (!this.jwksUri || request['jwt']) {
      return;
    }
    const token = this.getJwtFromAuthHeader(this.getAuthHeaderIncomingMessage(request));
    request['jwt'] = token ? await this.verifyWithJwks(token) : {};
  }

  getUsernameFromRequest(request: Request): string {
    return this.resolveClaim(this.initFromRequest(request), this.usernameClaim) || 'anonymous';
  }

  getRolesFromRequest(request: Request): string[] {
    return this.resolveClaim(this.initFromRequest(request), this.rolesClaim) || [];
  }

  getTenantFromRequest(request: Request): string | undefined {
    return this.resolveClaim(this.initFromRequest(request), this.tenantClaim) || undefined;
  }

  getUsernameFromIncomingMessage(incomingMessage: IncomingMessage): string {
    return this.resolveClaim(this.initFromIncomingMessage(incomingMessage), this.usernameClaim) || 'anonymous';
  }

  getRolesFromIncomingMessage(incomingMessage: IncomingMessage): string[] {
    return this.resolveClaim(this.initFromIncomingMessage(incomingMessage), this.rolesClaim) || [];
  }

  getTenantFromIncomingMessage(incomingMessage: IncomingMessage): string | undefined {
    return this.resolveClaim(this.initFromIncomingMessage(incomingMessage), this.tenantClaim) || undefined;
  }

  /** Reads a claim by name, supporting dotted paths for nested claims. */
  private resolveClaim(payload: any, path: string): any {
    if (!path) {
      return undefined;
    }
    return path.split('.').reduce((cur: any, key: string) => (cur == null ? undefined : cur[key]), payload);
  }

  private initFromRequest(request: Request): any {
    if (!request['jwt']) {
      const authHeader = this.getAuthHeaderFromRequest(request);
      const token = this.getJwtFromAuthHeader(authHeader);
      request['jwt'] = this.decodeJwt(token) || {};
    }
    return request['jwt'];
  }

  private initFromIncomingMessage(incomingMessage: IncomingMessage): any {
    if (!incomingMessage['jwt']) {
      const authHeader = this.getAuthHeaderIncomingMessage(incomingMessage);
      const token = this.getJwtFromAuthHeader(authHeader);
      incomingMessage['jwt'] = this.decodeJwt(token) || {};
    }
    return incomingMessage['jwt'];
  }

  private getAuthHeaderIncomingMessage(incomingMessage: IncomingMessage): string {
    return incomingMessage.headers['authorization'] as string;
  }

  private getAuthHeaderFromRequest(request: Request): string {
    return request.header('authorization');
  }

  private getJwtFromAuthHeader(authHeader: string): string {
    return authHeader ? authHeader.split(' ')[1] : null; // JWT sits after the 'Bearer' prefix
  }

  private decodeJwt(token: string): any {
    if (this.jwksUri) {
      // Reached without prepare() (not through the guard): no fetch possible
      // here, so only the keys already cached can verify the token.
      try {
        return this.verifyWithKeys(token, decode(token, { complete: true }), this.jwks);
      } catch (err) {
        return this.verificationFailed(err);
      }
    }
    if (!this.base64Key || !this.algorithm) {
      return decode(token);
    }
    try {
      return verify(token, this.base64Key, this.verifyOptions(this.algorithms));
    } catch (err) {
      return this.verificationFailed(err);
    }
  }

  /**
   * `jsonwebtoken` skips an unset `issuer` / `audience`. The cast is for the
   * arrays: its types want non-empty tuples, a plain `string[]` is friendlier.
   */
  private verifyOptions(algorithms: JwtAlgorithm[]): VerifyOptions {
    return { algorithms, issuer: this.issuer, audience: this.audience } as VerifyOptions;
  }

  /** Verifies against the cached JWKS; on failure, re-fetches it once and retries — the IdP may have rotated its keys. */
  private async verifyWithJwks(token: string): Promise<any> {
    const jwt = decode(token, { complete: true });
    if (!jwt) {
      return this.verificationFailed(new JsonWebTokenError('jwt malformed'));
    }
    const cached = await this.getJwks(false);
    try {
      return this.verifyWithKeys(token, jwt, cached);
    } catch (err) {
      const refreshed = signatureMatched(err) ? cached : await this.getJwks(true);
      if (refreshed === cached) {
        return this.verificationFailed(err);
      }
      try {
        return this.verifyWithKeys(token, jwt, refreshed);
      } catch (retryErr) {
        return this.verificationFailed(retryErr);
      }
    }
  }

  /**
   * Verifies with the key matching `kid` or, when the token has none, with each
   * key in turn. The algorithm is the key's: the token's `alg` only has to agree
   * with it. Taking it from the token is what `alg: none` and RS/HS confusion
   * attacks rely on.
   */
  private verifyWithKeys(token: string, jwt: Jwt | null, keys: JwksKey[]): any {
    if (!jwt) {
      throw new JsonWebTokenError('jwt malformed');
    }
    const { kid, alg } = jwt.header;
    const candidates = kid ? keys.filter((jwk) => jwk.kid === kid) : keys;
    let failure: unknown = new JsonWebTokenError('no JWKS key matches the token');
    for (const { key, algorithms } of candidates) {
      try {
        if (!algorithms.includes(alg as JwtAlgorithm)) {
          throw new JsonWebTokenError('invalid algorithm');
        }
        return alg === 'EdDSA' ? this.verifyEdDsa(token, jwt, key) : verify(token, key, this.verifyOptions(algorithms));
      } catch (err) {
        if (signatureMatched(err)) {
          throw err;
        }
        failure = err;
      }
    }
    throw failure;
  }

  /** `jsonwebtoken` has no EdDSA: `crypto` checks the signature, then the claims are checked the way `jsonwebtoken` does. */
  private verifyEdDsa(token: string, jwt: Jwt, key: KeyObject): JwtPayload {
    const signed = token.slice(0, token.lastIndexOf('.'));
    if (!verifySignature(null, Buffer.from(signed), key, Buffer.from(jwt.signature, 'base64url'))) {
      throw new JsonWebTokenError('invalid signature');
    }
    const payload = jwt.payload;
    if (!payload || typeof payload !== 'object') {
      throw new JsonWebTokenError('jwt malformed');
    }
    const now = Math.floor(Date.now() / 1000);
    if (payload.nbf !== undefined) {
      if (typeof payload.nbf !== 'number') {
        throw new JsonWebTokenError('invalid nbf value');
      }
      if (payload.nbf > now) {
        throw new NotBeforeError('jwt not active', new Date(payload.nbf * 1000));
      }
    }
    if (payload.exp !== undefined) {
      if (typeof payload.exp !== 'number') {
        throw new JsonWebTokenError('invalid exp value');
      }
      if (now >= payload.exp) {
        throw new TokenExpiredError('jwt expired', new Date(payload.exp * 1000));
      }
    }
    if (this.audience) {
      const accepted = [this.audience].flat();
      if (![payload.aud].flat().some((aud) => accepted.some((candidate) => (candidate instanceof RegExp ? candidate.test(aud) : candidate === aud)))) {
        throw new JsonWebTokenError(`jwt audience invalid. expected: ${accepted.join(' or ')}`);
      }
    }
    if (this.issuer && ![this.issuer].flat().includes(payload.iss)) {
      throw new JsonWebTokenError(`jwt issuer invalid. expected: ${this.issuer}`);
    }
    return payload;
  }

  /**
   * Cached keys, re-fetched once `jwksCacheMaxAge` has elapsed or when `force`d —
   * but never twice within `jwksCooldown`. A failed fetch keeps the last known
   * keys, so an IdP outage doesn't turn every caller anonymous.
   */
  private async getJwks(force: boolean): Promise<JwksKey[]> {
    const now = Date.now();
    const fresh = this.jwksFetchedAt > 0 && now - this.jwksFetchedAt < this.jwksCacheMaxAge;
    if (fresh && !force) {
      return this.jwks;
    }
    if (!this.jwksFetch) {
      if (now - this.jwksAttemptedAt < this.jwksCooldown) {
        return this.jwks;
      }
      this.jwksAttemptedAt = now;
      this.jwksFetch = this.fetchJwks()
        .then((keys) => {
          this.jwks = keys;
          this.jwksFetchedAt = Date.now();
          return keys;
        })
        .catch((err) => {
          const reason = err instanceof Error ? err.message : 'unknown error';
          console.warn(`[nestjs-granted] JWKS fetch failed (${this.jwksUri}): ${reason}`);
          return this.jwks;
        })
        .finally(() => {
          this.jwksFetch = undefined;
        });
    }
    return this.jwksFetch;
  }

  private async fetchJwks(): Promise<JwksKey[]> {
    const response = await fetch(this.jwksUri, { signal: AbortSignal.timeout(this.jwksTimeout) });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const jwks = await response.json();
    if (!Array.isArray(jwks?.keys)) {
      throw new Error('no "keys" array in the response');
    }
    // Encryption keys, and entries that aren't public keys (e.g. symmetric
    // `oct` ones, which would open the door to HS256 forgeries), are skipped.
    return jwks.keys
      .filter((jwk: any) => jwk.use !== 'enc')
      .flatMap((jwk: any) => {
        try {
          const key = createPublicKey({ key: jwk, format: 'jwk' });
          return [{ kid: jwk.kid, key, algorithms: this.jwksKeyAlgorithms(key, jwk.alg) }];
        } catch {
          return [];
        }
      });
  }

  /**
   * The `alg` the JWK declares, provided its key type can verify it. Without
   * `alg`: the one the key type implies (RSA → RS256, EC → its curve's ES*,
   * Ed25519 → EdDSA) or, when `algorithm` is configured, whichever of those
   * the key type can verify — an RSA key may sign PS256 as well.
   * Empty when nothing fits or the allowlist excludes it: the key verifies no token.
   */
  private jwksKeyAlgorithms(key: KeyObject, declared: unknown): JwtAlgorithm[] {
    const possible = keyAlgorithms(key);
    if (!this.algorithms) {
      return declared === undefined ? possible.slice(0, 1) : possible.filter((alg) => alg === declared);
    }
    return possible.filter((alg) => this.algorithms.includes(alg) && (declared === undefined || alg === declared));
  }

  private verificationFailed(err: unknown): object {
    // Never log the token or the key material. A failed verification
    // simply yields an anonymous request downstream.
    const reason = err instanceof Error ? err.message : 'unknown error';
    console.warn(`[nestjs-granted] JWT verification failed (${this.algorithms?.join(', ') ?? 'JWKS'}): ${reason}`);
    return {};
  }
}
