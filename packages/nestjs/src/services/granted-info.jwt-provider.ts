import { createPublicKey, KeyObject } from 'crypto';
import { Request } from 'express';
import * as fs from 'fs';
import { IncomingMessage } from 'http';
import { Algorithm, decode, JsonWebTokenError, NotBeforeError, TokenExpiredError, verify, VerifyOptions } from 'jsonwebtoken';
import { IGrantedPrincipalProvider } from './igranted-info.provider';

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
   * rotation needs no restart. Can't be combined with `base64Key` / `pemFile`.
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
  /** Signature algorithm. Defaults to `'RS256'`. */
  algorithm?: Algorithm;
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
  algorithm: Algorithm;
  issuer: string | string[];
  audience: string | RegExp | (string | RegExp)[];
  usernameClaim: string;
  rolesClaim: string;
  tenantClaim: string;

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
    this.algorithm = conf.algorithm || 'RS256';
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
        return this.verifyWithKeys(token, decode(token, { complete: true })?.header.kid, this.jwks);
      } catch (err) {
        return this.verificationFailed(err);
      }
    }
    if (!this.base64Key || !this.algorithm) {
      return decode(token);
    }
    try {
      return verify(token, this.base64Key, this.verifyOptions());
    } catch (err) {
      return this.verificationFailed(err);
    }
  }

  /**
   * `jsonwebtoken` skips an unset `issuer` / `audience`. The cast is for the
   * arrays: its types want non-empty tuples, a plain `string[]` is friendlier.
   */
  private verifyOptions(): VerifyOptions {
    return { algorithms: [this.algorithm], issuer: this.issuer, audience: this.audience } as VerifyOptions;
  }

  /** Verifies against the cached JWKS; on failure, re-fetches it once and retries — the IdP may have rotated its keys. */
  private async verifyWithJwks(token: string): Promise<any> {
    const header = decode(token, { complete: true })?.header;
    if (!header) {
      return this.verificationFailed(new JsonWebTokenError('jwt malformed'));
    }
    const cached = await this.getJwks(false);
    try {
      return this.verifyWithKeys(token, header.kid, cached);
    } catch (err) {
      const refreshed = signatureMatched(err) ? cached : await this.getJwks(true);
      if (refreshed === cached) {
        return this.verificationFailed(err);
      }
      try {
        return this.verifyWithKeys(token, header.kid, refreshed);
      } catch (retryErr) {
        return this.verificationFailed(retryErr);
      }
    }
  }

  /** Verifies with the key matching `kid` or, when the token has none, with each key in turn. */
  private verifyWithKeys(token: string, kid: string | undefined, keys: JwksKey[]): any {
    const candidates = kid ? keys.filter((jwk) => jwk.kid === kid) : keys;
    let failure: unknown = new JsonWebTokenError('no JWKS key matches the token');
    for (const { key } of candidates) {
      try {
        return verify(token, key, this.verifyOptions());
      } catch (err) {
        if (signatureMatched(err)) {
          throw err;
        }
        failure = err;
      }
    }
    throw failure;
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
          return [{ kid: jwk.kid, key: createPublicKey({ key: jwk, format: 'jwk' }) }];
        } catch {
          return [];
        }
      });
  }

  private verificationFailed(err: unknown): object {
    // Never log the token or the key material. A failed verification
    // simply yields an anonymous request downstream.
    const reason = err instanceof Error ? err.message : 'unknown error';
    console.warn(`[nestjs-granted] JWT verification failed (${this.algorithm}): ${reason}`);
    return {};
  }
}
