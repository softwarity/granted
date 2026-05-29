import { Request } from 'express';
import * as fs from 'fs';
import { IncomingMessage } from 'http';
import { Algorithm, decode, verify } from 'jsonwebtoken';
import { IGrantedPrincipalProvider } from './igranted-info.provider';

/** Key material + signature algorithm — the only thing a preset can't infer. */
export interface JwtKeyConfig {
  /** Public key (PEM) used to verify the token signature. */
  base64Key?: string;
  /** Path to a PEM public key file — read once at construction. */
  pemFile?: string;
  /** Signature algorithm. Defaults to `'RS256'`. */
  algorithm?: Algorithm;
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

/**
 * Resolves the identity from a verified JWT carried in the
 * `Authorization: Bearer <token>` header.
 *
 * Use the constructor for a fully custom claim mapping, or one of the static
 * presets ({@link GrantedJwtPrincipalProvider.rfc9068}, `.azureAd`, `.keycloak`,
 * `.okta`) which pre-fill the mapping so you only pass key material.
 *
 * A token that is missing, malformed, or fails verification yields an
 * anonymous request (empty claims) — it is then up to the `@GrantedTo` specs
 * to reject it.
 */
export class GrantedJwtPrincipalProvider implements IGrantedPrincipalProvider {
  base64Key: string;
  algorithm: Algorithm;
  usernameClaim: string;
  rolesClaim: string;
  tenantClaim: string;

  constructor(conf: GrantedJwtPrincipalProviderConfig) {
    this.base64Key = conf.base64Key;
    this.algorithm = conf.algorithm || 'RS256';
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
    if (!this.base64Key || !this.algorithm) {
      return decode(token);
    }
    try {
      return verify(token, this.base64Key, { algorithms: [this.algorithm] });
    } catch (err) {
      // Never log the token or the key material. A failed verification
      // simply yields an anonymous request downstream.
      const reason = err instanceof Error ? err.message : 'unknown error';
      console.warn(`[nestjs-granted] JWT verification failed (${this.algorithm}): ${reason}`);
      return {};
    }
  }
}
