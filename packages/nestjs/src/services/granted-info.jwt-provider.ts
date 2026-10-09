import { createPublicKey, KeyObject, verify as verifySignature } from 'crypto';
import { Request } from 'express';
import * as fs from 'fs';
import { IncomingMessage } from 'http';
import { Algorithm, decode, JsonWebTokenError, Jwt, JwtPayload, NotBeforeError, TokenExpiredError, verify, VerifyOptions } from 'jsonwebtoken';
import { IGrantedPrincipalProvider } from './igranted-info.provider';

/** `jsonwebtoken`'s algorithms, plus EdDSA — only with `jwksUri`, where Node's `crypto` verifies it. */
export type JwtAlgorithm = Algorithm | 'EdDSA';

/** Accepted `aud` value(s), as strings or patterns. */
export type JwtAudience = string | RegExp | (string | RegExp)[];

/** A `discoveryUris` entry with options: a bearer token to fetch with, its own audience, a bypass. */
export interface OpenIdProvider {
  /** The discovery document URL, or the URL it lives under — as a plain `discoveryUris` entry. */
  uri: string;
  /**
   * File holding the token sent as `Authorization: Bearer` to this provider's
   * discovery document and to the `jwks_uri` it announces — never to another
   * provider. Read at every fetch, so a rotated token is picked up. The
   * Kubernetes API server answers 403 without one.
   */
  bearerTokenFile?: string;
  /** Accepted `aud` of this provider's tokens, in place of the global `audience`. */
  audience?: JwtAudience;
  /**
   * `sub` patterns (`*` matches anything) whose tokens, from this provider,
   * pass every `@GrantedTo` — e.g. `'system:serviceaccount:canopy:*'` for the
   * services of a namespace. Only this provider's tokens can match.
   */
  bypass?: string[];
}

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
  /**
   * OpenID Providers to trust, each given by its discovery document URL, e.g.
   * `http://idp-a:8080/.well-known/openid-configuration` — or by
   * the URL it lives under, `/.well-known/openid-configuration` being appended.
   * The document gives the provider's `issuer` and `jwks_uri`: it is fetched on
   * first use and cached like the keys. A token is verified only with the keys
   * of the provider whose `issuer` is its `iss`; any other `iss` is rejected, and
   * no URL is ever taken from the token. The issuer is the document's, whatever
   * the URL it was fetched from — an IdP reached through an in-cluster address
   * keeps its public issuer. Can be combined with `jwksUri`, which then needs
   * `issuer` so tokens can be routed to it; not with `base64Key` / `pemFile`.
   *
   * An entry can also be an {@link OpenIdProvider}: a provider that wants a
   * bearer token (e.g. the Kubernetes API server), has its own audience, or
   * whose tokens bypass the `@GrantedTo` checks.
   */
  discoveryUris?: (string | OpenIdProvider)[];
  /**
   * Age (ms) after which cached JWKS keys — and OpenID discovery documents — are
   * re-fetched. Defaults to 10 minutes.
   */
  jwksCacheMaxAge?: number;
  /**
   * Minimum delay (ms) between two fetches of a JWK Set or discovery document, so
   * tokens with forged `kid`s or issuers can't make the provider hammer the IdP.
   * Defaults to 30 seconds.
   */
  jwksCooldown?: number;
  /** Timeout (ms) of a JWK Set or discovery document fetch. Defaults to 5 seconds. */
  jwksTimeout?: number;
  /**
   * With a PEM key (`base64Key` / `pemFile`): the signature algorithm. Defaults to `'ES256'`.
   *
   * With `jwksUri` / `discoveryUris`: optional. Each key verifies with the algorithm the JWK Set
   * gives it — never the one the token announces — so the IdP can change
   * algorithm without any change here. When set, it is an allowlist: a token
   * signed with another algorithm is rejected. Only asymmetric algorithms
   * (RS*, PS*, ES*, EdDSA) are accepted with a JWKS.
   */
  algorithm?: JwtAlgorithm | JwtAlgorithm[];
  /**
   * Accepted `iss` value(s). Not checked when unset — e.g. behind a gateway
   * that already validated the token. Needs a key (`base64Key`, `pemFile` or `jwksUri`).
   * With `discoveryUris`, it applies to `jwksUri` only, and is required with it:
   * the OpenID Providers' issuers come from their discovery documents.
   */
  issuer?: string | string[];
  /**
   * Accepted `aud` value(s), as strings or patterns. Not checked when unset.
   * Needs a key (`base64Key`, `pemFile`, `jwksUri` or `discoveryUris`).
   */
  audience?: JwtAudience;
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

const OPENID_CONFIGURATION = '/.well-known/openid-configuration';

/** The discovery document URL: as given, or the IdP URL with `/.well-known/openid-configuration` appended. */
function openidConfigurationUrl(uri: string): string {
  return uri.endsWith(OPENID_CONFIGURATION) ? uri : `${uri.replace(/\/+$/, '')}${OPENID_CONFIGURATION}`;
}

/** `*` matches any run of characters; everything else is literal. */
function subjectPattern(pattern: string): RegExp {
  return new RegExp(
    `^${pattern
      .split('*')
      .map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
      .join('.*')}$`,
  );
}

async function fetchJson(url: string, timeout: number, bearerTokenFile?: string): Promise<any> {
  // Read at every fetch: a projected token is rotated on disk by the kubelet.
  const headers = bearerTokenFile ? { authorization: `Bearer ${fs.readFileSync(bearerTokenFile, 'utf8').trim()}` } : undefined;
  const response = await fetch(url, { headers, signal: AbortSignal.timeout(timeout) });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  return response.json();
}

/** Cache age, minimum delay between two fetches, and timeout of a fetch. */
interface FetchPolicy {
  maxAge: number;
  cooldown: number;
  timeout: number;
}

/**
 * A value fetched over HTTP: cached, re-fetched once older than `maxAge` or when
 * `force`d — but never twice within `cooldown`. A failed fetch keeps the last
 * known value, so an IdP outage doesn't turn every caller anonymous.
 */
class Fetched<T> {
  value: T;
  /** Last successful fetch — drives `maxAge`. */
  private fetchedAt = 0;
  /** Last fetch attempt, successful or not — drives `cooldown`. */
  private attemptedAt = 0;
  /** Fetch in progress, shared by concurrent requests. */
  private pending: Promise<T> | undefined;

  constructor(
    initial: T,
    private readonly policy: FetchPolicy,
    private readonly load: () => Promise<T>,
    private readonly failure: () => string,
  ) {
    this.value = initial;
  }

  async get(force: boolean): Promise<T> {
    const now = Date.now();
    const fresh = this.fetchedAt > 0 && now - this.fetchedAt < this.policy.maxAge;
    if (fresh && !force) {
      return this.value;
    }
    if (!this.pending) {
      if (now - this.attemptedAt < this.policy.cooldown) {
        return this.value;
      }
      this.attemptedAt = now;
      this.pending = this.load()
        .then((value) => {
          this.value = value;
          this.fetchedAt = Date.now();
          return value;
        })
        .catch((err) => {
          const reason = err instanceof Error ? err.message : 'unknown error';
          console.warn(`[nestjs-granted] ${this.failure()}: ${reason}`);
          return this.value;
        })
        .finally(() => {
          this.pending = undefined;
        });
    }
    return this.pending;
  }

  /** The URL changed: the next get() fetches, cooldown or not. The last known value stays until then. */
  expire(): void {
    this.fetchedAt = 0;
    this.attemptedAt = 0;
  }
}

/** The issuer and audience a verified token must carry. Unset: not checked. */
interface ExpectedClaims {
  issuer?: string | string[];
  audience?: JwtAudience;
}

/** A JWK Set, the issuer its keys vouch for, and the audience and bypass that apply to their tokens. */
class JwksSource implements ExpectedClaims {
  readonly keys: Fetched<JwksKey[]>;
  /** `sub` patterns whose tokens pass every `@GrantedTo`. */
  bypass: RegExp[] = [];

  /** An undefined `issuer` routes every token here: a lone `jwksUri` configured without `issuer`. */
  constructor(
    public jwksUri: string | undefined,
    public issuer: string | string[] | undefined,
    readonly audience: JwtAudience | undefined,
    policy: FetchPolicy,
    parseKeys: (jwks: any) => JwksKey[],
    bearerTokenFile?: string,
  ) {
    this.keys = new Fetched<JwksKey[]>(
      [],
      policy,
      async () => parseKeys(await fetchJson(this.jwksUri, policy.timeout, bearerTokenFile)),
      () => `JWKS fetch failed (${this.jwksUri})`,
    );
  }

  /** Brings `issuer` and `jwksUri` up to date — nothing to do when they are configured. */
  async discover(): Promise<void> {}

  accepts(iss: unknown): boolean {
    return this.issuer === undefined || [this.issuer].flat().includes(iss as string);
  }
}

/** A JWKS source whose issuer and JWK Set URL come from an OpenID Provider's discovery document. */
class DiscoverySource extends JwksSource {
  private readonly configuration: Fetched<{ issuer: string; jwksUri: string } | undefined>;

  constructor({ uri, bearerTokenFile, audience, bypass }: OpenIdProvider, defaultAudience: JwtAudience | undefined, policy: FetchPolicy, parseKeys: (jwks: any) => JwksKey[]) {
    super(undefined, undefined, audience ?? defaultAudience, policy, parseKeys, bearerTokenFile);
    this.bypass = (bypass ?? []).map(subjectPattern);
    const discoveryUri = openidConfigurationUrl(uri);
    this.configuration = new Fetched(
      undefined,
      policy,
      async () => {
        const { issuer, jwks_uri: jwksUri } = (await fetchJson(discoveryUri, policy.timeout, bearerTokenFile)) ?? {};
        if (typeof issuer !== 'string' || !issuer || typeof jwksUri !== 'string' || !jwksUri) {
          throw new Error('no "issuer" or "jwks_uri" in the response');
        }
        return { issuer, jwksUri };
      },
      () => `OpenID configuration fetch failed (${discoveryUri})`,
    );
  }

  override async discover(): Promise<void> {
    const configuration = await this.configuration.get(false);
    if (!configuration) {
      return;
    }
    if (configuration.jwksUri !== this.jwksUri) {
      this.jwksUri = configuration.jwksUri;
      this.keys.expire();
    }
    this.issuer = configuration.issuer;
  }

  /** No token is routed here until the document has been fetched. */
  override accepts(iss: unknown): boolean {
    return this.issuer !== undefined && super.accepts(iss);
  }
}

/**
 * Resolves the identity from a verified JWT carried in the
 * `Authorization: Bearer <token>` header.
 *
 * Use the constructor for a fully custom claim mapping, or one of the static
 * presets ({@link GrantedJwtPrincipalProvider.rfc9068}, `.azureAd`, `.keycloak`,
 * `.okta`) which pre-fill the mapping so you only pass key material: a PEM key
 * (`base64Key` / `pemFile`), the IdP's JWK Set (`jwksUri`), or the discovery
 * documents of the OpenID Providers to trust (`discoveryUris`).
 *
 * A token that is missing, malformed, or fails verification yields an
 * anonymous request (empty claims) — it is then up to the `@GrantedTo` specs
 * to reject it. A token whose `sub` matches its provider's `bypass` passes them all.
 */
export class GrantedJwtPrincipalProvider implements IGrantedPrincipalProvider {
  base64Key: string;
  jwksUri: string;
  discoveryUris: (string | OpenIdProvider)[];
  jwksCacheMaxAge: number;
  jwksCooldown: number;
  jwksTimeout: number;
  algorithm: JwtAlgorithm | JwtAlgorithm[];
  issuer: string | string[];
  audience: JwtAudience;
  usernameClaim: string;
  rolesClaim: string;
  tenantClaim: string;

  /** `algorithm` as a list. Undefined with a JWKS and no allowlist: each key's own algorithm is accepted. */
  private algorithms: JwtAlgorithm[] | undefined;
  /** The JWK Sets to verify with: `jwksUri`'s, then one per `discoveryUris` entry. Empty with a PEM key. */
  private readonly sources: JwksSource[];
  /** Verified payloads whose `sub` matches their provider's `bypass` — set by the provider only, never by a claim. */
  private readonly bypassed = new WeakSet<object>();

  constructor(conf: GrantedJwtPrincipalProviderConfig) {
    const discoveryUris = conf.discoveryUris ?? [];
    const providers: OpenIdProvider[] = discoveryUris.map((entry) => (typeof entry === 'string' ? { uri: entry } : entry));
    if (providers.some(({ uri }) => typeof uri !== 'string' || !uri)) {
      throw new Error('[nestjs-granted] each discoveryUris entry needs a URL');
    }
    if (providers.some(({ bypass }) => bypass && (!Array.isArray(bypass) || bypass.some((pattern) => typeof pattern !== 'string' || !pattern)))) {
      throw new Error("[nestjs-granted] bypass is a list of sub patterns, e.g. ['system:serviceaccount:canopy:*']");
    }
    const jwks = Boolean(conf.jwksUri || discoveryUris.length);
    if (conf.jwksUri && (conf.base64Key || conf.pemFile)) {
      throw new Error('[nestjs-granted] jwksUri cannot be combined with base64Key or pemFile');
    }
    if (discoveryUris.length && (conf.base64Key || conf.pemFile)) {
      throw new Error('[nestjs-granted] discoveryUris cannot be combined with base64Key or pemFile');
    }
    if (discoveryUris.length && conf.issuer && !conf.jwksUri) {
      throw new Error('[nestjs-granted] issuer applies to jwksUri only: discoveryUris take their issuer from the discovery document');
    }
    if (discoveryUris.length && conf.jwksUri && !conf.issuer) {
      // Without it, jwksUri's keys would be tried on any token — those of the OpenID Providers included.
      throw new Error('[nestjs-granted] jwksUri needs an issuer when combined with discoveryUris, to route its tokens');
    }
    if ((conf.issuer || conf.audience) && !(conf.base64Key || conf.pemFile || jwks)) {
      // An unverified token's claims can say anything: checking them would only look secure.
      throw new Error('[nestjs-granted] issuer and audience need a key to verify the token: base64Key, pemFile, jwksUri or discoveryUris');
    }
    this.base64Key = conf.base64Key;
    this.jwksUri = conf.jwksUri;
    this.discoveryUris = discoveryUris;
    this.jwksCacheMaxAge = conf.jwksCacheMaxAge ?? 600_000;
    this.jwksCooldown = conf.jwksCooldown ?? 30_000;
    this.jwksTimeout = conf.jwksTimeout ?? 5_000;
    // The default is for a PEM key only: with a JWKS, each key brings its own algorithm.
    this.algorithm = conf.algorithm || (jwks ? undefined : 'ES256');
    this.algorithms = this.algorithm ? [this.algorithm].flat() : undefined;
    if (this.algorithms?.length === 0) {
      throw new Error('[nestjs-granted] algorithm is an empty list: no token could be verified');
    }
    if (jwks) {
      // A JWK Set publishes public keys: `none` and the shared-secret HS* have no place here.
      const refused = (this.algorithms || []).filter((alg) => !JWKS_ALGORITHMS.includes(alg));
      if (refused.length) {
        throw new Error(`[nestjs-granted] algorithm ${refused.join(', ')} cannot be used with jwksUri or discoveryUris, which accept ${JWKS_ALGORITHMS.join(', ')}`);
      }
    } else if (this.algorithms.includes('EdDSA')) {
      throw new Error('[nestjs-granted] EdDSA is only supported with jwksUri or discoveryUris');
    }
    this.issuer = conf.issuer;
    this.audience = conf.audience;
    this.usernameClaim = conf.usernameClaim || 'sub';
    this.rolesClaim = conf.rolesClaim || 'roles';
    this.tenantClaim = conf.tenantClaim || 'tenant';
    if (conf.pemFile) {
      this.base64Key = fs.readFileSync(conf.pemFile, 'utf8');
    }
    const policy: FetchPolicy = { maxAge: this.jwksCacheMaxAge, cooldown: this.jwksCooldown, timeout: this.jwksTimeout };
    const parseKeys = (jwks: any) => this.parseJwks(jwks);
    this.sources = [...(conf.jwksUri ? [new JwksSource(conf.jwksUri, conf.issuer, conf.audience, policy, parseKeys)] : []), ...providers.map((provider) => new DiscoverySource(provider, conf.audience, policy, parseKeys))];
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
    if (!this.sources.length || request['jwt']) {
      return;
    }
    const token = this.getJwtFromAuthHeader(this.getAuthHeaderIncomingMessage(request));
    request['jwt'] = token ? await this.verifyWithJwks(token) : {};
  }

  getUsernameFromRequest(request: Request): string {
    return this.username(this.initFromRequest(request));
  }

  getRolesFromRequest(request: Request): string[] {
    return this.resolveClaim(this.initFromRequest(request), this.rolesClaim) || [];
  }

  getTenantFromRequest(request: Request): string | undefined {
    return this.resolveClaim(this.initFromRequest(request), this.tenantClaim) || undefined;
  }

  getUsernameFromIncomingMessage(incomingMessage: IncomingMessage): string {
    return this.username(this.initFromIncomingMessage(incomingMessage));
  }

  isBypassed(request: Request): boolean {
    return this.bypassed.has(this.initFromRequest(request));
  }

  /** A bypassing token may lack the username claim (a service account has no `preferred_username`): its `sub` names it. */
  private username(payload: any): string {
    return this.resolveClaim(payload, this.usernameClaim) || (this.bypassed.has(payload) ? payload.sub : undefined) || 'anonymous';
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
    if (this.sources.length) {
      // Reached without prepare() (not through the guard): no fetch possible
      // here, so only the keys already cached can verify the token.
      try {
        return this.verifyWithCachedKeys(token, decode(token, { complete: true }));
      } catch (err) {
        return this.verificationFailed(err);
      }
    }
    if (!this.base64Key || !this.algorithm) {
      return decode(token);
    }
    try {
      return verify(token, this.base64Key, this.verifyOptions(this.algorithms, this));
    } catch (err) {
      return this.verificationFailed(err);
    }
  }

  /**
   * `jsonwebtoken` skips an unset `issuer` / `audience`. The cast is for the
   * arrays: its types want non-empty tuples, a plain `string[]` is friendlier.
   */
  private verifyOptions(algorithms: JwtAlgorithm[], { issuer, audience }: ExpectedClaims): VerifyOptions {
    return { algorithms, issuer, audience } as VerifyOptions;
  }

  /** The payload a source verified, remembered as bypassing when its `sub` matches the source's `bypass`. */
  private verifiedBy(source: JwksSource, payload: any): any {
    if (typeof payload?.sub === 'string' && source.bypass.some((pattern) => pattern.test(payload.sub))) {
      this.bypassed.add(payload);
    }
    return payload;
  }

  /** The sources whose issuer is the token's `iss`: a key never verifies a token claiming another issuer. */
  private sourcesFor(jwt: Jwt): JwksSource[] {
    const iss = typeof jwt.payload === 'object' ? jwt.payload.iss : undefined;
    return this.sources.filter((source) => source.accepts(iss));
  }

  private unknownIssuer(): JsonWebTokenError {
    const known = this.sources.flatMap((source) => [source.issuer ?? []].flat());
    return new JsonWebTokenError(known.length ? `jwt issuer invalid. expected: ${known.join(' or ')}` : 'jwt issuer invalid: no OpenID configuration fetched yet');
  }

  /**
   * Routes the token to the JWK Set of its issuer and verifies it with the cached
   * keys; on failure, re-fetches the set once and retries — the IdP may have
   * rotated its keys.
   */
  private async verifyWithJwks(token: string): Promise<any> {
    const jwt = decode(token, { complete: true });
    if (!jwt) {
      return this.verificationFailed(new JsonWebTokenError('jwt malformed'));
    }
    // Only the documents that may announce the token's issuer are awaited: a hung IdP doesn't slow down the others.
    const candidates = this.sourcesFor(jwt);
    await Promise.all((candidates.length ? candidates : this.sources).map((source) => source.discover()));
    let failure: unknown = this.unknownIssuer();
    for (const source of this.sourcesFor(jwt)) {
      const cached = await source.keys.get(false);
      try {
        return this.verifiedBy(source, this.verifyWithKeys(token, jwt, cached, source));
      } catch (err) {
        failure = err;
        const refreshed = signatureMatched(err) ? cached : await source.keys.get(true);
        if (refreshed !== cached) {
          try {
            return this.verifiedBy(source, this.verifyWithKeys(token, jwt, refreshed, source));
          } catch (retryErr) {
            failure = retryErr;
          }
        }
      }
    }
    return this.verificationFailed(failure);
  }

  private verifyWithCachedKeys(token: string, jwt: Jwt | null): any {
    if (!jwt) {
      throw new JsonWebTokenError('jwt malformed');
    }
    let failure: unknown = this.unknownIssuer();
    for (const source of this.sourcesFor(jwt)) {
      try {
        return this.verifiedBy(source, this.verifyWithKeys(token, jwt, source.keys.value, source));
      } catch (err) {
        failure = err;
      }
    }
    throw failure;
  }

  /**
   * Verifies with the key matching `kid` or, when the token has none, with each
   * key in turn. The algorithm is the key's: the token's `alg` only has to agree
   * with it. Taking it from the token is what `alg: none` and RS/HS confusion
   * attacks rely on.
   */
  private verifyWithKeys(token: string, jwt: Jwt, keys: JwksKey[], expected: ExpectedClaims): any {
    const { kid, alg } = jwt.header;
    const candidates = kid ? keys.filter((jwk) => jwk.kid === kid) : keys;
    let failure: unknown = new JsonWebTokenError('no JWKS key matches the token');
    for (const { key, algorithms } of candidates) {
      try {
        if (!algorithms.includes(alg as JwtAlgorithm)) {
          throw new JsonWebTokenError('invalid algorithm');
        }
        return alg === 'EdDSA' ? this.verifyEdDsa(token, jwt, key, expected) : verify(token, key, this.verifyOptions(algorithms, expected));
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
  private verifyEdDsa(token: string, jwt: Jwt, key: KeyObject, { issuer, audience }: ExpectedClaims): JwtPayload {
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
    if (audience) {
      const accepted = [audience].flat();
      if (![payload.aud].flat().some((aud) => accepted.some((candidate) => (candidate instanceof RegExp ? candidate.test(aud) : candidate === aud)))) {
        throw new JsonWebTokenError(`jwt audience invalid. expected: ${accepted.join(' or ')}`);
      }
    }
    if (issuer && ![issuer].flat().includes(payload.iss)) {
      throw new JsonWebTokenError(`jwt issuer invalid. expected: ${issuer}`);
    }
    return payload;
  }

  private parseJwks(jwks: any): JwksKey[] {
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
