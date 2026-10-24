package io.softwarity.granted;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import io.quarkus.runtime.annotations.ConfigPhase;
import io.quarkus.runtime.annotations.ConfigRoot;
import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;

/**
 * Where the caller comes from, and how its roles are shaped. The same defaults as
 * {@code @softwarity/nestjs-granted}: a NestJS and a Quarkus service behind the same gateway
 * read the same caller.
 */
@ConfigMapping(prefix = "granted")
@ConfigRoot(phase = ConfigPhase.RUN_TIME)
public interface GrantedConfig {

    /** Where the caller comes from. */
    enum Source {
        /** HTTP headers a gateway forwards, after it authenticated the caller. */
        HEADERS,
        /** A JWT that quarkus-oidc or quarkus-smallrye-jwt verified. Headers are then never read. */
        JWT
    }

    /** {@code headers} (default) or {@code jwt}. */
    @WithDefault("headers")
    Source source();

    /** The headers the gateway sets, with {@code granted.source=headers}. */
    Headers headers();

    /** The claims of the verified token, with {@code granted.source=jwt}. */
    Jwt jwt();

    /**
     * A role mapped to the roles it implies, expanded transitively:
     * {@code granted.role-hierarchy.ADMIN=MANAGER} and {@code granted.role-hierarchy.MANAGER=USER}
     * make an ADMIN a MANAGER and a USER too.
     */
    Map<String, List<String>> roleHierarchy();

    /**
     * Roles this service knows. When set, any other role is dropped - after the hierarchy is
     * expanded - so a token shared with other services doesn't bring theirs in.
     */
    Optional<List<String>> knownRoles();

    /** What a refused request (403) is told. */
    AccessDenied accessDenied();

    /** The headers the gateway sets. Header names are case-insensitive. */
    interface Headers {

        /** The caller's username. A request without it is anonymous. */
        @WithDefault("username")
        String username();

        /** A JSON array ({@code ["A","B"]}) or a comma-separated list ({@code A, B}): both are read. */
        @WithDefault("roles")
        String roles();

        /** The caller's tenant. */
        @WithDefault("tenant")
        String tenant();
    }

    /**
     * The JWT: how it is verified, and which of its claims carry the caller - nestjs-granted's
     * {@code GrantedJwtPrincipalProvider} options. With key material ({@code public-key},
     * {@code public-key-file}, {@code jwks-uri} or {@code discovery-uris}), granted verifies the
     * {@code Authorization: Bearer} token itself; without, it reads the token quarkus-oidc or
     * quarkus-smallrye-jwt verified. A missing or invalid token gives an anonymous caller.
     */
    interface Jwt {

        /** Claim mapping of a well-known identity provider. The {@code *-claim} options override it. */
        Optional<Preset> preset();

        /** The caller's username. Dotted paths reach nested claims. Default {@code sub}, or the preset's. */
        Optional<String> usernameClaim();

        /** The caller's roles: an array, or a comma-separated string. Default {@code roles}, or the preset's. */
        Optional<String> rolesClaim();

        /** The caller's tenant. Default {@code tenant}, or the preset's. */
        Optional<String> tenantClaim();

        /**
         * Public key (PEM) the token is verified with - or, with an HS* {@code algorithm}, the shared
         * secret. Can't be combined with {@code jwks-uri} or {@code discovery-uris}.
         */
        Optional<String> publicKey();

        /** Path to a PEM public key file, read once at startup: {@code public-key}, from a file. */
        Optional<String> publicKeyFile();

        /**
         * With a PEM key: the signature algorithm(s), default {@code ES256}. With {@code jwks-uri} or
         * {@code discovery-uris}: optional, an allowlist - each key verifies with its own algorithm,
         * never the one the token announces; {@code none} and HS* are refused.
         */
        Optional<List<String>> algorithm();

        /**
         * URL of the JWK Set publishing the issuer's signing keys. Fetched on first use, cached, and
         * re-fetched when a token fails verification, so a key rotation needs no restart.
         */
        Optional<String> jwksUri();

        /**
         * OpenID Providers to trust: {@code granted.jwt.discovery-uris[0].uri=https://idp-a},
         * {@code granted.jwt.discovery-uris[1].uri=...}. A token is verified only with the keys of the
         * provider whose issuer is its {@code iss}; any other {@code iss} is rejected, and no URL is
         * ever taken from the token.
         */
        List<Provider> discoveryUris();

        /** Age after which cached keys and discovery documents are re-fetched. */
        @WithDefault("10M")
        Duration jwksCacheMaxAge();

        /** Minimum delay between two fetches of one JWK Set or discovery document. */
        @WithDefault("30S")
        Duration jwksCooldown();

        /** Timeout of a JWK Set or discovery document fetch. */
        @WithDefault("5S")
        Duration jwksTimeout();

        /**
         * Accepted {@code iss}. Not checked when unset. With {@code discovery-uris}, it applies to
         * {@code jwks-uri} only, and is required with it.
         */
        Optional<List<String>> issuer();

        /** Accepted {@code aud}: strings, or patterns between slashes ({@code /^orders-/}). Not checked when unset. */
        Optional<List<String>> audience();

        /**
         * Name of a configuration of Quarkus's TLS registry ({@code quarkus.tls.<name>.*}) that the
         * discovery documents and JWK Sets are fetched with - e.g. a trust store holding the cluster's
         * CA. Unset: the JVM's trusted authorities. A provider can name its own. The host name is
         * always verified; a configuration trusting all certificates is refused unless
         * {@code quarkus.tls.trust-all} is on.
         */
        Optional<String> tlsConfigurationName();
    }

    /** Claim mappings of well-known identity providers - nestjs-granted's presets. */
    enum Preset {
        /** RFC 9068 access tokens: {@code sub}, {@code roles}, {@code tenant}. */
        RFC9068,
        /** Microsoft Entra ID: {@code preferred_username}, {@code roles}, {@code tid}. */
        AZURE_AD,
        /** Keycloak: {@code preferred_username}, {@code realm_access.roles}, {@code tenant}. */
        KEYCLOAK,
        /** Okta: {@code sub}, {@code groups}, {@code tenant}. */
        OKTA
    }

    /** An OpenID Provider to trust: by its discovery document, or by its issuer and JWK Set given outright. */
    interface Provider {

        /**
         * The discovery document URL, or the URL it lives under ({@code /.well-known/openid-configuration}
         * is appended). Not needed when {@code issuer} and {@code jwks-uri} are given.
         */
        Optional<String> uri();

        /** The provider's issuer, given instead of read from its discovery document - with {@code jwks-uri}. */
        Optional<String> issuer();

        /** The provider's JWK Set URL, given instead of read from its discovery document - with {@code issuer}. */
        Optional<String> jwksUri();

        /**
         * File holding a token sent as {@code Authorization: Bearer} to this provider's discovery
         * document and JWK Set - never to another provider. Read at every fetch.
         */
        Optional<String> bearerTokenFile();

        /** Accepted {@code aud} of this provider's tokens, in place of {@code granted.jwt.audience}. */
        Optional<List<String>> audience();

        /**
         * {@code sub} patterns ({@code *} matches anything) whose tokens, from this provider, pass every
         * role check - e.g. {@code system:serviceaccount:my-namespace:*}.
         */
        Optional<List<String>> bypass();

        /** The TLS configuration this provider is fetched with, in place of {@code granted.jwt.tls-configuration-name}. */
        Optional<String> tlsConfigurationName();

        /**
         * Whether the {@code granted-jwks} readiness check waits for this provider's keys. Off for a
         * provider whose outage must not take the service out of its users' traffic - the
         * Kubernetes API server, whose keys only verify service accounts.
         */
        @WithDefault("true")
        boolean readiness();
    }

    interface AccessDenied {

        /**
         * Also write why a request was refused into the 403 response - the rule, the caller, its
         * roles. Off by default: the reason is logged, and the caller learns nothing about the
         * rules, as with nestjs-granted. Turn it on where every caller is trusted.
         */
        @WithDefault("false")
        boolean details();
    }
}
