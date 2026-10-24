package io.softwarity.granted.jwt;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.regex.Pattern;

import io.softwarity.granted.GrantedConfig;

/**
 * How granted verifies a JWT itself - {@code granted.jwt.*}, checked at startup with
 * nestjs-granted's rules: a configuration that could only look secure fails the start.
 *
 * @param algorithms the configured algorithms; {@code null} with a JWK Set and no allowlist
 * @param key the PEM public key, or the HS* secret; {@code null} with a JWK Set
 * @param jwksUri a JWK Set given directly
 * @param providers the OpenID Providers of {@code discovery-uris}
 * @param issuer accepted {@code iss}: of the PEM key's tokens, or of {@code jwksUri}'s
 * @param audience accepted {@code aud}, strings or patterns
 * @param tls the TLS configuration {@code jwksUri} is fetched with; {@code null} for the JVM's
 */
public record JwtSettings(List<String> algorithms, String key, String jwksUri, List<ProviderSettings> providers, Policy policy,
        List<String> issuer, List<Audience> audience, Tls tls) {

    /** A configuration of Quarkus's TLS registry, and the property that named it - for the message when it doesn't exist. */
    public record Tls(String name, String property) {
    }

    /** What a JWK Set key may verify: asymmetric signatures only - never {@code none}, never a shared-secret HS*. */
    static final List<String> JWKS_ALGORITHMS = List.of("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384",
            "ES512", "EdDSA");

    static final List<String> HMAC_ALGORITHMS = List.of("HS256", "HS384", "HS512");

    /** Cache age, minimum delay between two fetches, and timeout of a fetch - in milliseconds. */
    public record Policy(long maxAge, long cooldown, long timeout) {
    }

    /**
     * An OpenID Provider: by its discovery document ({@code uri}), or by {@code issuer} and
     * {@code jwksUri}; fetched with {@code tls} ({@code null}: the JVM's authorities), awaited by
     * the readiness check unless {@code readiness} is off.
     */
    public record ProviderSettings(String uri, String issuer, String jwksUri, String bearerTokenFile, List<Audience> audience,
            List<Pattern> bypass, Tls tls, boolean readiness) {

        /** How the readiness check and the logs name this provider: its issuer when given, else its URL. */
        public String label() {
            return issuer != null ? issuer : uri;
        }
    }

    /** An accepted {@code aud}: a string, or a pattern given between slashes ({@code /^orders-/}). */
    public record Audience(String value, Pattern pattern) {

        static Audience of(String value) {
            return value.length() > 2 && value.startsWith("/") && value.endsWith("/")
                    ? new Audience(value, Pattern.compile(value.substring(1, value.length() - 1)))
                    : new Audience(value, null);
        }

        boolean accepts(Object aud) {
            return aud instanceof String string && (pattern != null ? pattern.matcher(string).find() : value.equals(string));
        }
    }

    /** Whether any key material is configured: without, the token is read as another extension verified it. */
    public static boolean configured(GrantedConfig.Jwt jwt) {
        return jwt.publicKey().isPresent() || jwt.publicKeyFile().isPresent() || jwt.jwksUri().isPresent()
                || !jwt.discoveryUris().isEmpty();
    }

    public static JwtSettings of(GrantedConfig.Jwt jwt) {
        List<GrantedConfig.Provider> providers = jwt.discoveryUris();
        boolean pem = jwt.publicKey().isPresent() || jwt.publicKeyFile().isPresent();
        boolean jwks = jwt.jwksUri().isPresent() || !providers.isEmpty();
        for (GrantedConfig.Provider provider : providers) {
            if (provider.issuer().isPresent() != provider.jwksUri().isPresent()) {
                throw invalid("a granted.jwt.discovery-uris entry gives issuer and jwks-uri together, or neither");
            }
            if (provider.uri().isEmpty() && provider.jwksUri().isEmpty()) {
                throw invalid("each granted.jwt.discovery-uris entry needs a uri - or an issuer and a jwks-uri");
            }
        }
        if (jwt.publicKey().isPresent() && jwt.publicKeyFile().isPresent()) {
            throw invalid("granted.jwt.public-key and public-key-file are the same key: give one");
        }
        if (jwt.jwksUri().isPresent() && pem) {
            throw invalid("granted.jwt.jwks-uri cannot be combined with public-key or public-key-file");
        }
        if (!providers.isEmpty() && pem) {
            throw invalid("granted.jwt.discovery-uris cannot be combined with public-key or public-key-file");
        }
        if (!providers.isEmpty() && jwt.issuer().isPresent() && jwt.jwksUri().isEmpty()) {
            throw invalid("granted.jwt.issuer applies to jwks-uri only: discovery-uris take their issuer from the discovery document");
        }
        if (!providers.isEmpty() && jwt.jwksUri().isPresent() && jwt.issuer().isEmpty()) {
            // Without it, jwks-uri's keys would be tried on any token - those of the OpenID Providers included.
            throw invalid("granted.jwt.jwks-uri needs an issuer when combined with discovery-uris, to route its tokens");
        }
        if ((jwt.issuer().isPresent() || jwt.audience().isPresent()) && !(pem || jwks)) {
            // An unverified token's claims can say anything: checking them would only look secure.
            throw invalid("granted.jwt.issuer and audience need a key to verify the token: public-key, public-key-file, jwks-uri or discovery-uris");
        }
        // The default is for a PEM key only: with a JWK Set, each key brings its own algorithm.
        List<String> algorithms = jwt.algorithm().orElse(jwks ? null : List.of("ES256"));
        if (algorithms != null) {
            for (String algorithm : algorithms) {
                if (!JWKS_ALGORITHMS.contains(algorithm) && !HMAC_ALGORITHMS.contains(algorithm)) {
                    throw invalid("granted.jwt.algorithm " + algorithm + " is not a JWS algorithm granted verifies: "
                            + String.join(", ", JWKS_ALGORITHMS) + ", " + String.join(", ", HMAC_ALGORITHMS));
                }
            }
            if (jwks) {
                // A JWK Set publishes public keys: the shared-secret HS* have no place here.
                List<String> refused = algorithms.stream().filter(algorithm -> !JWKS_ALGORITHMS.contains(algorithm)).toList();
                if (!refused.isEmpty()) {
                    throw invalid("granted.jwt.algorithm " + String.join(", ", refused) + " cannot be used with jwks-uri or discovery-uris, which accept "
                            + String.join(", ", JWKS_ALGORITHMS));
                }
            } else if (algorithms.contains("EdDSA")) {
                throw invalid("EdDSA is only supported with granted.jwt.jwks-uri or discovery-uris");
            }
        }
        String key = jwt.publicKey().orElse(null);
        if (jwt.publicKeyFile().isPresent()) {
            try {
                key = Files.readString(Path.of(jwt.publicKeyFile().get()));
            } catch (IOException e) {
                throw new UncheckedIOException("[quarkus-granted] granted.jwt.public-key-file can't be read: " + jwt.publicKeyFile().get(), e);
            }
        }
        List<Audience> audience = jwt.audience().map(values -> values.stream().map(Audience::of).toList()).orElse(null);
        Policy policy = new Policy(jwt.jwksCacheMaxAge().toMillis(), jwt.jwksCooldown().toMillis(), jwt.jwksTimeout().toMillis());
        Tls tls = jwt.tlsConfigurationName().map(name -> new Tls(name, "granted.jwt.tls-configuration-name")).orElse(null);
        List<ProviderSettings> resolved = new java.util.ArrayList<>();
        for (int i = 0; i < providers.size(); i++) {
            GrantedConfig.Provider provider = providers.get(i);
            String property = "granted.jwt.discovery-uris[" + i + "].tls-configuration-name";
            resolved.add(new ProviderSettings(provider.uri().orElse(null), provider.issuer().orElse(null), provider.jwksUri().orElse(null),
                    provider.bearerTokenFile().orElse(null),
                    provider.audience().map(values -> values.stream().map(Audience::of).toList()).orElse(audience),
                    provider.bypass().orElse(List.of()).stream().map(JwtSettings::subjectPattern).toList(),
                    provider.tlsConfigurationName().map(name -> new Tls(name, property)).orElse(tls), provider.readiness()));
        }
        return new JwtSettings(algorithms, key, jwt.jwksUri().orElse(null), List.copyOf(resolved), policy, jwt.issuer().orElse(null), audience, tls);
    }

    /** {@code *} matches any run of characters; everything else is literal. */
    static Pattern subjectPattern(String pattern) {
        StringBuilder regex = new StringBuilder("^");
        String[] parts = pattern.split("\\*", -1);
        for (int i = 0; i < parts.length; i++) {
            if (i > 0) {
                regex.append(".*");
            }
            regex.append(Pattern.quote(parts[i]));
        }
        return Pattern.compile(regex.append('$').toString());
    }

    private static IllegalStateException invalid(String message) {
        return new IllegalStateException("[quarkus-granted] " + message);
    }

    /** Whether the token's {@code iss} is one of {@code issuer}. Unset: anything. */
    static boolean issuerAccepted(List<String> issuer, Object iss) {
        // An immutable list refuses contains(null): a token without iss matches no issuer.
        return issuer == null || iss != null && issuer.contains(iss);
    }
}
