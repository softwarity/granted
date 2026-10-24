package io.softwarity.granted.jwt;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Stream;

import javax.net.ssl.SSLContext;

import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import io.quarkus.runtime.Startup;
import io.quarkus.tls.TlsConfiguration;
import io.quarkus.tls.TlsConfigurationRegistry;
import io.softwarity.granted.GrantedConfig;

/**
 * The verifier of {@code granted.jwt.*}, built at startup. A configuration that could only look
 * secure stops the application, as it stops nestjs-granted's provider at construction: an issuer
 * without a key, a JWK Set with HS256, a TLS configuration that doesn't exist or trusts every
 * certificate - and {@code granted.source=jwt} with nothing to verify the token, which would turn
 * every caller anonymous without a word in the logs.
 */
@Startup
@ApplicationScoped
public class JwtVerification {

    /**
     * Whether quarkus-oidc or quarkus-smallrye-jwt is in the application - set at build time by the
     * extension: without key material, granted reads the token one of them verified.
     */
    static volatile boolean externalVerifier;

    @Inject
    GrantedConfig config;

    @Inject
    TlsConfigurationRegistry registry;

    private JwtVerifier verifier;

    /** Set by the extension's recorder. */
    public static void externalVerifier(boolean present) {
        externalVerifier = present;
    }

    @PostConstruct
    void build() {
        if (config.source() != GrantedConfig.Source.JWT) {
            return;
        }
        if (JwtSettings.configured(config.jwt())) {
            JwtSettings settings = JwtSettings.of(config.jwt());
            verifier = new JwtVerifier(settings, sslContexts(settings));
            return;
        }
        // Validates what can be: an issuer or an audience without a key only looks secure.
        JwtSettings.of(config.jwt());
        if (!externalVerifier) {
            throw new IllegalStateException("[quarkus-granted] granted.source=jwt, but nothing verifies the token: give granted.jwt.public-key, "
                    + "public-key-file, jwks-uri or discovery-uris - or add quarkus-oidc or quarkus-smallrye-jwt. Every caller would be anonymous.");
        }
    }

    /**
     * The {@code SSLContext} of each TLS configuration the settings name, from Quarkus's registry.
     * A name the registry doesn't know stops the start, naming the property that gave it. A
     * configuration trusting every certificate would let anyone on the path serve the keys - and
     * so sign any token: it is refused, unless {@code quarkus.tls.trust-all} says that is meant.
     */
    private Map<String, SSLContext> sslContexts(JwtSettings settings) {
        boolean trustAllAllowed = registry.getDefault().map(TlsConfiguration::isTrustAll).orElse(false);
        Map<String, SSLContext> contexts = new HashMap<>();
        Stream.concat(Stream.of(settings.tls()), settings.providers().stream().map(JwtSettings.ProviderSettings::tls))
                .filter(Objects::nonNull)
                .forEach(tls -> {
                    if (contexts.containsKey(tls.name())) {
                        return;
                    }
                    TlsConfiguration configuration = registry.get(tls.name()).orElseThrow(() -> new IllegalStateException(
                            "[quarkus-granted] " + tls.property() + "=" + tls.name() + ": no such TLS configuration - declare quarkus.tls." + tls.name() + ".*"));
                    if (configuration.isTrustAll() && !trustAllAllowed) {
                        throw new IllegalStateException("[quarkus-granted] " + tls.property() + "=" + tls.name()
                                + " trusts every certificate: anyone on the path could serve the keys and sign any token. Set quarkus.tls.trust-all=true if that is meant");
                    }
                    try {
                        contexts.put(tls.name(), configuration.createSSLContext());
                    } catch (Exception e) {
                        throw new IllegalStateException("[quarkus-granted] " + tls.property() + "=" + tls.name() + ": the TLS configuration can't be loaded", e);
                    }
                });
        return contexts;
    }

    /** Whether granted verifies the token itself, rather than reading what another extension verified. */
    public boolean enabled() {
        return verifier != null;
    }

    /** Blocking: it may fetch a JWK Set or a discovery document. */
    public JwtVerifier.Verified verify(String token) {
        return verifier.verify(token);
    }

    /** The providers the readiness check waits for; empty when granted fetches nothing. Blocking. */
    public List<JwtVerifier.ProviderStatus> readiness() {
        return verifier == null ? List.of() : verifier.readiness();
    }
}
