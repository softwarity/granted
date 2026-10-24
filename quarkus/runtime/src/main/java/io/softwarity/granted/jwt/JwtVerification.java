package io.softwarity.granted.jwt;

import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import io.quarkus.runtime.Startup;
import io.softwarity.granted.GrantedConfig;

/**
 * The verifier of {@code granted.jwt.*}, built at startup: a configuration that could only look
 * secure - an issuer without a key, a JWK Set with HS256 - stops the application, as it stops
 * nestjs-granted's provider at construction.
 */
@Startup
@ApplicationScoped
public class JwtVerification {

    @Inject
    GrantedConfig config;

    private JwtVerifier verifier;

    @PostConstruct
    void build() {
        if (config.source() == GrantedConfig.Source.JWT && JwtSettings.configured(config.jwt())) {
            verifier = new JwtVerifier(JwtSettings.of(config.jwt()));
        } else if (config.source() == GrantedConfig.Source.JWT) {
            // Validates what can be: an issuer or an audience without a key only looks secure.
            JwtSettings.of(config.jwt());
        }
    }

    /** Whether granted verifies the token itself, rather than reading what another extension verified. */
    public boolean enabled() {
        return verifier != null;
    }

    /** Blocking: it may fetch a JWK Set or a discovery document. */
    public JwtVerifier.Verified verify(String token) {
        return verifier.verify(token);
    }
}
