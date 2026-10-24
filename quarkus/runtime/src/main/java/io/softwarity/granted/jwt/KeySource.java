package io.softwarity.granted.jwt;

import java.util.List;
import java.util.function.LongSupplier;
import java.util.regex.Pattern;

import io.softwarity.granted.jwt.JwtSettings.Audience;

/** A JWK Set, the issuer its keys vouch for, and the audience and bypass that apply to their tokens. */
class KeySource {

    final Fetched<List<JwksKey>> keys;

    /** The JWK Set URL - a discovery document may change it. */
    volatile String jwksUri;

    /** Accepted {@code iss}; {@code null} routes every token here: a lone {@code jwks-uri} without {@code issuer}. */
    volatile List<String> issuer;

    final List<Audience> audience;

    /** {@code sub} patterns whose tokens pass every role check. */
    final List<Pattern> bypass;

    /** How the readiness check names this source. */
    final String label;

    /** Whether the readiness check waits for this source's keys. */
    final boolean readiness;

    KeySource(String jwksUri, List<String> issuer, List<Audience> audience, List<Pattern> bypass, String bearerTokenFile,
            JwtSettings.Tls tls, String label, boolean readiness, JwtVerifier verifier, LongSupplier clock) {
        this.jwksUri = jwksUri;
        this.issuer = issuer;
        this.audience = audience;
        this.bypass = bypass;
        this.label = label;
        this.readiness = readiness;
        this.keys = new Fetched<>(List.of(), verifier.settings().policy(),
                () -> verifier.parseJwks(verifier.fetchJson(this.jwksUri, bearerTokenFile, tls)),
                () -> "JWKS fetch failed (" + this.jwksUri + ")", clock);
    }

    /** Why this source has no issuer yet - only a discovery document can lack one. */
    String discoveryFailure() {
        return null;
    }

    /** Brings {@code issuer} and {@code jwksUri} up to date - nothing to do when they are configured. */
    void discover() {
    }

    boolean accepts(Object iss) {
        return JwtSettings.issuerAccepted(issuer, iss);
    }
}
