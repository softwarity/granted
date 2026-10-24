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

    KeySource(String jwksUri, List<String> issuer, List<Audience> audience, List<Pattern> bypass, String bearerTokenFile,
            JwtVerifier verifier, LongSupplier clock) {
        this.jwksUri = jwksUri;
        this.issuer = issuer;
        this.audience = audience;
        this.bypass = bypass;
        this.keys = new Fetched<>(List.of(), verifier.settings().policy(),
                () -> verifier.parseJwks(verifier.fetchJson(this.jwksUri, bearerTokenFile)),
                () -> "JWKS fetch failed (" + this.jwksUri + ")", clock);
    }

    /** Brings {@code issuer} and {@code jwksUri} up to date - nothing to do when they are configured. */
    void discover() {
    }

    boolean accepts(Object iss) {
        return JwtSettings.issuerAccepted(issuer, iss);
    }
}
