package io.softwarity.granted.jwt;

import java.util.List;
import java.util.Map;
import java.util.function.LongSupplier;

import io.softwarity.granted.jwt.JwtSettings.ProviderSettings;

/** A key source whose issuer and JWK Set URL come from an OpenID Provider's discovery document. */
final class DiscoverySource extends KeySource {

    private static final String OPENID_CONFIGURATION = "/.well-known/openid-configuration";

    private record Configuration(String issuer, String jwksUri) {
    }

    private final Fetched<Configuration> configuration;

    DiscoverySource(ProviderSettings provider, JwtVerifier verifier, LongSupplier clock) {
        super(null, null, provider.audience(), provider.bypass(), provider.bearerTokenFile(), provider.tls(), provider.label(),
                provider.readiness(), verifier, clock);
        String discoveryUri = openidConfigurationUrl(provider.uri());
        this.configuration = new Fetched<>(null, verifier.settings().policy(), () -> {
            Object document = verifier.fetchJson(discoveryUri, provider.bearerTokenFile(), provider.tls());
            Object issuer = document instanceof Map<?, ?> map ? map.get("issuer") : null;
            Object jwksUri = document instanceof Map<?, ?> map ? map.get("jwks_uri") : null;
            if (!(issuer instanceof String i) || i.isEmpty() || !(jwksUri instanceof String j) || j.isEmpty()) {
                throw new IllegalStateException("no \"issuer\" or \"jwks_uri\" in the response");
            }
            return new Configuration(i, j);
        }, () -> "OpenID configuration fetch failed (" + discoveryUri + ")", clock);
    }

    /** The discovery document URL: as given, or the IdP URL with {@code /.well-known/openid-configuration} appended. */
    static String openidConfigurationUrl(String uri) {
        return uri.endsWith(OPENID_CONFIGURATION) ? uri : uri.replaceAll("/+$", "") + OPENID_CONFIGURATION;
    }

    @Override
    void discover() {
        Configuration current = configuration.get(false);
        if (current == null) {
            return;
        }
        if (!current.jwksUri().equals(jwksUri)) {
            jwksUri = current.jwksUri();
            keys.expire();
        }
        issuer = List.of(current.issuer());
    }

    @Override
    String discoveryFailure() {
        String failure = configuration.lastFailure();
        return failure == null ? "no discovery document fetched yet" : "discovery document: " + failure;
    }

    /** No token is routed here until the document has been fetched. */
    @Override
    boolean accepts(Object iss) {
        return issuer != null && super.accepts(iss);
    }
}
