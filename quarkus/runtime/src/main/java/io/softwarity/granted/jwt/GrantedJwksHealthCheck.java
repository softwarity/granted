package io.softwarity.granted.jwt;

import java.util.List;

import jakarta.inject.Inject;

import org.eclipse.microprofile.health.HealthCheck;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.eclipse.microprofile.health.HealthCheckResponseBuilder;
import org.eclipse.microprofile.health.Readiness;

import io.softwarity.granted.GrantedConfig;

/**
 * {@code granted-jwks}: without its providers' keys, granted refuses every token, so the service
 * is not ready to serve. DOWN while a provider has no key, naming it and why - the status, a TLS
 * handshake, a timeout; UP with the number of keys of each.
 *
 * <p>It asks exactly what a verification asks, through the same cache, TLS configuration, bearer
 * token and cooldown: polling it never makes granted hammer an IdP. A provider with
 * {@code readiness=false} is not waited for - the Kubernetes API server, whose outage must not
 * take the pod out of its users' traffic. With a PEM key, or without granted verifying the token,
 * there is nothing to wait for: UP.
 *
 * <p>Registered by the extension when quarkus-smallrye-health is present and
 * {@code granted.health.enabled} is on - no bean-defining annotation, so without the health
 * extension this class is never loaded.
 */
@Readiness
public class GrantedJwksHealthCheck implements HealthCheck {

    static final String NAME = "granted-jwks";

    @Inject
    GrantedConfig config;

    @Inject
    JwtVerification verification;

    @Override
    public HealthCheckResponse call() {
        HealthCheckResponseBuilder response = HealthCheckResponse.named(NAME);
        if (!verification.enabled()) {
            return response.up().withData("verification", config.source() == GrantedConfig.Source.HEADERS
                    ? "gateway headers: nothing to fetch" : "by quarkus-oidc or quarkus-smallrye-jwt: nothing to fetch").build();
        }
        List<JwtVerifier.ProviderStatus> providers = verification.readiness();
        if (providers.isEmpty()) {
            return response.up().withData("verification", "nothing to wait for: a PEM key, or every provider with readiness=false").build();
        }
        boolean up = true;
        for (JwtVerifier.ProviderStatus provider : providers) {
            response.withData(provider.label(), provider.up() ? provider.keys() + " keys" : provider.failure());
            up &= provider.up();
        }
        return response.status(up).build();
    }
}
