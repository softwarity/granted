package io.softwarity.granted;

import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.IdentityProvider;
import io.quarkus.security.identity.IdentityProviderManager;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.AuthenticationRequest;
import io.quarkus.security.identity.request.BaseAuthenticationRequest;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.vertx.http.runtime.security.ChallengeData;
import io.quarkus.vertx.http.runtime.security.HttpAuthenticationMechanism;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;

/**
 * The caller from the gateway's headers ({@code granted.source=headers}, the default): the
 * gateway authenticated it and forwards {@code username}, {@code roles} and {@code tenant}.
 * Nothing to verify here - the service must therefore never be reachable except through the
 * gateway. With {@code granted.source=jwt} the headers are never read.
 *
 * <p>The identity goes through the {@link IdentityProviderManager} like any other, so the
 * augmentors - the role hierarchy among them - apply to it.
 */
@ApplicationScoped
public class HeaderAuthenticationMechanism implements HttpAuthenticationMechanism {

    /** The caller as the gateway describes it. */
    public static final class GatewayHeadersRequest extends BaseAuthenticationRequest {

        final String username;

        final Set<String> roles;

        GatewayHeadersRequest(String username, Set<String> roles) {
            this.username = username;
            this.roles = roles;
        }
    }

    /** Trusts the gateway's headers as they are. */
    @ApplicationScoped
    public static class GatewayHeadersIdentityProvider implements IdentityProvider<GatewayHeadersRequest> {

        @Override
        public Class<GatewayHeadersRequest> getRequestType() {
            return GatewayHeadersRequest.class;
        }

        @Override
        public Uni<SecurityIdentity> authenticate(GatewayHeadersRequest request, AuthenticationRequestContext context) {
            return Uni.createFrom().item(QuarkusSecurityIdentity.builder()
                    .setPrincipal(new QuarkusPrincipal(request.username))
                    .addRoles(request.roles)
                    .build());
        }
    }

    @Inject
    GrantedConfig config;

    @Override
    public Uni<SecurityIdentity> authenticate(RoutingContext context, IdentityProviderManager identityProviderManager) {
        if (config.source() != GrantedConfig.Source.HEADERS) {
            return Uni.createFrom().optional(Optional.empty());
        }
        String username = context.request().getHeader(config.headers().username());
        if (username == null || username.isBlank()) {
            return Uni.createFrom().optional(Optional.empty());
        }
        Set<String> roles = new LinkedHashSet<>(Claims.strings(context.request().getHeader(config.headers().roles())));
        return identityProviderManager.authenticate(new GatewayHeadersRequest(username.trim(), roles));
    }

    @Override
    public Uni<ChallengeData> getChallenge(RoutingContext context) {
        return Uni.createFrom().item(new ChallengeData(401, null, null));
    }

    @Override
    public Set<Class<? extends AuthenticationRequest>> getCredentialTypes() {
        return Set.of(GatewayHeadersRequest.class);
    }
}
