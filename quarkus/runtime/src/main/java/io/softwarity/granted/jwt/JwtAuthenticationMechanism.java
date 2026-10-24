package io.softwarity.granted.jwt;

import java.util.Map;
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
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.vertx.http.runtime.security.ChallengeData;
import io.quarkus.vertx.http.runtime.security.HttpAuthenticationMechanism;
import io.smallrye.mutiny.Uni;
import io.smallrye.mutiny.infrastructure.Infrastructure;
import io.softwarity.granted.GrantedConfig;
import io.vertx.ext.web.RoutingContext;

/**
 * The caller from the {@code Authorization} token, verified by granted itself
 * ({@code granted.source=jwt} with {@code granted.jwt} key material). A missing, malformed or
 * invalid token gives an anonymous caller - never a 401 of its own: the rules decide, as with
 * nestjs-granted. The verification runs on a worker thread: it may fetch a JWK Set.
 */
@ApplicationScoped
public class JwtAuthenticationMechanism implements HttpAuthenticationMechanism {

    /** The identity attribute marking a token whose {@code sub} matched its provider's {@code bypass}. Set here only. */
    public static final String BYPASS = "io.softwarity.granted.bypass";

    /** A token granted verified. */
    public static final class VerifiedTokenRequest extends BaseAuthenticationRequest {

        final GrantedJsonWebToken token;

        final boolean bypass;

        VerifiedTokenRequest(GrantedJsonWebToken token, boolean bypass) {
            this.token = token;
            this.bypass = bypass;
        }
    }

    /** Turns a verified token into the identity: its principal, and the bypass mark. Roles come from the augmentor. */
    @ApplicationScoped
    public static class VerifiedTokenIdentityProvider implements IdentityProvider<VerifiedTokenRequest> {

        @Override
        public Class<VerifiedTokenRequest> getRequestType() {
            return VerifiedTokenRequest.class;
        }

        @Override
        public Uni<SecurityIdentity> authenticate(VerifiedTokenRequest request, AuthenticationRequestContext context) {
            return Uni.createFrom().item(QuarkusSecurityIdentity.builder()
                    .setPrincipal(request.token)
                    .addAttribute(BYPASS, request.bypass)
                    .build());
        }
    }

    @Inject
    GrantedConfig config;

    @Inject
    JwtVerification verification;

    @Override
    public Uni<SecurityIdentity> authenticate(RoutingContext context, IdentityProviderManager identityProviderManager) {
        if (config.source() != GrantedConfig.Source.JWT || !verification.enabled()) {
            return Uni.createFrom().optional(Optional.empty());
        }
        String token = token(context.request().getHeader("Authorization"));
        if (token == null) {
            return Uni.createFrom().optional(Optional.empty());
        }
        return Uni.createFrom().item(() -> verification.verify(token))
                .runSubscriptionOn(Infrastructure.getDefaultWorkerPool())
                .onItem().transformToUni(verified -> verified == null
                        ? Uni.createFrom().<SecurityIdentity> nullItem()
                        : identityProviderManager.authenticate(new VerifiedTokenRequest(principal(token, verified), verified.bypass())));
    }

    /** The token sits after the scheme: {@code Bearer <token>}. */
    static String token(String authorization) {
        if (authorization == null) {
            return null;
        }
        String[] parts = authorization.trim().split("\\s+");
        return parts.length > 1 && !parts[1].isEmpty() ? parts[1] : null;
    }

    /**
     * The principal is named by the username claim; a bypassing token may lack it (a service
     * account has no {@code preferred_username}): its {@code sub} names it.
     */
    private GrantedJsonWebToken principal(String token, JwtVerifier.Verified verified) {
        Map<String, Object> claims = verified.claims();
        Object username = io.softwarity.granted.ClaimPaths.read(claims, io.softwarity.granted.ClaimPaths.username(config.jwt()));
        String name = username instanceof String s && !s.isEmpty() ? s
                : verified.bypass() && claims.get("sub") instanceof String sub ? sub : "anonymous";
        return new GrantedJsonWebToken(name, token, claims);
    }

    @Override
    public Uni<ChallengeData> getChallenge(RoutingContext context) {
        return Uni.createFrom().item(new ChallengeData(401, "WWW-Authenticate", "Bearer"));
    }

    @Override
    public Set<Class<? extends AuthenticationRequest>> getCredentialTypes() {
        return Set.of(VerifiedTokenRequest.class);
    }
}
