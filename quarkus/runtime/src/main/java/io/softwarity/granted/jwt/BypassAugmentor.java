package io.softwarity.granted.jwt;

import jakarta.enterprise.context.ApplicationScoped;

import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.SecurityIdentityAugmentor;
import io.smallrye.mutiny.Uni;

/**
 * A token whose {@code sub} matched its provider's {@code bypass} passes every role check: the
 * identity answers yes to any role, and to any permission. Only the mark the mechanism sets after
 * verifying the token with that provider's keys counts - never a claim. Applied last, after the
 * roles are shaped.
 */
@ApplicationScoped
public class BypassAugmentor implements SecurityIdentityAugmentor {

    @Override
    public int priority() {
        return Integer.MIN_VALUE;
    }

    @Override
    public Uni<SecurityIdentity> augment(SecurityIdentity identity, AuthenticationRequestContext context) {
        return Uni.createFrom().item(Boolean.TRUE.equals(identity.getAttribute(JwtAuthenticationMechanism.BYPASS)) ? new BypassIdentity(identity) : identity);
    }
}
