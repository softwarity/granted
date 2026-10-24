package io.softwarity.granted;

import java.util.LinkedHashSet;
import java.util.Set;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.eclipse.microprofile.jwt.JsonWebToken;

import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.SecurityIdentityAugmentor;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.smallrye.mutiny.Uni;

/**
 * The roles the caller is judged on, whatever authenticated it: with a JWT, the roles of
 * {@code granted.jwt.roles-claim} (an array, or a comma-separated string) are added to those
 * the verifying extension mapped; then the hierarchy expands them and {@code known-roles}
 * filters them. {@code @RolesAllowed} and {@link GrantedCaller#roles()} see the result.
 */
@ApplicationScoped
public class GrantedIdentityAugmentor implements SecurityIdentityAugmentor {

    @Inject
    GrantedConfig config;

    @Override
    public Uni<SecurityIdentity> augment(SecurityIdentity identity, AuthenticationRequestContext context) {
        if (identity.isAnonymous()) {
            return Uni.createFrom().item(identity);
        }
        Set<String> roles = new LinkedHashSet<>(identity.getRoles());
        if (config.source() == GrantedConfig.Source.JWT && identity.getPrincipal() instanceof JsonWebToken jwt) {
            roles.addAll(Claims.strings(Claims.read(jwt, ClaimMapping.of(config.jwt()).roles())));
        }
        Set<String> resolved = RoleHierarchy.resolve(roles, config.roleHierarchy(), config.knownRoles());
        if (resolved.equals(identity.getRoles())) {
            return Uni.createFrom().item(identity);
        }
        if (resolved.containsAll(identity.getRoles())) {
            return Uni.createFrom().item(QuarkusSecurityIdentity.builder(identity).addRoles(resolved).build());
        }
        // known-roles dropped a role: a builder can only add, so the identity is rebuilt, its
        // permission checks delegated to the original.
        return Uni.createFrom().item(QuarkusSecurityIdentity.builder()
                .setPrincipal(identity.getPrincipal())
                .addCredentials(identity.getCredentials())
                .addAttributes(identity.getAttributes())
                .addRoles(resolved)
                .addPermissionChecker(identity::checkPermission)
                .build());
    }
}
