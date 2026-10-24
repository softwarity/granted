package io.softwarity.granted.jwt;

import java.security.Permission;
import java.security.Principal;
import java.util.Map;
import java.util.Set;

import io.quarkus.security.credential.Credential;
import io.quarkus.security.identity.SecurityIdentity;
import io.smallrye.mutiny.Uni;

/** An identity that passes every role and permission check - its roles stay what they are. */
final class BypassIdentity implements SecurityIdentity {

    private final SecurityIdentity delegate;

    BypassIdentity(SecurityIdentity delegate) {
        this.delegate = delegate;
    }

    @Override
    public Principal getPrincipal() {
        return delegate.getPrincipal();
    }

    @Override
    public boolean isAnonymous() {
        return false;
    }

    @Override
    public Set<String> getRoles() {
        return delegate.getRoles();
    }

    @Override
    public boolean hasRole(String role) {
        return true;
    }

    @Override
    public Set<Permission> getPermissions() {
        return delegate.getPermissions();
    }

    @Override
    public <T extends Credential> T getCredential(Class<T> type) {
        return delegate.getCredential(type);
    }

    @Override
    public Set<Credential> getCredentials() {
        return delegate.getCredentials();
    }

    @Override
    public <T> T getAttribute(String name) {
        return delegate.getAttribute(name);
    }

    @Override
    public Map<String, Object> getAttributes() {
        return delegate.getAttributes();
    }

    @Override
    public Uni<Boolean> checkPermission(Permission permission) {
        return Uni.createFrom().item(true);
    }
}
