package io.softwarity.granted;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;

import org.eclipse.microprofile.jwt.JsonWebToken;

import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.vertx.http.runtime.CurrentVertxRequest;

/**
 * The caller of the current request - what nestjs-granted's {@code @Username()},
 * {@code @Roles()}, {@code @Tenant()} and {@code @Claim()} give a handler.
 *
 * <pre>{@code
 * @Inject
 * GrantedCaller caller;
 *
 * @GET
 * @RolesAllowed("FORECASTER")
 * public List<Station> list() {
 *     return Station.list("territory in ?1", caller.claims("territories", String.class));
 * }
 * }</pre>
 *
 * Request-scoped: a resource is a singleton, and each call reads the request being served -
 * never one captured when the resource was built.
 *
 * <p>With {@code granted.source=jwt}, every value comes from the verified token - never from a
 * header, whatever the request carries. With {@code headers}, from the header of that name.
 */
@RequestScoped
public class GrantedCaller {

    /** The username of a caller nobody authenticated. */
    public static final String ANONYMOUS = "anonymous";

    @Inject
    SecurityIdentity identity;

    @Inject
    GrantedConfig config;

    @Inject
    CurrentVertxRequest request;

    /** The caller's username, or {@value #ANONYMOUS}. */
    public String username() {
        if (identity.isAnonymous()) {
            return ANONYMOUS;
        }
        if (jwt() != null && Claims.read(jwt(), ClaimMapping.of(config.jwt()).username()) instanceof String username && !username.isEmpty()) {
            return username;
        }
        return identity.getPrincipal().getName();
    }

    /** The roles the rules see: after the hierarchy, and {@code known-roles}. */
    public Set<String> roles() {
        return identity.getRoles();
    }

    /** The caller's tenant: the claim {@code granted.jwt.tenant-claim}, or the header {@code granted.headers.tenant}. */
    public Optional<String> tenant() {
        String name = config.source() == GrantedConfig.Source.JWT ? ClaimMapping.of(config.jwt()).tenant() : config.headers().tenant();
        return claim(name, String.class);
    }

    /**
     * Any other attribute of the caller, as one value: a claim of the verified token (dotted
     * paths allowed, e.g. {@code realm_access.level}), or the header of that name.
     *
     * @param type {@code String}, {@code Long}, {@code Integer}, {@code Double}, {@code Boolean}
     *        - a number or a boolean given as a string converts - or {@code Object} for the value
     *        as found
     * @return empty when missing, or not of that type (logged, never with the value)
     */
    public <T> Optional<T> claim(String name, Class<T> type) {
        Object value = Claims.scalar(raw(name), type);
        if (value == Claims.INVALID) {
            Claims.warnInvalid(name, type, false);
            return Optional.empty();
        }
        return Optional.ofNullable(type.cast(value));
    }

    /**
     * A list: a JSON array or a comma-separated list in a header, an array in a token - a single
     * value is a list of one. The elements of the wrong type are dropped (logged).
     *
     * @return empty when missing - ready for an {@code IN (...)}
     */
    @SuppressWarnings("unchecked")
    public <T> List<T> claims(String name, Class<T> type) {
        Object values = Claims.list(raw(name), type, name);
        if (values == Claims.INVALID) {
            Claims.warnInvalid(name, type, true);
            return List.of();
        }
        return (List<T>) values;
    }

    /** {@link #claim}, or a 403 when it is missing or not of that type. */
    public <T> T requireClaim(String name, Class<T> type) {
        return claim(name, type).orElseThrow(() -> new MissingClaimException(name));
    }

    /** {@link #claims}, or a 403 when the list is missing, empty, or has no element of that type. */
    public <T> List<T> requireClaims(String name, Class<T> type) {
        List<T> values = claims(name, type);
        if (values.isEmpty()) {
            throw new MissingClaimException(name);
        }
        return values;
    }

    private Object raw(String name) {
        if (config.source() == GrantedConfig.Source.JWT) {
            return jwt() == null ? null : Claims.read(jwt(), name);
        }
        return request.getCurrent() == null ? null : request.getCurrent().request().getHeader(name);
    }

    private JsonWebToken jwt() {
        return config.source() == GrantedConfig.Source.JWT && identity.getPrincipal() instanceof JsonWebToken jwt ? jwt : null;
    }
}
