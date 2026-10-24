package io.softwarity.granted;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.json.Json;
import jakarta.json.JsonObjectBuilder;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.jboss.logging.Logger;
import org.jboss.logging.MDC;

/**
 * A refused request (403), logged and answered: the rule spelled as nestjs-granted names it
 * ({@code hasRole(ADMIN)}, {@code or(hasRole(A),hasRole(B))}, {@code claim(territories)}), the
 * caller, the roles it was judged on and its tenant.
 *
 * <p>The reason is always logged, at WARN: the sentence, and the fields in the MDC for that one
 * line ({@code denied.spec}, {@code denied.username}, {@code denied.roles},
 * {@code denied.tenant}, with {@code http.request.method} and {@code url.path}), for a JSON log
 * to carry as attributes. The response is nestjs-granted's bare
 * {@code {"statusCode":403,"error":"Forbidden","message":"Forbidden resource"}} unless
 * {@code granted.access-denied.details} is on: the details tell an attacker what to forge.
 *
 * <p>Shared by the exception mapper ({@code @RolesAllowed}, {@link GrantedCaller#requireClaim})
 * and the parameters ({@code @GrantedClaim(required = true)}), so a refusal reads the same
 * whatever refused.
 */
@ApplicationScoped
public class AccessDenial {

    private static final Logger LOG = Logger.getLogger(AccessDeniedMapper.class);

    @Inject
    GrantedConfig config;

    @Inject
    GrantedCaller caller;

    /** Logs why {@code method path} was refused, and builds the 403 to answer it with. */
    public Response refuse(String spec, String method, String path, String uri) {
        String username = caller.username();
        List<String> roles = List.copyOf(new TreeSet<>(caller.roles()));
        String tenant = caller.tenant().orElse(null);
        String reason = reason(spec, username, roles, tenant);
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("http.request.method", method);
        fields.put("url.path", path);
        fields.put("denied.spec", spec);
        fields.put("denied.username", username);
        fields.put("denied.roles", String.join(",", roles));
        if (tenant != null) {
            fields.put("denied.tenant", tenant);
        }
        fields.forEach(MDC::put);
        try {
            LOG.warnf("%s %s denied: %s", method, uri, reason);
        } finally {
            fields.keySet().forEach(MDC::remove);
        }

        // Written with JSON-P, which this library carries: the application may have no JSON
        // provider of its own for REST.
        JsonObjectBuilder body = Json.createObjectBuilder().add("statusCode", 403).add("error", "Forbidden");
        if (!config.accessDenied().details()) {
            body.add("message", "Forbidden resource");
        } else {
            body.add("message", "Forbidden resource: " + reason);
            JsonObjectBuilder denied = Json.createObjectBuilder().add("spec", spec).add("username", username)
                    .add("roles", Json.createArrayBuilder(roles));
            if (tenant != null) {
                denied.add("tenant", tenant);
            }
            body.add("denied", denied);
        }
        return Response.status(Response.Status.FORBIDDEN).type(MediaType.APPLICATION_JSON).entity(body.build().toString()).build();
    }

    /** {@code hasRole(ADMIN) not met by 'jdoe' (roles: USER; tenant: acme)} */
    static String reason(String spec, String username, List<String> roles, String tenant) {
        return spec + " not met by '" + username + "' (roles: " + (roles.isEmpty() ? "none" : String.join(", ", roles))
                + (tenant == null ? "" : "; tenant: " + tenant) + ")";
    }
}
