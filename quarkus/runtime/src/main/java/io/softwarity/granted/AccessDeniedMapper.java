package io.softwarity.granted;

import java.lang.reflect.AnnotatedElement;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import jakarta.annotation.security.DenyAll;
import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.ws.rs.container.ResourceInfo;
import jakarta.ws.rs.core.Response;

import org.jboss.resteasy.reactive.server.ServerExceptionMapper;

import io.quarkus.security.Authenticated;
import io.quarkus.security.ForbiddenException;
import io.vertx.core.http.HttpServerRequest;

/**
 * Says why a request was refused (403: authenticated, not authorized). Quarkus answers a bare
 * 403 and the reason is lost; here it is rebuilt from what decided - the endpoint's
 * {@code @RolesAllowed}, or the claim the code required - and handed to {@link AccessDenial},
 * which logs it and answers.
 */
public class AccessDeniedMapper {

    @Inject
    AccessDenial denial;

    @ServerExceptionMapper
    public Response deny(ForbiddenException exception, ResourceInfo resource, HttpServerRequest request) {
        String spec = exception instanceof MissingClaimException missing ? "claim(" + missing.claim() + ")" : deniedSpec(resource);
        return denial.refuse(spec, request.method().name(), request.path(), request.uri());
    }

    /**
     * What the endpoint requires, the method's annotation first (it overrides the class's):
     * {@code hasRole(R)}, {@code or(hasRole(A),hasRole(B))}, {@code isAuthenticated()},
     * {@code isFalse()} for {@code @DenyAll}.
     */
    static String deniedSpec(ResourceInfo resource) {
        String spec = resource == null ? null : spec(resource.getResourceMethod());
        if (spec == null && resource != null) {
            spec = spec(resource.getResourceClass());
        }
        return spec == null ? "a security check" : spec;
    }

    private static String spec(AnnotatedElement element) {
        if (element == null) {
            return null;
        }
        if (element.isAnnotationPresent(DenyAll.class)) {
            return "isFalse()";
        }
        RolesAllowed allowed = element.getAnnotation(RolesAllowed.class);
        if (allowed != null) {
            List<String> specs = Arrays.stream(allowed.value())
                    .map(role -> "**".equals(role) ? "isAuthenticated()" : "hasRole(" + role + ")")
                    .toList();
            return specs.size() == 1 ? specs.get(0) : specs.stream().collect(Collectors.joining(",", "or(", ")"));
        }
        if (element.isAnnotationPresent(Authenticated.class)) {
            return "isAuthenticated()";
        }
        return null;
    }
}
