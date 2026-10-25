package io.softwarity.granted.deployment;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import org.eclipse.microprofile.openapi.OASFactory;
import org.eclipse.microprofile.openapi.OASFilter;
import org.eclipse.microprofile.openapi.models.OpenAPI;
import org.eclipse.microprofile.openapi.models.Operation;
import org.eclipse.microprofile.openapi.models.PathItem;
import org.eclipse.microprofile.openapi.models.responses.APIResponses;
import org.eclipse.microprofile.openapi.models.security.SecurityRequirement;
import org.eclipse.microprofile.openapi.models.security.SecurityScheme;

/**
 * Each route's access rule in the OpenAPI document, as nestjs-granted writes its {@code @GrantedTo}:
 *
 * <ul>
 * <li>{@code security}: the entries are alternatives ({@code or}), the roles of one entry are all
 * required ({@code and}). {@code @RolesAllowed({"A", "B"})} gives {@code [{bearer: [A]}, {bearer: [B]}]};
 * an authenticated caller without a given role ({@code @Authenticated}, {@code "**"}) gives
 * {@code {bearer: []}}; {@code @PermitAll} gives {@code {}}; {@code @DenyAll} writes none.</li>
 * <li>a {@code 403}, the rule in clear - {@code Forbidden unless: hasRole(A) or hasRole(B)} - when an
 * authenticated caller can be refused; and a {@code 401} when an anonymous one is, as Quarkus
 * answers it.</li>
 * </ul>
 *
 * <p>What the host declared itself stays: a {@code @SecurityRequirement} is kept, granted's entries
 * added after it; a {@code 401} or {@code 403} of an {@code @APIResponse} is kept unchanged. What
 * smallrye-openapi added on its own from the same annotations - its security requirement, its
 * {@code 401 Not Authorized} and {@code 403 Not Allowed} - is replaced: it doesn't tell the
 * alternatives apart, and this filter runs after it.
 *
 * <p>Built and run when the application is built: the routes come from {@link GrantedOpenApiScanner},
 * keyed by HTTP method and path as smallrye-openapi writes them.
 */
final class GrantedOpenApiFilter implements OASFilter {

    static final String UNAUTHORIZED = "Unauthorized: no authenticated caller";
    static final String NOBODY = "Forbidden: nobody may call this route";

    /**
     * What a route lets through: anonymous callers, or the alternatives - each the roles it
     * requires, none for any authenticated caller; and the 403 that tells the rule, if an
     * authenticated caller can be refused.
     */
    record Access(boolean anonymous, List<List<String>> alternatives, String forbidden) {

        static Access permitAll() {
            return new Access(true, List.of(), null);
        }

        static Access authenticated() {
            return new Access(false, List.of(List.of()), null);
        }

        static Access denyAll() {
            return new Access(false, List.of(), NOBODY);
        }

        /** {@code **} is any authenticated caller - and with it, an authenticated caller always passes. */
        static Access rolesAllowed(List<String> roles) {
            if (roles.isEmpty()) {
                return denyAll();
            }
            List<List<String>> alternatives = roles.stream().distinct()
                    .map(role -> "**".equals(role) ? List.<String> of() : List.of(role))
                    .distinct()
                    .toList();
            String forbidden = roles.contains("**") ? null
                    : roles.stream().distinct().map(role -> "hasRole(" + role + ")").collect(Collectors.joining(" or ", "Forbidden unless: ", ""));
            return new Access(false, alternatives, forbidden);
        }
    }

    /** A route's access, and what the host declared on it: a security requirement, the response codes. */
    record Route(Access access, boolean declaredSecurity, Set<String> declaredResponses) {
    }

    private final Map<String, Route> routes;
    private final String scheme;

    GrantedOpenApiFilter(Map<String, Route> routes, String scheme) {
        this.routes = Map.copyOf(routes);
        this.scheme = scheme;
    }

    @Override
    public void filterOpenAPI(OpenAPI openAPI) {
        if (openAPI.getPaths() == null || openAPI.getPaths().getPathItems() == null) {
            return;
        }
        boolean named = false;
        for (Map.Entry<String, PathItem> path : openAPI.getPaths().getPathItems().entrySet()) {
            Map<PathItem.HttpMethod, Operation> operations = path.getValue().getOperations();
            if (operations == null) {
                continue;
            }
            for (Map.Entry<PathItem.HttpMethod, Operation> operation : operations.entrySet()) {
                Route route = routes.get(GrantedOpenApiScanner.key(operation.getKey().name(), path.getKey()));
                if (route != null) {
                    named |= writeSecurity(operation.getValue(), route);
                    writeResponses(operation.getValue(), route);
                }
            }
        }
        if (named) {
            defineScheme(openAPI);
        }
    }

    /** Writes the route's requirements; whether one names the scheme. */
    private boolean writeSecurity(Operation operation, Route route) {
        List<SecurityRequirement> requirements = new ArrayList<>();
        if (route.access().anonymous()) {
            requirements.add(OASFactory.createSecurityRequirement());
        }
        route.access().alternatives()
                .forEach(roles -> requirements.add(OASFactory.createSecurityRequirement().addScheme(scheme, new ArrayList<>(roles))));
        // The host's own requirements stay, granted's after them; smallrye-openapi's automatic one goes.
        List<SecurityRequirement> security = new ArrayList<>();
        if (route.declaredSecurity() && operation.getSecurity() != null) {
            security.addAll(operation.getSecurity());
        }
        for (SecurityRequirement requirement : requirements) {
            if (security.stream().noneMatch(existing -> Objects.equals(existing.getSchemes(), requirement.getSchemes()))) {
                security.add(requirement);
            }
        }
        // An empty `security` would mean "no security": nothing granted (@DenyAll) writes nothing.
        operation.setSecurity(security.isEmpty() ? null : security);
        return !route.access().alternatives().isEmpty();
    }

    private void writeResponses(Operation operation, Route route) {
        APIResponses responses = operation.getResponses();
        if (responses == null) {
            responses = OASFactory.createAPIResponses();
            operation.setResponses(responses);
        }
        Access access = route.access();
        // A 401 or 403 the host declared wins; smallrye-openapi's own is replaced, or removed where it can't happen.
        write(responses, route, "401", access.anonymous() ? null : UNAUTHORIZED);
        write(responses, route, "403", access.forbidden());
    }

    private static void write(APIResponses responses, Route route, String status, String description) {
        if (route.declaredResponses().contains(status)) {
            return;
        }
        if (description != null) {
            responses.addAPIResponse(status, OASFactory.createAPIResponse().description(description));
        } else {
            responses.removeAPIResponse(status);
        }
    }

    /** The scheme the requirements name, unless the document defines it: a bearer token. */
    private void defineScheme(OpenAPI openAPI) {
        if (openAPI.getComponents() == null) {
            openAPI.setComponents(OASFactory.createComponents());
        }
        Map<String, SecurityScheme> schemes = openAPI.getComponents().getSecuritySchemes();
        if (schemes == null || !schemes.containsKey(scheme)) {
            openAPI.getComponents().addSecurityScheme(scheme,
                    OASFactory.createSecurityScheme().type(SecurityScheme.Type.HTTP).scheme("bearer"));
        }
    }
}
