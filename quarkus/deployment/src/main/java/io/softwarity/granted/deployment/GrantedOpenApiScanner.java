package io.softwarity.granted.deployment;

import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.eclipse.microprofile.config.Config;
import org.jboss.jandex.AnnotationInstance;
import org.jboss.jandex.AnnotationTarget;
import org.jboss.jandex.AnnotationValue;
import org.jboss.jandex.ClassInfo;
import org.jboss.jandex.DotName;
import org.jboss.jandex.IndexView;
import org.jboss.jandex.MethodInfo;

import io.quarkus.security.spi.SecurityTransformer;
import io.smallrye.common.expression.Expression;
import io.smallrye.config.common.utils.StringUtil;
import io.softwarity.granted.deployment.GrantedOpenApiFilter.Access;
import io.softwarity.granted.deployment.GrantedOpenApiFilter.Route;

/**
 * The access rule of each JAX-RS route, read at build time from the annotations Quarkus enforces,
 * with Jakarta semantics: the method's annotation replaces the class's, never combined with it.
 * Keyed by HTTP method and path as smallrye-openapi writes them in the document - the context
 * root, the {@code @ApplicationPath} or {@code quarkus.rest.path}, the class's and the method's
 * {@code @Path}, a template's regular expression left out.
 *
 * <p>Left alone: a route whose rule is another (a {@code @PermissionsAllowed}, an authorization
 * policy), a route without a rule - unless {@code quarkus.security.jaxrs.deny-unannotated-endpoints}
 * or {@code default-roles-allowed} gives it one, as Quarkus does - the methods of a sub-resource,
 * and a path several methods with different rules answer.
 */
final class GrantedOpenApiScanner {

    private static final DotName PATH = DotName.createSimple("jakarta.ws.rs.Path");
    private static final DotName APPLICATION = DotName.createSimple("jakarta.ws.rs.core.Application");
    private static final DotName APPLICATION_PATH = DotName.createSimple("jakarta.ws.rs.ApplicationPath");
    private static final DotName OBJECT = DotName.createSimple(Object.class);
    private static final List<String> HTTP_METHODS = List.of("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS");

    private static final DotName ROLES_ALLOWED = DotName.createSimple("jakarta.annotation.security.RolesAllowed");
    private static final DotName PERMIT_ALL = DotName.createSimple("jakarta.annotation.security.PermitAll");
    private static final DotName DENY_ALL = DotName.createSimple("jakarta.annotation.security.DenyAll");
    private static final DotName AUTHENTICATED = DotName.createSimple("io.quarkus.security.Authenticated");

    private static final String OPENAPI = "org.eclipse.microprofile.openapi.annotations.";
    private static final List<DotName> SECURITY_REQUIREMENTS = Stream.of("SecurityRequirement", "SecurityRequirements",
            "SecurityRequirementsSet", "SecurityRequirementsSets")
            .map(name -> DotName.createSimple(OPENAPI + "security." + name)).toList();
    private static final DotName API_RESPONSE = DotName.createSimple(OPENAPI + "responses.APIResponse");
    private static final DotName API_RESPONSES = DotName.createSimple(OPENAPI + "responses.APIResponses");

    /** {@code {id: \d+}}: smallrye-openapi writes {@code {id}}. Its own pattern. */
    private static final Pattern TEMPLATE_REGEX = Pattern
            .compile("\\{[ \\t]*(\\w[\\w\\.-]*)[ \\t]*:[ \\t]*((?:[^{}]|\\{[^{}]+\\})+)\\}");

    private final IndexView index;
    private final SecurityTransformer security;
    private final Function<String[], List<String>> roles;
    private final Access unannotated;

    /**
     * @param roles the roles of a {@code @RolesAllowed}, its config expressions resolved
     * @param unannotated what a route without a rule is given, or {@code null}
     */
    GrantedOpenApiScanner(IndexView index, SecurityTransformer security, Function<String[], List<String>> roles, Access unannotated) {
        this.index = index;
        this.security = security;
        this.roles = roles;
        this.unannotated = unannotated;
    }

    /** {@code GET /api/items/{id}}: how a route is found in the document. */
    static String key(String httpMethod, String path) {
        String normalized = TEMPLATE_REGEX.matcher(path).replaceAll("{$1}").replaceAll("/{2,}", "/");
        if (normalized.length() > 1 && normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return httpMethod + " " + normalized;
    }

    /** The routes, by {@link #key}. {@code rootPath}: quarkus.http.root-path; {@code restPath}: quarkus.rest.path. */
    Map<String, Route> scan(String rootPath, String restPath) {
        // As smallrye-openapi resolves it: an @ApplicationPath replaces quarkus.rest.path.
        String prefix = index.getAllKnownSubclasses(APPLICATION).stream()
                .map(application -> application.declaredAnnotation(APPLICATION_PATH))
                .filter(Objects::nonNull)
                .map(path -> join(rootPath, path.value().asString()))
                .findFirst()
                .orElseGet(() -> join(rootPath, restPath));
        Map<String, Route> routes = new HashMap<>();
        Set<String> ambiguous = new HashSet<>();
        for (AnnotationInstance path : index.getAnnotations(PATH)) {
            if (path.target().kind() != AnnotationTarget.Kind.CLASS) {
                continue;
            }
            ClassInfo resource = path.target().asClass();
            String base = join(prefix, path.value().asString());
            List<ClassInfo> endpoints = endpoints(resource);
            Set<ClassInfo> scanned = hierarchy(resource);
            for (ClassInfo declaring : scanned) {
                for (MethodInfo method : declaring.methods()) {
                    String httpMethod = httpMethod(method);
                    if (httpMethod == null) {
                        continue;
                    }
                    AnnotationInstance methodPath = method.declaredAnnotation(PATH);
                    String key = key(httpMethod, join(base, methodPath == null ? "" : methodPath.value().asString()));
                    for (ClassInfo endpoint : endpoints) {
                        MethodInfo implementation = implementation(endpoint, method);
                        // An override that is a resource method itself is described as one.
                        if (!implementation.equals(method) && httpMethod(implementation) != null && scanned.contains(implementation.declaringClass())) {
                            continue;
                        }
                        Route route = route(method, implementation);
                        if (route == null) {
                            ambiguous.add(key);
                        } else if (routes.putIfAbsent(key, route) != null && !routes.get(key).equals(route)) {
                            ambiguous.add(key);
                        }
                    }
                }
            }
        }
        ambiguous.forEach(routes::remove);
        return routes;
    }

    /** The rule Quarkus applies to {@code implementation} - reached through {@code method} - and what the host declared. */
    private Route route(MethodInfo method, MethodInfo implementation) {
        Optional<AnnotationInstance> annotation = security.findFirstSecurityAnnotation(implementation)
                .or(() -> security.findFirstSecurityAnnotation(method))
                .or(() -> security.findFirstSecurityAnnotation(implementation.declaringClass()))
                .or(() -> security.findFirstSecurityAnnotation(method.declaringClass()));
        Access access = annotation.map(this::access).orElse(unannotated);
        if (access == null) {
            return null;
        }
        List<AnnotationTarget> targets = List.of(implementation, method, implementation.declaringClass(), method.declaringClass());
        boolean declaredSecurity = targets.stream().anyMatch(target -> SECURITY_REQUIREMENTS.stream().anyMatch(name -> declared(target, name) != null));
        Set<String> declaredResponses = new HashSet<>();
        for (AnnotationTarget target : targets) {
            AnnotationInstance response = declared(target, API_RESPONSE);
            if (response != null) {
                declaredResponses.add(responseCode(response));
            }
            AnnotationInstance responses = declared(target, API_RESPONSES);
            AnnotationValue value = responses == null ? null : responses.value();
            if (value != null) {
                Arrays.stream(value.asNestedArray()).map(GrantedOpenApiScanner::responseCode).forEach(declaredResponses::add);
            }
        }
        return new Route(access, declaredSecurity, Set.copyOf(declaredResponses));
    }

    /** Another rule than these four - a @PermissionsAllowed, a policy - is not granted's to describe: {@code null}. */
    private Access access(AnnotationInstance annotation) {
        DotName name = annotation.name();
        if (name.equals(DENY_ALL)) {
            return Access.denyAll();
        }
        if (name.equals(PERMIT_ALL)) {
            return Access.permitAll();
        }
        if (name.equals(AUTHENTICATED)) {
            return Access.authenticated();
        }
        if (name.equals(ROLES_ALLOWED)) {
            AnnotationValue value = annotation.value();
            return Access.rolesAllowed(roles.apply(value == null ? new String[0] : value.asStringArray()));
        }
        return null;
    }

    /**
     * {@code @RolesAllowed("${admin-role}")}: resolved with the configuration the application is
     * built with, a comma-separated value giving several roles - as Quarkus does at startup. An
     * expression without a value at build time is kept as written.
     */
    static List<String> resolve(String[] values, Config config) {
        List<String> roles = new ArrayList<>();
        for (String value : values) {
            if (!value.contains("${")) {
                roles.add(value);
                continue;
            }
            try {
                String resolved = Expression.compile(value).evaluate((context, builder) -> {
                    Optional<String> property = config.getOptionalValue(context.getKey(), String.class);
                    if (property.isPresent()) {
                        builder.append(property.get());
                    } else if (context.hasDefault()) {
                        context.expandDefault();
                    } else {
                        throw new IllegalStateException(context.getKey());
                    }
                });
                Arrays.stream(StringUtil.split(resolved)).map(String::trim).filter(role -> !role.isEmpty()).forEach(roles::add);
            } catch (RuntimeException unresolved) {
                roles.add(value);
            }
        }
        return roles;
    }

    /** The concrete classes serving {@code resource}: itself, or what implements or extends it. */
    private List<ClassInfo> endpoints(ClassInfo resource) {
        if (concrete(resource)) {
            return List.of(resource);
        }
        Set<ClassInfo> candidates = new LinkedHashSet<>(resource.isInterface() ? index.getAllKnownImplementations(resource.name())
                : index.getAllKnownSubclasses(resource.name()));
        return candidates.stream().filter(GrantedOpenApiScanner::concrete).toList();
    }

    /** The classes whose methods smallrye-openapi describes for {@code resource}: its superclasses and their interfaces. */
    private Set<ClassInfo> hierarchy(ClassInfo resource) {
        Set<ClassInfo> classes = new LinkedHashSet<>();
        for (ClassInfo current = resource; current != null; current = superclass(current)) {
            classes.add(current);
            current.interfaceNames().stream().map(index::getClassByName).filter(Objects::nonNull).forEach(classes::add);
        }
        return classes;
    }

    /** The method {@code endpoint} runs for {@code method}: the most specific concrete one of its superclasses. */
    private MethodInfo implementation(ClassInfo endpoint, MethodInfo method) {
        for (ClassInfo current = endpoint; current != null; current = superclass(current)) {
            MethodInfo candidate = current.method(method.name(), method.parameterTypes());
            if (candidate != null && !Modifier.isAbstract(candidate.flags())) {
                return candidate;
            }
        }
        return method;
    }

    /** {@code null} past the last class of the application's: Object, or a class outside the index. */
    private ClassInfo superclass(ClassInfo clazz) {
        DotName name = clazz.superName();
        return name == null || name.equals(OBJECT) ? null : index.getClassByName(name);
    }

    private static String httpMethod(MethodInfo method) {
        return HTTP_METHODS.stream().filter(name -> method.hasDeclaredAnnotation(DotName.createSimple("jakarta.ws.rs." + name)))
                .findFirst().orElse(null);
    }

    private static boolean concrete(ClassInfo clazz) {
        return !clazz.isInterface() && !Modifier.isAbstract(clazz.flags());
    }

    private static AnnotationInstance declared(AnnotationTarget target, DotName name) {
        return target.kind() == AnnotationTarget.Kind.METHOD ? target.asMethod().declaredAnnotation(name)
                : target.asClass().declaredAnnotation(name);
    }

    private static String responseCode(AnnotationInstance response) {
        AnnotationValue code = response.value("responseCode");
        return code == null ? "default" : code.asString();
    }

    /** Segments joined as smallrye-openapi joins them: each stripped of its leading and trailing slash. */
    static String join(String... segments) {
        return "/" + Arrays.stream(segments)
                .filter(Objects::nonNull)
                .map(segment -> segment.replaceAll("^/+|/+$", ""))
                .filter(segment -> !segment.isEmpty())
                .collect(Collectors.joining("/"));
    }
}
