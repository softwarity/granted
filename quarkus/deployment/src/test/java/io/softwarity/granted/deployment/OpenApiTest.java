package io.softwarity.granted.deployment;

import static io.softwarity.granted.deployment.OpenApiDocument.document;
import static io.softwarity.granted.deployment.OpenApiDocument.json;
import static io.softwarity.granted.deployment.OpenApiDocument.operation;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.Set;

import jakarta.annotation.security.DenyAll;
import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import jakarta.json.JsonObject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;

import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.eclipse.microprofile.openapi.annotations.security.SecurityRequirement;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.security.Authenticated;
import io.quarkus.test.QuarkusExtensionTest;

/**
 * Each route's rule in the OpenAPI document quarkus-smallrye-openapi generates - the cases of
 * nestjs-granted's openapi.spec.ts, with Quarkus's annotations.
 */
class OpenApiTest {

    @Path("/items")
    @RolesAllowed("USER")
    public static class ItemsResource {

        @GET
        public String list() {
            return "items";
        }

        @POST
        @RolesAllowed({ "ADMIN", "MANAGER" })
        public String create() {
            return "created";
        }

        @GET
        @Path("/mine")
        @Authenticated
        public String mine() {
            return "mine";
        }

        @GET
        @Path("/public")
        @PermitAll
        public String open() {
            return "open";
        }
    }

    @Path("/users")
    public static class UsersResource {

        @GET
        @Path("/{id: \\d+}")
        @RolesAllowed({ "ADMIN", "**" })
        public String get(@PathParam("id") long id) {
            return "user";
        }

        @GET
        @RolesAllowed("**")
        public String list() {
            return "users";
        }

        @POST
        @Path("/never")
        @DenyAll
        public String never() {
            return "never";
        }

        @POST
        public String ungranted() {
            return "ungranted";
        }

        @GET
        @Path("/audit")
        @RolesAllowed("${granted-test.audit-roles}")
        public String audit() {
            return "audit";
        }

        @GET
        @Path("/runtime")
        @RolesAllowed("${granted-test.runtime-role}")
        public String runtime() {
            return "runtime";
        }
    }

    @Path("/orders")
    @RolesAllowed("ADMIN")
    public static class OrdersResource {

        @POST
        @Path("/purge")
        public void purge() {
        }

        @GET
        @Path("/{id}")
        @APIResponse(responseCode = "200", description = "The order")
        @APIResponse(responseCode = "404", description = "No such order")
        public String get(@PathParam("id") String id) {
            return "order";
        }

        @POST
        @Path("/{id}/cancel")
        @APIResponse(responseCode = "403", description = "Admins only")
        public String cancel(@PathParam("id") String id) {
            return "cancelled";
        }

        @GET
        @Path("/{id}/history")
        @SecurityRequirement(name = "apiKey")
        public String history(@PathParam("id") String id) {
            return "history";
        }
    }

    /** The JAX-RS annotations on an interface, the rule on the class implementing it. */
    @Path("/reports")
    public interface ReportsApi {

        @GET
        String list();
    }

    @RolesAllowed("AUDITOR")
    public static class ReportsResource implements ReportsApi {

        @Override
        public String list() {
            return "reports";
        }
    }

    @RegisterExtension
    static final QuarkusExtensionTest app = new QuarkusExtensionTest()
            .withApplicationRoot(jar -> jar.addClasses(ItemsResource.class, UsersResource.class, OrdersResource.class,
                    ReportsApi.class, ReportsResource.class, OpenApiDocument.class))
            .overrideConfigKey("granted-test.audit-roles", "AUDITOR,ADMIN")
            .overrideRuntimeConfigKey("granted-test.runtime-role", "OPERATOR");

    @Test
    void writesTheClassRuleOnARouteWithoutItsOwn() {
        assertEquals(json("[{\"bearer\":[\"USER\"]}]"), operation("/items", "get").get("security"));
    }

    @Test
    void theMethodRuleReplacesTheClassRule() {
        // Jakarta: not hasRole(USER) and (...) - the class's rule doesn't apply at all.
        assertEquals(json("[{\"bearer\":[\"ADMIN\"]},{\"bearer\":[\"MANAGER\"]}]"), operation("/items", "post").get("security"));
    }

    @Test
    void anAuthenticatedCallerWithoutAGivenRole() {
        assertEquals(json("[{\"bearer\":[]}]"), operation("/items/mine", "get").get("security"));
        assertEquals(json("[{\"bearer\":[]}]"), operation("/users", "get").get("security"));
        assertEquals(json("[{\"bearer\":[\"ADMIN\"]},{\"bearer\":[]}]"), operation("/users/{id}", "get").get("security"));
    }

    @Test
    void permitAllIsAnAnonymousCallerDenyAllWritesNoSecurity() {
        assertEquals(json("[{}]"), operation("/items/public", "get").get("security"));
        assertNull(operation("/users/never", "post").get("security"));
    }

    @Test
    void leavesARouteWithoutARuleAlone() {
        JsonObject ungranted = operation("/users", "post");
        assertNull(ungranted.get("security"));
        assertEquals(Set.of("200"), ungranted.getJsonObject("responses").keySet());
    }

    @Test
    void resolvesConfigExpressionsInRoles() {
        assertEquals(json("[{\"bearer\":[\"AUDITOR\"]},{\"bearer\":[\"ADMIN\"]}]"), operation("/users/audit", "get").get("security"));
        assertEquals("Forbidden unless: hasRole(AUDITOR) or hasRole(ADMIN)",
                operation("/users/audit", "get").getJsonObject("responses").getJsonObject("403").getString("description"));
        // Set only when the application starts: the document, generated before, keeps it as written.
        assertEquals(json("[{\"bearer\":[\"${granted-test.runtime-role}\"]}]"), operation("/users/runtime", "get").get("security"));
    }

    @Test
    void describesTheRuleInA403AndAnAnonymousCallerInA401() {
        JsonObject responses = operation("/items", "get").getJsonObject("responses");
        assertEquals("Forbidden unless: hasRole(USER)", responses.getJsonObject("403").getString("description"));
        assertEquals(GrantedOpenApiFilter.UNAUTHORIZED, responses.getJsonObject("401").getString("description"));
        // The success response stays.
        assertEquals("OK", responses.getJsonObject("200").getString("description"));
        assertEquals("Forbidden unless: hasRole(ADMIN) or hasRole(MANAGER)",
                operation("/items", "post").getJsonObject("responses").getJsonObject("403").getString("description"));
        assertEquals(GrantedOpenApiFilter.NOBODY,
                operation("/users/never", "post").getJsonObject("responses").getJsonObject("403").getString("description"));
    }

    @Test
    void no403WhereAnAuthenticatedCallerAlwaysGetsThrough() {
        for (String path : new String[] { "/items/mine", "/users", "/users/{id}" }) {
            JsonObject responses = operation(path, "get").getJsonObject("responses");
            // Not even smallrye-openapi's own "Not Allowed".
            assertFalse(responses.containsKey("403"), path);
            assertEquals(GrantedOpenApiFilter.UNAUTHORIZED, responses.getJsonObject("401").getString("description"), path);
        }
        JsonObject open = operation("/items/public", "get").getJsonObject("responses");
        assertFalse(open.containsKey("401"));
        assertFalse(open.containsKey("403"));
    }

    @Test
    void keepsTheResponsesAndThe403TheHostDeclared() {
        JsonObject purge = operation("/orders/purge", "post").getJsonObject("responses");
        // smallrye-openapi's own success response for a POST: kept.
        assertEquals(Set.of("201", "401", "403"), purge.keySet());
        assertEquals("Forbidden unless: hasRole(ADMIN)", purge.getJsonObject("403").getString("description"));

        JsonObject get = operation("/orders/{id}", "get").getJsonObject("responses");
        assertEquals("The order", get.getJsonObject("200").getString("description"));
        assertEquals("No such order", get.getJsonObject("404").getString("description"));
        assertEquals("Forbidden unless: hasRole(ADMIN)", get.getJsonObject("403").getString("description"));

        assertEquals(json("{\"description\":\"Admins only\"}"), operation("/orders/{id}/cancel", "post").getJsonObject("responses").get("403"));
    }

    @Test
    void keepsTheSecurityRequirementTheHostDeclared() {
        assertEquals(json("[{\"apiKey\":[]},{\"bearer\":[\"ADMIN\"]}]"), operation("/orders/{id}/history", "get").get("security"));
    }

    @Test
    void readsTheRuleOfTheClassImplementingTheResourceInterface() {
        assertEquals(json("[{\"bearer\":[\"AUDITOR\"]}]"), operation("/reports", "get").get("security"));
    }

    @Test
    void definesTheSchemeItNames() {
        assertEquals(json("{\"type\":\"http\",\"scheme\":\"bearer\"}"),
                document().getJsonObject("components").getJsonObject("securitySchemes").get("bearer"));
    }
}
