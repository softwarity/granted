package io.softwarity.granted.deployment;

import static io.softwarity.granted.deployment.OpenApiDocument.json;
import static io.softwarity.granted.deployment.OpenApiDocument.operation;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import jakarta.annotation.security.PermitAll;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusExtensionTest;

/** quarkus.security.jaxrs.deny-unannotated-endpoints: an endpoint without a rule reads as @DenyAll - before default-roles-allowed, as Quarkus REST applies them. */
class OpenApiDenyUnannotatedTest {

    @Path("/items")
    public static class ItemsResource {

        @GET
        @PermitAll
        public String list() {
            return "items";
        }

        @POST
        public String ungranted() {
            return "ungranted";
        }
    }

    @RegisterExtension
    static final QuarkusExtensionTest app = new QuarkusExtensionTest()
            .withApplicationRoot(jar -> jar.addClasses(ItemsResource.class, OpenApiDocument.class))
            .overrideConfigKey("quarkus.security.jaxrs.deny-unannotated-endpoints", "true")
            .overrideConfigKey("quarkus.security.jaxrs.default-roles-allowed", "USER");

    @Test
    void anEndpointWithoutARuleIsDenied() {
        assertEquals(json("[{}]"), operation("/items", "get").get("security"));
        assertNull(operation("/items", "post").get("security"));
        assertEquals(GrantedOpenApiFilter.NOBODY, operation("/items", "post").getJsonObject("responses").getJsonObject("403").getString("description"));
    }
}
