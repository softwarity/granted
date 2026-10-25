package io.softwarity.granted.deployment;

import static io.softwarity.granted.deployment.OpenApiDocument.document;
import static io.softwarity.granted.deployment.OpenApiDocument.json;
import static io.softwarity.granted.deployment.OpenApiDocument.operation;
import static org.junit.jupiter.api.Assertions.assertEquals;

import jakarta.annotation.security.RolesAllowed;
import jakarta.json.JsonObject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusExtensionTest;

/**
 * granted.openapi.security-scheme names the scheme - one the document already defines is kept as
 * it is; and an endpoint without a rule gets quarkus.security.jaxrs.default-roles-allowed, as
 * Quarkus REST applies it.
 */
class OpenApiSchemeTest {

    @Path("/items")
    public static class ItemsResource {

        @GET
        @RolesAllowed("USER")
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
            .overrideConfigKey("granted.openapi.security-scheme", "jwt")
            .overrideConfigKey("quarkus.smallrye-openapi.security-scheme", "jwt")
            .overrideConfigKey("quarkus.smallrye-openapi.security-scheme-name", "jwt")
            .overrideConfigKey("quarkus.security.jaxrs.default-roles-allowed", "MANAGER,**");

    @Test
    void writesUnderTheConfiguredSchemeName() {
        assertEquals(json("[{\"jwt\":[\"USER\"]}]"), operation("/items", "get").get("security"));
    }

    @Test
    void keepsTheSchemeTheDocumentDefines() {
        assertEquals(json("{\"description\":\"Authentication\",\"type\":\"http\",\"scheme\":\"bearer\",\"bearerFormat\":\"JWT\"}"),
                document().getJsonObject("components").getJsonObject("securitySchemes").get("jwt"));
    }

    @Test
    void anEndpointWithoutARuleGetsTheDefaultRoles() {
        JsonObject ungranted = operation("/items", "post");
        assertEquals(json("[{\"jwt\":[\"MANAGER\"]},{\"jwt\":[]}]"), ungranted.get("security"));
        assertEquals(GrantedOpenApiFilter.UNAUTHORIZED, ungranted.getJsonObject("responses").getJsonObject("401").getString("description"));
    }
}
