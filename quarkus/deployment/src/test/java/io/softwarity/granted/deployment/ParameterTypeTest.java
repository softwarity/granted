package io.softwarity.granted.deployment;

import static org.junit.jupiter.api.Assertions.fail;

import java.util.Map;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusExtensionTest;
import io.softwarity.granted.GrantedClaim;

/** A parameter of a type the annotation can't fill fails the build - never a request. */
class ParameterTypeTest {

    @Path("/wrong")
    public static class WrongResource {

        @GET
        public String wrong(@GrantedClaim("territories") Map<String, String> territories) {
            return "unreachable";
        }
    }

    @RegisterExtension
    static final QuarkusExtensionTest app = new QuarkusExtensionTest()
            .withApplicationRoot(jar -> jar.addClass(WrongResource.class))
            .assertException(StartupRefusalTest.refusal("@GrantedClaim(\"territories\") can't fill a parameter of type java.util.Map"));

    @Test
    void failsTheBuild() {
        fail("the build should have failed");
    }
}
