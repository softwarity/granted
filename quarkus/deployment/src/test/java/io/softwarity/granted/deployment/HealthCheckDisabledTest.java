package io.softwarity.granted.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusExtensionTest;

/** granted-jwks is not registered with granted.health.enabled=false. */
class HealthCheckDisabledTest {

    @RegisterExtension
    static final QuarkusExtensionTest app = new QuarkusExtensionTest()
            .overrideConfigKey("granted.health.enabled", "false");

    @Test
    void readiness() {
        given().get("/q/health/ready").then().statusCode(200).body("checks.name", not(hasItem("granted-jwks")));
    }
}
