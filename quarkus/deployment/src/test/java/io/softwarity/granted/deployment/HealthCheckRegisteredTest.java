package io.softwarity.granted.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.is;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusExtensionTest;

/** granted-jwks is registered when quarkus-smallrye-health is there - UP in headers mode, where nothing is fetched. */
class HealthCheckRegisteredTest {

    @RegisterExtension
    static final QuarkusExtensionTest app = new QuarkusExtensionTest();

    @Test
    void readiness() {
        given().get("/q/health/ready").then().statusCode(200).body("checks.name", hasItem("granted-jwks")).body("checks.find { it.name == 'granted-jwks' }.data.verification", is("gateway headers: nothing to fetch"));
    }
}
