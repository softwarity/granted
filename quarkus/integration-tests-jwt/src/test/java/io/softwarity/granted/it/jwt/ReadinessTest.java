package io.softwarity.granted.it.jwt;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.eclipse.microprofile.config.ConfigProvider;
import org.junit.jupiter.api.Test;

import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.common.ResourceArg;
import io.quarkus.test.junit.QuarkusTest;

/** granted-jwks: DOWN while Meerkat's JWK Set fails, UP once it answers - never more than one fetch per cooldown. */
@QuarkusTest
@QuarkusTestResource(value = CanopyIdp.class, restrictToAnnotatedClass = true, initArgs = {
        @ResourceArg(name = "jwks", value = "503"), @ResourceArg(name = "cooldown", value = "2S") })
class ReadinessTest {

    static String control(String query) {
        return ConfigProvider.getConfig().getValue("it.control", String.class) + query;
    }

    static int jwksFetches() {
        Integer fetches = given().get(control("")).then().extract().path("fetches.'/jwks'");
        return fetches == null ? 0 : fetches;
    }

    @Test
    void isDownWhileTheJwkSetFailsThenUpWithoutHammeringTheIdp() throws Exception {
        String meerkat = ConfigProvider.getConfig().getValue("it.meerkat", String.class);
        for (int i = 0; i < 15; i++) {
            given().get("/q/health/ready").then().statusCode(503)
                    .body("checks.find { it.name == 'granted-jwks' }.status", is("DOWN"))
                    .body("checks.find { it.name == 'granted-jwks' }.data.'" + meerkat + "'", is("JWK Set: HTTP 503"));
        }
        assertEquals(1, jwksFetches(), "one fetch for fifteen probes within the cooldown");
        given().get(control("?jwks=200")).then().statusCode(200);
        Thread.sleep(2_100);
        for (int i = 0; i < 15; i++) {
            given().get("/q/health/ready").then().statusCode(200)
                    .body("checks.find { it.name == 'granted-jwks' }.data.'" + meerkat + "'", is("1 keys"));
        }
        assertEquals(2, jwksFetches());
    }
}
