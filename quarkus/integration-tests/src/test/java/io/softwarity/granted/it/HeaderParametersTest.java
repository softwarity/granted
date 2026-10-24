package io.softwarity.granted.it;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;

/** The annotated parameters, the caller from the gateway's headers. */
@QuarkusTest
class HeaderParametersTest {

    @Test
    void injectsTheCaller() {
        given().header("username", "alice").header("roles", "ADMIN").header("tenant", "meteo-france").get("/params/me").then()
                .statusCode(200)
                .body("username", is("alice"))
                .body("roles", contains("ADMIN", "MANAGER", "USER"))
                .body("roleCount", is(3))
                .body("tenant", is("meteo-france"));
        given().get("/params/me").then().body("username", is("anonymous")).body("roles", empty()).body("tenant", nullValue());
    }

    @Test
    void injectsAClaimForTheRuleItScopes() {
        given().header("username", "alice").header("roles", "FORECASTER").header("territories", "FR, GP").get("/params/stations").then()
                .statusCode(200).body("$", contains("FR", "GP"));
        given().header("username", "alice").header("roles", "FORECASTER").get("/params/stations").then().statusCode(200).body("$", empty());
        given().header("username", "bob").header("roles", "USER").header("territories", "FR").get("/params/stations").then().statusCode(403);
    }

    @Test
    void convertsByTheParameterType() {
        given().header("maxAmount", "5000").header("rank", "3").header("ratio", "0.5").header("auditor", "true")
                .header("codes", "[1, \"two\", 3]").header("territories", "[\"FR\",\"GP\",\"FR\"]").header("level", "gold")
                .get("/params/types").then().statusCode(200)
                .body("maxAmount", is(5000))
                .body("rank", is(3))
                .body("ratio", is(0.5f))
                .body("auditor", is(true))
                .body("codes", contains(1, 3))
                .body("territorySet", contains("FR", "GP"))
                .body("level", is("gold"));
        given().header("maxAmount", "a-lot").header("rank", "2.5").get("/params/types").then().statusCode(200)
                .body("maxAmount", nullValue()).body("rank", nullValue()).body("codes", empty()).body("territorySet", empty());
    }

    @Test
    void aRequiredClaimMissingIsA403() {
        given().get("/params/required").then().statusCode(403).body("message", is("Forbidden resource"));
        given().header("territories", "41").get("/params/required").then().statusCode(200).body("$", contains("41"));
        given().header("territories", "FR").get("/params/required").then().statusCode(200).body("$", contains("FR"));
        given().get("/params/primitive").then().statusCode(403);
        given().header("maxAmount", "7").get("/params/primitive").then().statusCode(200).body(is("7"));
    }

    @Test
    void readsEachRequestItsOwnCaller() {
        // The resource is a singleton: nothing of a request may stay for the next one.
        for (int i = 0; i < 3; i++) {
            given().header("username", "alice").header("territories", "FR").get("/params/me").then().body("username", is("alice"));
            given().header("username", "bob").header("territories", "GP").header("roles", "FORECASTER").get("/params/stations").then()
                    .body("$", contains("GP"));
            given().get("/params/me").then().body("username", is("anonymous"));
        }
    }
}
