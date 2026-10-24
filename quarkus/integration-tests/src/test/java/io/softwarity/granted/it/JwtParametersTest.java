package io.softwarity.granted.it;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import io.smallrye.jwt.build.Jwt;
import io.smallrye.jwt.build.JwtClaimsBuilder;

/** The annotated parameters, the caller from a verified JWT: never from a header. */
@QuarkusTest
@TestProfile(JwtProfile.class)
class JwtParametersTest {

    private static JwtClaimsBuilder token(String username, String... roles) {
        return Jwt.subject("id-" + username).claim("preferred_username", username).claim("realm_access", Map.of("roles", List.of(roles)));
    }

    @Test
    void injectsTheCallerFromTheToken() {
        given().auth().oauth2(token("alice", "ADMIN").claim("tenant", "meteo-france").sign()).get("/params/me").then()
                .body("username", is("alice")).body("roles", contains("ADMIN", "MANAGER", "USER")).body("tenant", is("meteo-france"));
    }

    @Test
    void neverInjectsAHeader() {
        given().header("username", "mallory").header("tenant", "evil").get("/params/me").then()
                .body("username", is("anonymous")).body("tenant", nullValue());
        given().auth().oauth2(token("alice", "USER").sign()).header("username", "mallory").header("tenant", "evil")
                .header("maxAmount", "999").header("territories", "FR").get("/params/types").then()
                .body("maxAmount", nullValue()).body("territorySet", empty());
        given().auth().oauth2(token("alice", "USER").sign()).header("territories", "FR").get("/params/required").then().statusCode(403);
    }

    @Test
    void convertsTheClaimsByTheParameterType() {
        String jwt = token("alice", "USER").claim("maxAmount", 5000).claim("rank", "3").claim("auditor", true)
                .claim("codes", List.of(1, "two", "3")).claim("territories", List.of("FR", 42, "GP")).claim("level", "gold").sign();
        given().auth().oauth2(jwt).get("/params/types").then().statusCode(200)
                .body("maxAmount", is(5000)).body("rank", is(3)).body("auditor", is(true))
                .body("codes", contains(1, 3)).body("territorySet", contains("FR", "GP")).body("level", is("gold"));
    }

    @Test
    void aRequiredClaimMissingOrInvalidIsA403() {
        given().auth().oauth2(token("alice", "USER").sign()).get("/params/required").then().statusCode(403);
        given().auth().oauth2(token("alice", "USER").claim("territories", List.of(41, 42)).sign()).get("/params/required").then()
                .statusCode(403);
        given().auth().oauth2(token("alice", "USER").claim("territories", "FR").sign()).get("/params/required").then()
                .statusCode(200).body("$", contains("FR"));
    }

    @Test
    void readsEachRequestItsOwnCaller() {
        String alice = token("alice", "FORECASTER").claim("territories", List.of("FR")).sign();
        String bob = token("bob", "FORECASTER").claim("territories", List.of("GP", "MQ")).sign();
        for (int i = 0; i < 3; i++) {
            given().auth().oauth2(alice).get("/params/stations").then().body("$", contains("FR"));
            given().auth().oauth2(bob).get("/params/stations").then().body("$", contains("GP", "MQ"));
            given().auth().oauth2(bob).get("/params/me").then().body("username", is("bob"));
        }
    }
}
