package io.softwarity.granted.it;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;

import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.specification.RequestSpecification;

/** The caller from the gateway's headers - granted.source=headers, the default. */
@QuarkusTest
class HeaderModeTest {

    private static RequestSpecification as(String username, String roles) {
        return given().header("username", username).header("roles", roles);
    }

    @Test
    void readsTheCallerFromTheHeaders() {
        as("alice", "[\"ADMIN\"]").header("tenant", "meteo-france").get("/test/whoami").then().statusCode(200)
                .body("username", is("alice"))
                .body("roles", contains("ADMIN", "MANAGER", "USER"))
                .body("tenant", is("meteo-france"));
    }

    @Test
    void readsTheRolesAsAJsonArrayOrAsACommaSeparatedList() {
        as("alice", "[\"AUDITOR\",\"USER\"]").get("/test/whoami").then().body("roles", contains("AUDITOR", "USER"));
        as("alice", " AUDITOR , USER ").get("/test/whoami").then().body("roles", contains("AUDITOR", "USER"));
    }

    @Test
    void aMalformedRolesHeaderGivesNoRole() {
        as("alice", "[\"ADMIN\",").get("/test/whoami").then().statusCode(200).body("roles", empty());
    }

    @Test
    void expandsTheHierarchyForTheRulesToo() {
        as("alice", "ADMIN").get("/test/user").then().statusCode(200);
        as("bob", "USER").get("/test/user").then().statusCode(200);
        as("bob", "USER").get("/test/admin").then().statusCode(403);
    }

    @Test
    void anonymousWithoutAUsernameHeader() {
        given().get("/test/whoami").then().statusCode(200).body("username", is("anonymous")).body("roles", empty());
        given().header("roles", "ADMIN").get("/test/admin").then().statusCode(401);
    }

    @Test
    void answersABare403ByDefault() {
        as("bob", "USER").get("/test/admin").then().statusCode(403)
                .body("statusCode", is(403))
                .body("error", is("Forbidden"))
                .body("message", is("Forbidden resource"))
                .body("denied", nullValue());
    }

    @Test
    void readsAnyOtherClaimFromItsHeader() {
        given().header("territories", "[\"FR\",\"GP\"]").get("/test/territories").then().body("$", contains("FR", "GP"));
        given().header("territories", "FR, GP").get("/test/territories").then().body("$", contains("FR", "GP"));
        given().header("codes", "1, two, 3").get("/test/codes").then().body("$", contains(1, 3));
        given().header("maxAmount", "5000").header("auditor", "false").get("/test/claims").then()
                .body("maxAmount", is(5000)).body("auditor", is(false));
        given().header("maxAmount", "a-lot").header("auditor", "yes").get("/test/claims").then()
                .body("maxAmount", is("-")).body("auditor", is("-"));
    }

    @Test
    void anAbsentListIsEmpty() {
        given().get("/test/territories").then().statusCode(200).body("$", empty());
    }

    @Test
    void aRequiredClaimMissingIsA403() {
        as("alice", "USER").get("/test/required").then().statusCode(403);
        as("alice", "USER").header("territories", "FR").get("/test/required").then().statusCode(200).body("$", contains("FR"));
        as("alice", "USER").header("territories", "").get("/test/required").then().statusCode(403).body("message", not("FR"));
    }
}
