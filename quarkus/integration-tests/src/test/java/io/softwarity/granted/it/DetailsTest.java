package io.softwarity.granted.it;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.is;

import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;

/** granted.access-denied.details=true: the reason of a refusal in the response, spelled as nestjs-granted names its rules. */
@QuarkusTest
@TestProfile(DetailsProfile.class)
class DetailsTest {

    @Test
    void saysWhichRuleRefusedTheCaller() {
        given().header("username", "bob").header("roles", "USER").header("tenant", "acme").get("/test/admin").then().statusCode(403)
                .body("message", is("Forbidden resource: hasRole(ADMIN) not met by 'bob' (roles: USER; tenant: acme)"))
                .body("denied.spec", is("hasRole(ADMIN)"))
                .body("denied.username", is("bob"))
                .body("denied.roles", contains("USER"))
                .body("denied.tenant", is("acme"));
    }

    @Test
    void spellsSeveralRolesAsAnOr() {
        given().header("username", "bob").header("roles", "USER").get("/test/either").then().statusCode(403)
                .body("denied.spec", is("or(hasRole(ADMIN),hasRole(AUDITOR))"));
    }

    @Test
    void spellsDenyAllAsIsFalse() {
        given().header("username", "alice").header("roles", "ADMIN").get("/test/nobody").then().statusCode(403)
                .body("denied.spec", is("isFalse()"))
                .body("denied.roles", contains("ADMIN", "MANAGER", "USER"));
    }

    @Test
    void namesTheMissingClaim() {
        given().header("username", "alice").header("roles", "USER").get("/test/required").then().statusCode(403)
                .body("denied.spec", is("claim(territories)"));
    }
}
