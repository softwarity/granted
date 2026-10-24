package io.softwarity.granted.it;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import io.smallrye.jwt.build.Jwt;
import io.smallrye.jwt.build.JwtClaimsBuilder;

/** The caller from a JWT smallrye-jwt verified: claims mapped by path, headers never read. */
@QuarkusTest
@TestProfile(JwtProfile.class)
class JwtModeTest {

    private static JwtClaimsBuilder token(String username, String... roles) {
        return Jwt.subject("id-" + username).claim("preferred_username", username).claim("realm_access", Map.of("roles", List.of(roles)));
    }

    @Test
    void mapsTheCallerFromTheClaims() {
        given().auth().oauth2(token("alice", "ADMIN", "OTHER_APP").claim("tenant", "meteo-france").sign()).get("/test/whoami").then()
                .statusCode(200)
                .body("username", is("alice"))
                // OTHER_APP isn't one of the known roles.
                .body("roles", contains("ADMIN", "MANAGER", "USER"))
                .body("tenant", is("meteo-france"));
    }

    @Test
    void splitsARolesClaimGivenAsAString() {
        String token = Jwt.subject("alice").claim("realm_access", Map.of("roles", "AUDITOR, USER")).sign();
        given().auth().oauth2(token).get("/test/whoami").then().body("roles", contains("AUDITOR", "USER")).body("username", is("alice"));
    }

    @Test
    void neverReadsTheHeaders() {
        given().header("username", "mallory").header("roles", "ADMIN").get("/test/whoami").then()
                .body("username", is("anonymous")).body("roles", empty());
        given().header("username", "mallory").header("roles", "ADMIN").get("/test/admin").then().statusCode(401);
        given().auth().oauth2(token("alice", "USER").sign()).header("username", "mallory").header("tenant", "evil")
                .header("territories", "FR").get("/test/whoami").then()
                .body("username", is("alice")).body("tenant", is("-"));
        given().auth().oauth2(token("alice", "USER").sign()).header("territories", "FR").get("/test/territories").then()
                .body("$", empty());
    }

    @Test
    void appliesTheRulesToTheMappedRoles() {
        given().auth().oauth2(token("alice", "MANAGER").sign()).get("/test/user").then().statusCode(200);
        given().auth().oauth2(token("bob", "USER").sign()).get("/test/admin").then().statusCode(403);
    }

    @Test
    void readsClaimsOfEveryType() {
        String token = token("alice", "USER")
                .claim("territories", List.of("FR", 42, "GP"))
                .claim("codes", List.of("1", 2))
                .claim("maxAmount", 5000)
                .claim("auditor", true)
                .claim("realm_access", Map.of("roles", List.of("USER"), "level", "gold"))
                .sign();
        given().auth().oauth2(token).get("/test/territories").then().body("$", contains("FR", "GP"));
        given().auth().oauth2(token).get("/test/codes").then().body("$", contains(1, 2));
        given().auth().oauth2(token).get("/test/claims").then()
                .body("maxAmount", is(5000)).body("auditor", is(true)).body("level", is("gold"));
    }

    @Test
    void takesASingleValueAsAListOfOne() {
        given().auth().oauth2(token("alice", "USER").claim("territories", "FR").sign()).get("/test/territories").then()
                .body("$", contains("FR"));
    }

    @Test
    void readsNothingFromATokenThatFailsVerification() {
        String token = token("mallory", "ADMIN").claim("territories", List.of("FR")).sign();
        String forged = token.substring(0, token.lastIndexOf('.') + 1) + "AAAA";
        given().auth().oauth2(forged).get("/test/admin").then().statusCode(401);
    }

    @Test
    void aRequiredClaimMissingIsA403() {
        given().auth().oauth2(token("alice", "USER").sign()).get("/test/required").then().statusCode(403);
        given().auth().oauth2(token("alice", "USER").claim("territories", List.of(42)).sign()).get("/test/required").then().statusCode(403);
    }
}
