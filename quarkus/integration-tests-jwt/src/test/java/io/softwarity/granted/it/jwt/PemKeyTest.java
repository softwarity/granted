package io.softwarity.granted.it.jwt;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.is;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;

/** granted verifies the token with a PEM key file - ES256 by default - checking issuer and audience. */
@QuarkusTest
@TestProfile(PemKeyTest.Pem.class)
class PemKeyTest {

    public static class Pem implements QuarkusTestProfile {

        @Override
        public Map<String, String> getConfigOverrides() {
            try {
                Path dir = Files.createTempDirectory("granted-pem");
                KeyPair pair = Keys.generate("EC");
                Keys.save(dir, "pem", pair);
                return Map.of(
                        "granted.source", "jwt",
                        "granted.jwt.public-key-file", dir.resolve("pem.pem").toString(),
                        "granted.jwt.issuer", "https://gateway.acme",
                        "granted.jwt.audience", "/^orders-/",
                        "granted.role-hierarchy.ADMIN", "FORECASTER",
                        "it.keys", dir.toString());
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }

    static String token(String alg, Map<String, Object> claims) {
        return Keys.sign("pem", alg, null, claims);
    }

    @Test
    void verifiesWithTheKeyFileUnderEs256() {
        Map<String, Object> claims = Map.of("sub", "alice", "roles", List.of("ADMIN"), "iss", "https://gateway.acme", "aud", "orders-api",
                "territories", "FR, GP");
        given().auth().oauth2(token("ES256", claims)).get("/caller").then().body("username", is("alice")).body("roles", contains("ADMIN", "FORECASTER"));
        given().auth().oauth2(token("ES256", claims)).get("/caller/stations").then().statusCode(200).body("$", contains("FR", "GP"));
    }

    @Test
    void checksTheIssuerAndTheAudience() {
        given().auth().oauth2(token("ES256", Map.of("sub", "alice", "iss", "https://evil", "aud", "orders-api"))).get("/caller").then()
                .body("username", is("anonymous"));
        given().auth().oauth2(token("ES256", Map.of("sub", "alice", "iss", "https://gateway.acme", "aud", "billing"))).get("/caller").then()
                .body("username", is("anonymous"));
    }

    @Test
    void refusesAnotherAlgorithmThanTheConfiguredOne() {
        given().auth().oauth2(token("ES384", Map.of("sub", "alice", "iss", "https://gateway.acme", "aud", "orders-api"))).get("/caller").then()
                .body("username", is("anonymous"));
    }
}
