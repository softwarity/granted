package io.softwarity.granted.it.jwt;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.everyItem;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;

import java.util.List;
import java.util.Map;

import org.eclipse.microprofile.config.ConfigProvider;
import org.junit.jupiter.api.Test;

import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;

/**
 * granted verifies the token itself, against two OpenID Providers: one found by discovery, one
 * Kubernetes API server given by issuer and JWK Set, behind a bearer token, whose service accounts
 * of my-namespace bypass every role check. Claims mapped by the keycloak preset.
 */
@QuarkusTest
@QuarkusTestResource(value = LocalIdp.class, restrictToAnnotatedClass = true)
class DiscoveryTest {

    static String idpA(Map<String, Object> claims) {
        return Keys.sign("idp-a", "RS256", "idp-a", claims);
    }

    static String kubernetes(String sub) {
        return Keys.sign("k8s", "RS256", "k8s", Map.of("sub", sub, "iss", LocalIdp.KUBERNETES));
    }

    static Map<String, Object> keycloak(String username, String... roles) {
        return Map.of("sub", "id-" + username, "iss", "https://idp-a", "preferred_username", username,
                "realm_access", Map.of("roles", List.of(roles)), "territories", List.of("FR", "GP"), "tenant", "meteo-france");
    }

    @Test
    void verifiesATokenOfTheDiscoveredProviderAndMapsItThroughThePreset() {
        given().auth().oauth2(idpA(keycloak("alice", "ADMIN"))).get("/caller").then().statusCode(200)
                .body("username", is("alice")).body("roles", contains("ADMIN")).body("tenant", is("meteo-france"));
        given().auth().oauth2(idpA(keycloak("alice", "ADMIN"))).get("/caller/admin").then().statusCode(200).body(is("alice"));
        given().auth().oauth2(idpA(keycloak("bob", "FORECASTER"))).get("/caller/stations").then().statusCode(200).body("$", contains("FR", "GP"));
    }

    @Test
    void anInvalidTokenIsAnAnonymousCallerNotA401() {
        String forged = Keys.sign("k8s", "RS256", "idp-a", keycloak("mallory", "ADMIN"));
        given().auth().oauth2(forged).get("/caller").then().statusCode(200).body("username", is("anonymous")).body("roles", empty());
        given().auth().oauth2("not-a-token").get("/caller").then().statusCode(200).body("username", is("anonymous"));
        given().auth().oauth2(forged).get("/caller/admin").then().statusCode(401);
    }

    @Test
    void rejectsAnUnknownIssuer() {
        Map<String, Object> claims = Map.of("sub", "mallory", "iss", ConfigProvider.getConfig().getValue("it.idp", String.class) + "/evil",
                "preferred_username", "mallory", "realm_access", Map.of("roles", List.of("ADMIN")));
        given().auth().oauth2(idpA(claims)).get("/caller").then().body("username", is("anonymous"));
    }

    @Test
    void aServiceAccountOfTheNamespacePassesEveryRoleCheckNamedByItsSub() {
        given().auth().oauth2(kubernetes("system:serviceaccount:my-namespace:reports")).get("/caller/admin").then()
                .statusCode(200).body(is("system:serviceaccount:my-namespace:reports"));
        given().auth().oauth2(kubernetes("system:serviceaccount:my-namespace:reports")).get("/caller/stations").then().statusCode(200);
    }

    @Test
    void theBypassIsTheKubernetesProvidersOnly() {
        given().auth().oauth2(kubernetes("system:serviceaccount:elsewhere:reports")).get("/caller/admin").then().statusCode(403);
        // The same sub, from the other provider: authenticated, no bypass.
        given().auth().oauth2(idpA(Map.of("sub", "system:serviceaccount:my-namespace:reports", "iss", "https://idp-a"))).get("/caller/admin").then()
                .statusCode(403);
    }

    @Test
    void theBearerTokenGoesToTheKubernetesProviderOnly() {
        given().auth().oauth2(kubernetes("system:serviceaccount:my-namespace:reports")).get("/caller/admin").then().statusCode(200);
        given().auth().oauth2(idpA(keycloak("alice", "ADMIN"))).get("/caller/admin").then().statusCode(200);
        given().get(ConfigProvider.getConfig().getValue("it.idp", String.class) + "/_authorizations").then()
                .body("'/k8s/jwks'", everyItem(is("Bearer sa-token")))
                .body("'/a/jwks'", everyItem(is("-")))
                .body("'/a/.well-known/openid-configuration'", everyItem(is("-")));
    }

    @Test
    void neverReadsTheIdentityHeaders() {
        given().header("username", "mallory").header("roles", "ADMIN").get("/caller").then().body("username", is("anonymous"));
        given().auth().oauth2(idpA(keycloak("alice", "USER"))).header("username", "mallory").header("tenant", "evil").get("/caller").then()
                .body("username", is("alice")).body("tenant", is("meteo-france")).body("roles", not(hasItem("ADMIN")));
    }
}
