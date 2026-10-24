package io.softwarity.granted.it.jwt;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.everyItem;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.hasKey;

import java.util.List;
import java.util.Map;

import org.eclipse.microprofile.config.ConfigProvider;
import org.junit.jupiter.api.Test;

import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;

/** The configuration a canopy service runs with, end to end, over HTTPS with the cluster's CAs. */
@QuarkusTest
@QuarkusTestResource(value = CanopyIdp.class, restrictToAnnotatedClass = true)
class CanopyTest {

    static String config(String key) {
        return ConfigProvider.getConfig().getValue(key, String.class);
    }

    static String user(String sub, String audience, String... roles) {
        return Keys.sign("meerkat", "RS256", "meerkat", Map.of("sub", sub, "iss", CanopyIdp.MEERKAT, "aud", audience, "roles", List.of(roles)));
    }

    static String serviceAccount(String sub) {
        return Keys.sign("k8s", "RS256", "k8s", Map.of("sub", sub, "iss", CanopyIdp.KUBERNETES, "aud", "my-service"));
    }

    @Test
    void aUserOfMeerkatIsVerifiedThroughTheClustersCaAndTheHierarchyApplies() {
        given().auth().oauth2(user("alice", "my-service", "ROLE_ADMIN")).get("/caller/user").then().statusCode(200).body(is("alice"));
        given().auth().oauth2(user("bob", "my-service", "ROLE_USER")).get("/caller/role-admin").then().statusCode(403);
    }

    @Test
    void aTokenForAnotherAudienceIsAnonymous() {
        given().auth().oauth2(user("alice", "billing", "ROLE_ADMIN")).get("/caller").then().body("username", is("anonymous"));
    }

    @Test
    void aServiceAccountOfTheNamespacePassesEveryRoleCheckAndTheBearerTokenGoesToKubernetesOnly() {
        given().auth().oauth2(serviceAccount("system:serviceaccount:my-namespace:reports")).get("/caller/role-admin").then()
                .statusCode(200).body(is("system:serviceaccount:my-namespace:reports"));
        given().auth().oauth2(serviceAccount("system:serviceaccount:elsewhere:reports")).get("/caller/role-admin").then().statusCode(403);
        given().auth().oauth2(user("alice", "my-service", "ROLE_USER")).get("/caller/user").then().statusCode(200);
        given().get(config("it.control")).then()
                .body("authorizations.'/openid/v1/jwks'", everyItem(is("Bearer sa-token")))
                .body("authorizations.'/jwks'", everyItem(is("-")))
                .body("authorizations.'/.well-known/openid-configuration'", everyItem(is("-")));
    }

    @Test
    void isReadyOnMeerkatsKeysAloneKubernetesBeingLeftOut() {
        given().get("/q/health/ready").then().statusCode(200)
                .body("checks.find { it.name == 'granted-jwks' }.status", is("UP"))
                .body("checks.find { it.name == 'granted-jwks' }.data.'" + config("it.meerkat") + "'", is("1 keys"))
                .body("checks.find { it.name == 'granted-jwks' }.data", not(hasKey(CanopyIdp.KUBERNETES)));
    }
}
