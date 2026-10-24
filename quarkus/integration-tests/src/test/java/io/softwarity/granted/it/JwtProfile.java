package io.softwarity.granted.it;

import java.util.Map;

import io.quarkus.test.junit.QuarkusTestProfile;

/** The caller from a JWT that smallrye-jwt verified, with Keycloak's nesting of the roles. */
public class JwtProfile implements QuarkusTestProfile {

    @Override
    public Map<String, String> getConfigOverrides() {
        return Map.of(
                "granted.source", "jwt",
                "granted.jwt.username-claim", "preferred_username",
                "granted.jwt.roles-claim", "realm_access.roles",
                "granted.known-roles", "ADMIN,MANAGER,USER,AUDITOR,FORECASTER");
    }
}
