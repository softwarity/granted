package io.softwarity.granted.it;

import java.util.Map;

import io.quarkus.test.junit.QuarkusTestProfile;

/** The reason of a refusal written into the response too. */
public class DetailsProfile implements QuarkusTestProfile {

    @Override
    public Map<String, String> getConfigOverrides() {
        return Map.of("granted.access-denied.details", "true");
    }
}
