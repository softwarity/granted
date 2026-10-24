package io.softwarity.granted;

import java.util.Map;

/** Claim paths for the jwt package: the mapping, and a read through a claims map. */
public final class ClaimPaths {

    private ClaimPaths() {
    }

    public static String username(GrantedConfig.Jwt jwt) {
        return ClaimMapping.of(jwt).username();
    }

    /** A claim by its dotted path. */
    public static Object read(Map<String, Object> claims, String path) {
        Object value = claims;
        for (String key : path.split("\\.")) {
            value = value instanceof Map<?, ?> map ? map.get(key) : null;
        }
        return value;
    }
}
