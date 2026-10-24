package io.softwarity.granted;

import io.softwarity.granted.GrantedConfig.Preset;

/** The claims carrying the caller: {@code granted.jwt.*-claim}, else the preset's, else nestjs-granted's defaults. */
record ClaimMapping(String username, String roles, String tenant) {

    static ClaimMapping of(GrantedConfig.Jwt jwt) {
        ClaimMapping preset = jwt.preset().map(ClaimMapping::of).orElse(new ClaimMapping("sub", "roles", "tenant"));
        return new ClaimMapping(jwt.usernameClaim().orElse(preset.username), jwt.rolesClaim().orElse(preset.roles),
                jwt.tenantClaim().orElse(preset.tenant));
    }

    static ClaimMapping of(Preset preset) {
        return switch (preset) {
            case RFC9068 -> new ClaimMapping("sub", "roles", "tenant");
            case AZURE_AD -> new ClaimMapping("preferred_username", "roles", "tid");
            case KEYCLOAK -> new ClaimMapping("preferred_username", "realm_access.roles", "tenant");
            case OKTA -> new ClaimMapping("sub", "groups", "tenant");
        };
    }
}
