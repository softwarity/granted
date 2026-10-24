package io.softwarity.granted.jwt;

import java.util.Map;
import java.util.Set;

import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.JsonWebToken;

/** A token granted verified itself, as the principal of the request: claims as plain Java values. */
public final class GrantedJsonWebToken implements JsonWebToken {

    private final String name;

    private final String rawToken;

    private final Map<String, Object> claims;

    public GrantedJsonWebToken(String name, String rawToken, Map<String, Object> claims) {
        this.name = name;
        this.rawToken = rawToken;
        this.claims = Map.copyOf(claims.entrySet().stream().filter(e -> e.getValue() != null)
                .collect(java.util.stream.Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue)));
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public Set<String> getClaimNames() {
        return claims.keySet();
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> T getClaim(String claimName) {
        return Claims.raw_token.name().equals(claimName) ? (T) rawToken : (T) claims.get(claimName);
    }

    @Override
    public String toString() {
        // Never the token.
        return "GrantedJsonWebToken[" + name + "]";
    }
}
