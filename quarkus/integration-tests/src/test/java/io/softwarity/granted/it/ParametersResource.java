package io.softwarity.granted.it;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

import io.softwarity.granted.GrantedClaim;
import io.softwarity.granted.GrantedRoles;
import io.softwarity.granted.GrantedTenant;
import io.softwarity.granted.GrantedUsername;

/** The caller injected into resource methods - nestjs-granted's parameter decorators. */
@Path("/params")
@Produces(MediaType.APPLICATION_JSON)
public class ParametersResource {

    @GET
    @Path("/me")
    @PermitAll
    public Map<String, Object> me(@GrantedUsername String username, @GrantedRoles Set<String> roles, @GrantedRoles List<String> roleList,
            @GrantedTenant String tenant) {
        Map<String, Object> me = new HashMap<>();
        me.put("username", username);
        me.put("roles", new java.util.TreeSet<>(roles));
        me.put("roleCount", roleList.size());
        me.put("tenant", tenant);
        return me;
    }

    @GET
    @Path("/stations")
    @RolesAllowed("FORECASTER")
    public List<String> stations(@GrantedClaim("territories") List<String> territories) {
        return territories;
    }

    @GET
    @Path("/types")
    @PermitAll
    public Map<String, Object> types(@GrantedClaim("maxAmount") Long maxAmount, @GrantedClaim("rank") Integer rank,
            @GrantedClaim("ratio") Double ratio, @GrantedClaim("auditor") Boolean auditor, @GrantedClaim("codes") List<Integer> codes,
            @GrantedClaim("territories") Set<String> territorySet, @GrantedClaim("level") String level) {
        Map<String, Object> types = new HashMap<>();
        types.put("maxAmount", maxAmount);
        types.put("rank", rank);
        types.put("ratio", ratio);
        types.put("auditor", auditor);
        types.put("codes", codes);
        types.put("territorySet", territorySet == null ? null : new java.util.TreeSet<>(territorySet));
        types.put("level", level);
        return types;
    }

    @GET
    @Path("/required")
    @PermitAll
    public List<String> required(@GrantedClaim(value = "territories", required = true) List<String> territories) {
        return territories;
    }

    @GET
    @Path("/primitive")
    @PermitAll
    public long primitive(@GrantedClaim(value = "maxAmount", required = true) long maxAmount) {
        return maxAmount;
    }
}
