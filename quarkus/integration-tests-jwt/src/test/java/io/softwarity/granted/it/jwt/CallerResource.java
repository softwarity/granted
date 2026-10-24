package io.softwarity.granted.it.jwt;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

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

@Path("/caller")
@Produces(MediaType.APPLICATION_JSON)
public class CallerResource {

    @GET
    @PermitAll
    public Map<String, Object> me(@GrantedUsername String username, @GrantedRoles Set<String> roles, @GrantedTenant String tenant) {
        Map<String, Object> me = new HashMap<>();
        me.put("username", username);
        me.put("roles", new TreeSet<>(roles));
        me.put("tenant", tenant);
        return me;
    }

    @GET
    @Path("/admin")
    @RolesAllowed("ADMIN")
    public String admin(@GrantedUsername String username) {
        return username;
    }

    @GET
    @Path("/stations")
    @RolesAllowed("FORECASTER")
    public List<String> stations(@GrantedClaim("territories") List<String> territories) {
        return territories;
    }
}
