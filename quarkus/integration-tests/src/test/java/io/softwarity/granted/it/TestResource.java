package io.softwarity.granted.it;

import java.util.List;
import java.util.Map;
import java.util.TreeSet;

import jakarta.annotation.security.DenyAll;
import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

import io.quarkus.security.Authenticated;
import io.softwarity.granted.GrantedCaller;

/** What an application of this library looks like: a singleton resource reading its caller. */
@Path("/test")
@Produces(MediaType.APPLICATION_JSON)
public class TestResource {

    @Inject
    GrantedCaller caller;

    @GET
    @Path("/whoami")
    @PermitAll
    public Map<String, Object> whoami() {
        return Map.of("username", caller.username(), "roles", new TreeSet<>(caller.roles()), "tenant", caller.tenant().orElse("-"));
    }

    @GET
    @Path("/admin")
    @RolesAllowed("ADMIN")
    public String admin() {
        return "admin";
    }

    @GET
    @Path("/user")
    @RolesAllowed("USER")
    public String user() {
        return "user";
    }

    @GET
    @Path("/either")
    @RolesAllowed({ "ADMIN", "AUDITOR" })
    public String either() {
        return "either";
    }

    @GET
    @Path("/nobody")
    @DenyAll
    public String nobody() {
        return "nobody";
    }

    @GET
    @Path("/territories")
    @PermitAll
    public List<String> territories() {
        return caller.claims("territories", String.class);
    }

    @GET
    @Path("/codes")
    @PermitAll
    public List<Long> codes() {
        return caller.claims("codes", Long.class);
    }

    @GET
    @Path("/claims")
    @PermitAll
    public Map<String, Object> claims() {
        return Map.of(
                "maxAmount", caller.claim("maxAmount", Long.class).map(Object.class::cast).orElse("-"),
                "auditor", caller.claim("auditor", Boolean.class).map(Object.class::cast).orElse("-"),
                "level", caller.claim("realm_access.level", String.class).orElse("-"));
    }

    @GET
    @Path("/required")
    @Authenticated
    public List<String> required() {
        return caller.requireClaims("territories", String.class);
    }
}
