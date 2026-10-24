package io.softwarity.granted;

import java.util.LinkedHashSet;
import java.util.List;

import jakarta.ws.rs.WebApplicationException;

import org.jboss.resteasy.reactive.server.core.ResteasyReactiveRequestContext;
import org.jboss.resteasy.reactive.server.core.parameters.ParameterExtractor;

import io.quarkus.arc.Arc;

/**
 * Gives a {@code @GrantedClaim}, {@code @GrantedUsername}, {@code @GrantedRoles} or
 * {@code @GrantedTenant} parameter its value, from the {@link GrantedCaller} of the request being
 * served. Built by the deployment module and recorded into the application, hence a bean with a
 * no-argument constructor and accessors: not meant to be used directly.
 */
public class GrantedParameterExtractor implements ParameterExtractor {

    /** What the parameter receives. */
    public enum Kind {
        USERNAME, ROLES, TENANT, CLAIM
    }

    /** How a claim's values are collected. */
    public enum Collection {
        NONE, LIST, SET
    }

    private Kind kind;

    private String name;

    private String type;

    private Collection collection = Collection.NONE;

    private boolean required;

    /** {@link #type}, loaded once. */
    private volatile Class<?> loaded;

    public GrantedParameterExtractor() {
    }

    public GrantedParameterExtractor(Kind kind, String name, String type, Collection collection, boolean required) {
        this.kind = kind;
        this.name = name;
        this.type = type;
        this.collection = collection;
        this.required = required;
    }

    @Override
    public Object extractParameter(ResteasyReactiveRequestContext context) {
        GrantedCaller caller = Arc.container().instance(GrantedCaller.class).get();
        return switch (kind) {
            case USERNAME -> caller.username();
            case ROLES -> collection == Collection.SET ? new LinkedHashSet<>(caller.roles()) : List.copyOf(caller.roles());
            case TENANT -> caller.tenant().orElse(null);
            case CLAIM -> claim(caller, context);
        };
    }

    private Object claim(GrantedCaller caller, ResteasyReactiveRequestContext context) {
        Class<?> elementType = elementType();
        try {
            if (collection == Collection.NONE) {
                return required ? caller.requireClaim(name, elementType) : caller.claim(name, elementType).orElse(null);
            }
            List<?> values = required ? caller.requireClaims(name, elementType) : caller.claims(name, elementType);
            return collection == Collection.SET ? new LinkedHashSet<>(values) : values;
        } catch (MissingClaimException e) {
            // Quarkus REST answers 400 to any other exception thrown while extracting a parameter:
            // the 403 is built here, the same one the exception mapper answers.
            AccessDenial denial = Arc.container().instance(AccessDenial.class).get();
            throw new WebApplicationException(denial.refuse("claim(" + name + ")", context.getMethod(), context.getPath(), context.getPath()));
        }
    }

    private Class<?> elementType() {
        Class<?> elementType = loaded;
        if (elementType == null) {
            try {
                elementType = Class.forName(type, false, Thread.currentThread().getContextClassLoader());
            } catch (ClassNotFoundException e) {
                throw new IllegalStateException("No class " + type + " for @GrantedClaim(\"" + name + "\")", e);
            }
            loaded = elementType;
        }
        return elementType;
    }

    public Kind getKind() {
        return kind;
    }

    public void setKind(Kind kind) {
        this.kind = kind;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    /** The claim's element type, as a class name: {@code java.lang.String}, {@code java.lang.Long}... */
    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public Collection getCollection() {
        return collection;
    }

    public void setCollection(Collection collection) {
        this.collection = collection;
    }

    public boolean isRequired() {
        return required;
    }

    public void setRequired(boolean required) {
        this.required = required;
    }
}
