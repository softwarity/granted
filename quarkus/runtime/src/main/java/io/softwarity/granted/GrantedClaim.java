package io.softwarity.granted;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Injects an attribute of the caller into a resource method - nestjs-granted's {@code @Claim}.
 *
 * <pre>{@code
 * @GET
 * @RolesAllowed("FORECASTER")
 * public List<Station> list(@GrantedClaim("territories") List<String> territories) {
 *     return Station.list("territory in ?1", territories);
 * }
 * }</pre>
 *
 * The value is read where the rest of the identity comes from: a claim of the verified token
 * (dotted paths allowed, e.g. {@code realm_access.territories}), or the header of that name in
 * headers mode - never from a header when the identity comes from a JWT. It is read for each
 * request, never captured.
 *
 * <p>The parameter's type says how the value is read: {@code String}, {@code Integer},
 * {@code Long}, {@code Double}, {@code Boolean}, {@code Object} for the value as found, or a
 * {@code List} / {@code Set} of one of them. A number or a boolean given as a string converts; a
 * list is a JSON array or a comma-separated list, and a single value is a list of one. A value
 * of the wrong type is treated as missing - in a list, only the elements of the wrong type are
 * dropped - with a warning that never shows the value. Missing gives {@code null}, or an empty
 * list. A primitive ({@code int}, {@code long}...) can't say "missing": it needs
 * {@code required = true}.
 *
 * <p>Named so as not to be mistaken for MicroProfile JWT's {@code @Claim}, which reads a token
 * only.
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ ElementType.PARAMETER, ElementType.FIELD })
public @interface GrantedClaim {

    /** The claim, or the header in headers mode. */
    String value();

    /** Refuse the request (403) when the claim is missing, not of the expected type, or an empty list. */
    boolean required() default false;
}
