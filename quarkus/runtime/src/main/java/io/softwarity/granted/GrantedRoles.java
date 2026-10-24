package io.softwarity.granted;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * The roles the rules see, after the hierarchy and {@code granted.known-roles} - nestjs-granted's {@code @Roles()}. On a {@code Set<String>} or a {@code List<String>}. Read for each request, never captured.
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ ElementType.PARAMETER, ElementType.FIELD })
public @interface GrantedRoles {
}
