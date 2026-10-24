package io.softwarity.granted;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * The caller's tenant, or {@code null} - nestjs-granted's {@code @Tenant()}: the claim {@code granted.jwt.tenant-claim}, or the header {@code granted.headers.tenant}. On a {@code String}. Read for each request, never captured.
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ ElementType.PARAMETER, ElementType.FIELD })
public @interface GrantedTenant {
}
