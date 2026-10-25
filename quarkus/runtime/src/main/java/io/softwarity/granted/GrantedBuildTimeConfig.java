package io.softwarity.granted;

import io.quarkus.runtime.annotations.ConfigPhase;
import io.quarkus.runtime.annotations.ConfigRoot;
import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;

/** What granted decides when the application is built. */
@ConfigMapping(prefix = "granted")
@ConfigRoot(phase = ConfigPhase.BUILD_TIME)
public interface GrantedBuildTimeConfig {

    /** The {@code granted-jwks} readiness check. */
    Health health();

    /** What granted writes in the OpenAPI document, when quarkus-smallrye-openapi is present. */
    OpenApi openapi();

    /** The {@code granted-jwks} readiness check, registered when quarkus-smallrye-health is present. */
    interface Health {

        /**
         * Whether to register the {@code granted-jwks} readiness check: DOWN while a provider granted
         * verifies tokens with has no key.
         */
        @WithDefault("true")
        boolean enabled();
    }

    /**
     * Each route's access rule - its {@code @RolesAllowed}, {@code @Authenticated},
     * {@code @PermitAll} or {@code @DenyAll} - written in the OpenAPI document when
     * quarkus-smallrye-openapi is present: the document is generated at build time.
     */
    interface OpenApi {

        /**
         * The security scheme the routes' requirements name, as nestjs-granted's
         * {@code openApiSecurityScheme}. Added to the document as an HTTP bearer scheme unless it
         * defines one by that name.
         */
        @WithDefault("bearer")
        String securityScheme();
    }
}
