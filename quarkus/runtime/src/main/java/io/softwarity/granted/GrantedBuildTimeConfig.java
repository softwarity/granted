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

    /** The {@code granted-jwks} readiness check, registered when quarkus-smallrye-health is present. */
    interface Health {

        /**
         * Whether to register the {@code granted-jwks} readiness check: DOWN while a provider granted
         * verifies tokens with has no key.
         */
        @WithDefault("true")
        boolean enabled();
    }
}
