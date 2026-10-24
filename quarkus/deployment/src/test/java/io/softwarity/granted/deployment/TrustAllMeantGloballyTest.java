package io.softwarity.granted.deployment;

import static org.junit.jupiter.api.Assertions.assertTrue;

import jakarta.inject.Inject;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusExtensionTest;
import io.softwarity.granted.jwt.JwtVerification;

/** A TLS configuration trusting every certificate is accepted when quarkus.tls.trust-all says that is meant. */
class TrustAllMeantGloballyTest {

    @RegisterExtension
    static final QuarkusExtensionTest app = new QuarkusExtensionTest()
            .overrideConfigKey("granted.source", "jwt")
            .overrideConfigKey("granted.jwt.discovery-uris[0].uri", StartupRefusalTest.PROVIDER)
            .overrideConfigKey("granted.jwt.tls-configuration-name", "lax")
            .overrideConfigKey("quarkus.tls.lax.trust-all", "true")
            .overrideConfigKey("quarkus.tls.trust-all", "true");

    @Inject
    JwtVerification verification;

    @Test
    void starts() {
        assertTrue(verification.enabled());
    }
}
