package io.softwarity.granted.deployment;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.function.Consumer;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusExtensionTest;

/** What stops the application: a configuration that could only look secure. */
class StartupRefusalTest {

    static final String PROVIDER = "https://localhost:1";

    /** The message of the cause that says why, whatever wraps it. */
    static Consumer<Throwable> refusal(String... fragments) {
        return thrown -> {
            StringBuilder messages = new StringBuilder();
            for (Throwable t = thrown; t != null; t = t.getCause()) {
                messages.append(t.getMessage()).append('\n');
            }
            for (String fragment : fragments) {
                assertTrue(messages.toString().contains(fragment), messages.toString());
            }
        };
    }

    @Nested
    class UnknownTlsConfiguration {

        @RegisterExtension
        static final QuarkusExtensionTest app = new QuarkusExtensionTest()
                .overrideConfigKey("granted.source", "jwt")
                .overrideConfigKey("granted.jwt.discovery-uris[0].uri", PROVIDER)
                .overrideConfigKey("granted.jwt.tls-configuration-name", "clustr")
                .assertException(refusal("granted.jwt.tls-configuration-name=clustr: no such TLS configuration"));

        @Test
        void stopsTheStartNamingTheProperty() {
        }
    }

    @Nested
    class UnknownTlsConfigurationOfAProvider {

        @RegisterExtension
        static final QuarkusExtensionTest app = new QuarkusExtensionTest()
                .overrideConfigKey("granted.source", "jwt")
                .overrideConfigKey("granted.jwt.discovery-uris[0].uri", PROVIDER)
                .overrideConfigKey("granted.jwt.discovery-uris[1].issuer", "https://kubernetes.default.svc.cluster.local")
                .overrideConfigKey("granted.jwt.discovery-uris[1].jwks-uri", PROVIDER + "/openid/v1/jwks")
                .overrideConfigKey("granted.jwt.discovery-uris[1].tls-configuration-name", "kube")
                .assertException(refusal("granted.jwt.discovery-uris[1].tls-configuration-name=kube: no such TLS configuration"));

        @Test
        void stopsTheStartNamingTheProvidersProperty() {
        }
    }

    @Nested
    class TrustAll {

        @RegisterExtension
        static final QuarkusExtensionTest app = new QuarkusExtensionTest()
                .overrideConfigKey("granted.source", "jwt")
                .overrideConfigKey("granted.jwt.discovery-uris[0].uri", PROVIDER)
                .overrideConfigKey("granted.jwt.tls-configuration-name", "lax")
                .overrideConfigKey("quarkus.tls.lax.trust-all", "true")
                .assertException(refusal("granted.jwt.tls-configuration-name=lax trusts every certificate", "quarkus.tls.trust-all=true"));

        @Test
        void isRefused() {
        }
    }

    @Nested
    class NothingVerifiesTheToken {

        @RegisterExtension
        static final QuarkusExtensionTest app = new QuarkusExtensionTest()
                .overrideConfigKey("granted.source", "jwt")
                .assertException(refusal("granted.source=jwt, but nothing verifies the token"));

        @Test
        void stopsTheStart() {
        }
    }
}
