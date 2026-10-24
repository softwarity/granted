package io.softwarity.granted.jwt;

import static io.softwarity.granted.jwt.JwtTestSupport.claims;
import static io.softwarity.granted.jwt.JwtTestSupport.jwks;
import static io.softwarity.granted.jwt.JwtTestSupport.rsa;
import static io.softwarity.granted.jwt.JwtTestSupport.sign;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import javax.net.ssl.SSLContext;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import io.softwarity.granted.jwt.JwtTestSupport.Config;
import io.softwarity.granted.jwt.JwtTestSupport.Idp;
import io.softwarity.granted.jwt.JwtTestSupport.Provider;
import io.softwarity.granted.jwt.JwtTestSupport.SigningKey;
import io.softwarity.granted.jwt.JwtVerifier.ProviderStatus;

/** granted.jwt.tls-configuration-name, and what the granted-jwks readiness check sees. */
class JwtTlsAndReadinessTest {

    static TestCa cluster;
    static TestCa publicCa;
    static final SigningKey MEERKAT = rsa("meerkat");
    static final SigningKey K8S = rsa("k8s");

    final List<Idp> idps = new ArrayList<>();
    final AtomicLong elapsed = new AtomicLong();

    @BeforeAll
    static void authorities() throws Exception {
        cluster = TestCa.create("cluster CA");
        publicCa = TestCa.create("public CA");
    }

    @AfterEach
    void stop() {
        idps.forEach(Idp::close);
    }

    /** An IdP over HTTPS, its certificate signed by {@code ca} for these names, reached as localhost. */
    Idp https(TestCa ca, String... names) throws Exception {
        Idp idp = new Idp(ca.issue(names).serverContext(), "localhost");
        idps.add(idp);
        return idp;
    }

    Idp meerkat(TestCa ca, String... names) throws Exception {
        Idp idp = https(ca, names);
        idp.discovery("/.well-known/openid-configuration", "https://meerkat", "/jwks");
        idp.routes.put("/jwks", () -> jwks(List.of(MEERKAT.jwk())));
        return idp;
    }

    JwtVerifier verifier(Config config, Map<String, SSLContext> tls) {
        return new JwtVerifier(JwtSettings.of(config), tls, () -> System.currentTimeMillis() + elapsed.get());
    }

    static String user(String iss) {
        return sign(MEERKAT, claims("sub", "alice", "iss", iss));
    }

    @Nested
    class Tls {

        @Test
        void withoutATlsConfigurationAClusterCertificateIsRefusedAndTheCallerAnonymous() throws Exception {
            Idp idp = meerkat(cluster, "localhost", "127.0.0.1");
            JwtVerifier verifier = verifier(new Config().provider(Provider.uri(idp.url("/"))), Map.of());
            assertNull(verifier.verify(user("https://meerkat")));
            assertTrue(verifier.readiness().get(0).failure().contains("TLS handshake failed"), verifier.readiness().toString());
        }

        @Test
        void withTheTlsConfigurationOfTheClusterTheTokenIsVerified() throws Exception {
            Idp idp = meerkat(cluster, "localhost", "127.0.0.1");
            Config config = new Config().provider(Provider.uri(idp.url("/")));
            config.tlsConfigurationName = "cluster";
            assertNotNull(verifier(config, Map.of("cluster", cluster.clientContext())).verify(user("https://meerkat")));
        }

        @Test
        void aCertificateForAnotherHostNameIsRefused() throws Exception {
            Idp idp = meerkat(cluster, "meerkat.other.example");
            Config config = new Config().provider(Provider.uri(idp.url("/")));
            config.tlsConfigurationName = "cluster";
            JwtVerifier verifier = verifier(config, Map.of("cluster", cluster.clientContext()));
            assertNull(verifier.verify(user("https://meerkat")));
            assertTrue(verifier.readiness().get(0).failure().contains("TLS handshake failed"), verifier.readiness().toString());
        }

        @Test
        void aProviderNamesItsOwnConfigurationInPlaceOfTheGlobalOne() throws Exception {
            Idp gateway = meerkat(publicCa, "localhost");
            Idp kubernetes = https(cluster, "localhost");
            kubernetes.routes.put("/openid/v1/jwks", () -> jwks(List.of(K8S.jwk())));
            Provider k8s = new Provider();
            k8s.issuer = "https://kubernetes.default.svc.cluster.local";
            k8s.jwksUri = kubernetes.url("/openid/v1/jwks");
            k8s.tlsConfigurationName = "cluster";
            Config config = new Config().provider(Provider.uri(gateway.url("/"))).provider(k8s);
            config.tlsConfigurationName = "public";
            Map<String, SSLContext> tls = Map.of("public", publicCa.clientContext(), "cluster", cluster.clientContext());
            JwtVerifier verifier = verifier(config, tls);
            assertNotNull(verifier.verify(user("https://meerkat")));
            assertNotNull(verifier.verify(sign(K8S, claims("sub", "system:serviceaccount:ns:x", "iss", k8s.issuer))));
            // The global configuration alone doesn't trust the cluster's CA.
            k8s.tlsConfigurationName = null;
            assertNull(verifier(config, Map.of("public", publicCa.clientContext())).verify(sign(K8S, claims("sub", "x", "iss", k8s.issuer))));
        }
    }

    @Nested
    class Readiness {

        @Test
        void isDownWhileTheJwkSetFailsNamingTheProviderAndTheStatusThenUpOnceKeysArrive() throws Exception {
            Idp idp = meerkat(cluster, "localhost");
            idp.status.put("/jwks", 503);
            Config config = new Config().provider(Provider.uri(idp.url("/")));
            config.tlsConfigurationName = "cluster";
            JwtVerifier verifier = verifier(config, Map.of("cluster", cluster.clientContext()));
            ProviderStatus down = verifier.readiness().get(0);
            assertFalse(down.up());
            assertEquals(idp.url("/"), down.label());
            assertEquals("JWK Set: HTTP 503", down.failure());
            idp.status.remove("/jwks");
            elapsed.addAndGet(31_000);
            ProviderStatus up = verifier.readiness().get(0);
            assertTrue(up.up());
            assertEquals(1, up.keys());
            assertNull(up.failure());
        }

        @Test
        void isDownWhileTheJwkSetHasNoKey() throws Exception {
            Idp idp = meerkat(cluster, "localhost");
            idp.routes.put("/jwks", () -> jwks(List.of()));
            Config config = new Config().provider(Provider.uri(idp.url("/")));
            config.tlsConfigurationName = "cluster";
            assertEquals("no key in the JWK Set", verifier(config, Map.of("cluster", cluster.clientContext())).readiness().get(0).failure());
        }

        @Test
        void isDownWhileTheDiscoveryDocumentFails() throws Exception {
            Idp idp = meerkat(cluster, "localhost");
            idp.status.put("/.well-known/openid-configuration", 500);
            Config config = new Config().provider(Provider.uri(idp.url("/")));
            config.tlsConfigurationName = "cluster";
            assertEquals("discovery document: HTTP 500", verifier(config, Map.of("cluster", cluster.clientContext())).readiness().get(0).failure());
        }

        @Test
        void saysWhenTheIdpDoesNotAnswerInTime() throws Exception {
            Idp idp = new Idp();
            idps.add(idp);
            Config config = new Config();
            config.jwksUri = idp.url("/hang");
            config.timeout = Duration.ofMillis(200);
            ProviderStatus status = verifier(config, Map.of()).readiness().get(0);
            assertEquals(idp.url("/hang"), status.label());
            assertEquals("JWK Set: timeout after 200 ms", status.failure());
        }

        @Test
        void neverFetchesMoreThanOncePerCooldownHoweverOftenItIsAsked() throws Exception {
            Idp idp = meerkat(cluster, "localhost");
            idp.routes.put("/jwks", () -> jwks(List.of()));
            Config config = new Config().provider(Provider.uri(idp.url("/")));
            config.tlsConfigurationName = "cluster";
            JwtVerifier verifier = verifier(config, Map.of("cluster", cluster.clientContext()));
            for (int i = 0; i < 20; i++) {
                assertFalse(verifier.readiness().get(0).up());
            }
            assertEquals(1, idp.fetches("/jwks"));
            assertEquals(1, idp.fetches("/.well-known/openid-configuration"));
            idp.routes.put("/jwks", () -> jwks(List.of(MEERKAT.jwk())));
            elapsed.addAndGet(31_000);
            for (int i = 0; i < 20; i++) {
                assertTrue(verifier.readiness().get(0).up());
            }
            assertEquals(2, idp.fetches("/jwks"));
        }

        @Test
        void sharesTheCacheOfTheVerification() throws Exception {
            Idp idp = meerkat(cluster, "localhost");
            Config config = new Config().provider(Provider.uri(idp.url("/")));
            config.tlsConfigurationName = "cluster";
            JwtVerifier verifier = verifier(config, Map.of("cluster", cluster.clientContext()));
            assertNotNull(verifier.verify(user("https://meerkat")));
            assertTrue(verifier.readiness().get(0).up());
            assertEquals(1, idp.fetches("/jwks"));
        }

        @Test
        void leavesOutAProviderWithReadinessOffAndSendsTheBearerTokenAsTheVerificationDoes() throws Exception {
            Idp gateway = meerkat(cluster, "localhost");
            Provider k8s = new Provider();
            k8s.issuer = "https://kubernetes.default.svc.cluster.local";
            k8s.jwksUri = "https://localhost:1/openid/v1/jwks";
            k8s.readiness = false;
            Config config = new Config().provider(Provider.uri(gateway.url("/"))).provider(k8s);
            config.tlsConfigurationName = "cluster";
            List<ProviderStatus> statuses = verifier(config, Map.of("cluster", cluster.clientContext())).readiness();
            assertEquals(1, statuses.size());
            assertTrue(statuses.get(0).up());
        }

        @Test
        void waitsForAJwksUriGivenAlone() throws Exception {
            Idp idp = https(cluster, "localhost");
            idp.routes.put("/jwks", () -> jwks(List.of(MEERKAT.jwk(), K8S.jwk())));
            Config config = new Config();
            config.jwksUri = idp.url("/jwks");
            config.tlsConfigurationName = "cluster";
            ProviderStatus status = verifier(config, Map.of("cluster", cluster.clientContext())).readiness().get(0);
            assertEquals(2, status.keys());
            assertEquals(idp.url("/jwks"), status.label());
        }

        @Test
        void hasNothingToWaitForWithAPemKey() {
            Config config = new Config();
            config.publicKey = "a-shared-secret";
            config.algorithm = List.of("HS256");
            assertTrue(verifier(config, Map.of()).readiness().isEmpty());
        }
    }
}
