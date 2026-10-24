package io.softwarity.granted.jwt;

import static io.softwarity.granted.jwt.JwtTestSupport.claims;
import static io.softwarity.granted.jwt.JwtTestSupport.ec;
import static io.softwarity.granted.jwt.JwtTestSupport.ed;
import static io.softwarity.granted.jwt.JwtTestSupport.jwks;
import static io.softwarity.granted.jwt.JwtTestSupport.rsa;
import static io.softwarity.granted.jwt.JwtTestSupport.sign;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.stream.IntStream;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.softwarity.granted.jwt.JwtTestSupport.Config;
import io.softwarity.granted.jwt.JwtTestSupport.Idp;
import io.softwarity.granted.jwt.JwtTestSupport.Provider;
import io.softwarity.granted.jwt.JwtTestSupport.SigningKey;

/** nestjs-granted's jwks.spec.ts and info-providers.spec.ts, case by case. */
class JwtVerifierTest {

    static final SigningKey KEY_A = rsa("key-a");
    static final SigningKey KEY_B = rsa("key-b");
    static final SigningKey OUTSIDER = rsa("outsider");
    static final SigningKey EC = ec("key-ec");
    static final SigningKey ED = ed("key-ed");

    Idp idp;
    List<Map<String, Object>> published;
    final AtomicLong elapsed = new AtomicLong();
    final List<String> logged = new ArrayList<>();

    private final Handler capture = new Handler() {
        @Override
        public void publish(LogRecord record) {
            String message = record.getParameters() == null ? record.getMessage()
                    : String.format(record.getMessage().replace("%d", "%s"), record.getParameters());
            synchronized (logged) {
                logged.add(message);
            }
        }

        @Override
        public void flush() {
        }

        @Override
        public void close() {
        }
    };

    @BeforeEach
    void start() throws Exception {
        idp = new Idp();
        published = new ArrayList<>(List.of(KEY_A.jwk()));
        idp.routes.put("/jwks.json", () -> jwks(published));
        Logger.getLogger("io.softwarity.granted").addHandler(capture);
    }

    @AfterEach
    void stop() {
        idp.close();
        Logger.getLogger("io.softwarity.granted").removeHandler(capture);
    }

    String warnings() {
        synchronized (logged) {
            return String.join("\n", logged);
        }
    }

    void advance(long millis) {
        elapsed.addAndGet(millis);
    }

    JwtVerifier verifier(Config config) {
        return new JwtVerifier(JwtSettings.of(config), () -> System.currentTimeMillis() + elapsed.get());
    }

    Config jwksConfig() {
        Config config = new Config();
        config.jwksUri = idp.url("/jwks.json");
        return config;
    }

    /** The token's {@code sub}, or {@code "anonymous"} - what the caller would be. */
    static String subOf(JwtVerifier verifier, String token) {
        JwtVerifier.Verified verified = verifier.verify(token);
        return verified == null ? "anonymous" : (String) verified.claims().get("sub");
    }

    static String alice(SigningKey key) {
        return sign(key, claims("sub", "alice", "roles", List.of("ADMIN")));
    }

    long now() {
        return (System.currentTimeMillis() + elapsed.get()) / 1000;
    }

    @Nested
    class Jwks {

        @Test
        void verifiesATokenSignedByAKeyOfTheSetFetchingTheSetOnlyOnce() {
            JwtVerifier verifier = verifier(jwksConfig());
            assertEquals("alice", subOf(verifier, alice(KEY_A)));
            assertEquals("alice", subOf(verifier, alice(KEY_A)));
            assertEquals(1, idp.fetches("/jwks.json"));
        }

        @Test
        void reFetchesTheSetWhenATokenIsSignedByAKeyRotatedInSinceTheLastFetch() {
            JwtVerifier verifier = verifier(jwksConfig());
            assertEquals("alice", subOf(verifier, alice(KEY_A)));
            published.add(KEY_B.jwk());
            advance(31_000);
            assertEquals("alice", subOf(verifier, alice(KEY_B)));
            assertEquals(2, idp.fetches("/jwks.json"));
        }

        @Test
        void reFetchesAtMostOncePerCooldownHoweverManyUnknownKidsComeIn() {
            JwtVerifier verifier = verifier(jwksConfig());
            assertEquals("alice", subOf(verifier, alice(KEY_A)));
            advance(31_000);
            for (String kid : List.of("forged-1", "forged-2", "forged-3")) {
                assertEquals("anonymous", subOf(verifier, sign(OUTSIDER.withKid(kid), claims("sub", "mallory"))));
            }
            assertEquals(2, idp.fetches("/jwks.json"));
        }

        @Test
        void sharesASingleFetchBetweenConcurrentRequests() {
            JwtVerifier verifier = verifier(jwksConfig());
            List<CompletableFuture<String>> names = IntStream.range(0, 5)
                    .mapToObj(i -> CompletableFuture.supplyAsync(() -> subOf(verifier, alice(KEY_A)))).toList();
            names.forEach(name -> assertEquals("alice", name.join()));
            assertEquals(1, idp.fetches("/jwks.json"));
        }

        @Test
        void reFetchesTheSetOnceTheCacheMaxAgeHasElapsedDroppingWithdrawnKeys() {
            Config config = jwksConfig();
            config.maxAge = Duration.ofSeconds(60);
            JwtVerifier verifier = verifier(config);
            assertEquals("alice", subOf(verifier, alice(KEY_A)));
            published.clear();
            published.add(KEY_B.jwk());
            advance(61_000);
            assertEquals("anonymous", subOf(verifier, alice(KEY_A)));
            assertEquals(2, idp.fetches("/jwks.json"));
        }

        @Test
        void keepsTheLastKnownKeysWhenAFetchFails() {
            Config config = jwksConfig();
            config.maxAge = Duration.ofSeconds(60);
            JwtVerifier verifier = verifier(config);
            assertEquals("alice", subOf(verifier, alice(KEY_A)));
            idp.status.put("/jwks.json", 503);
            advance(61_000);
            assertEquals("alice", subOf(verifier, alice(KEY_A)));
            assertEquals(2, idp.fetches("/jwks.json"));
            assertTrue(warnings().contains("JWKS fetch failed"), warnings());
        }

        @Test
        void doesNotReFetchForAnExpiredTokenItsKeyIsKnown() {
            JwtVerifier verifier = verifier(jwksConfig());
            assertEquals("alice", subOf(verifier, alice(KEY_A)));
            advance(31_000);
            assertEquals("anonymous", subOf(verifier, sign(KEY_A, claims("sub", "alice", "exp", now() - 60))));
            assertEquals(1, idp.fetches("/jwks.json"));
            assertTrue(warnings().contains("jwt expired"), warnings());
        }

        @Test
        void doesNotReFetchForATokenRejectedOnItsAudienceItsKeyIsKnown() {
            Config config = jwksConfig();
            config.audience = List.of("orders-api");
            JwtVerifier verifier = verifier(config);
            assertEquals("alice", subOf(verifier, sign(KEY_A, claims("sub", "alice", "aud", "orders-api"))));
            advance(31_000);
            assertEquals("anonymous", subOf(verifier, sign(KEY_A, claims("sub", "alice", "aud", "billing-api"))));
            assertEquals(1, idp.fetches("/jwks.json"));
            assertTrue(warnings().contains("jwt audience invalid"), warnings());
        }

        @Test
        void triesEveryKeyWhenTheTokenCarriesNoKid() {
            published.add(KEY_B.jwk());
            assertEquals("alice", subOf(verifier(jwksConfig()), sign("RS256", null, KEY_B.pair().getPrivate(), claims("sub", "alice"))));
        }

        @Test
        void ignoresSymmetricAndEncryptionKeysPublishedInTheSet() {
            String secret = "shared-secret-shared-secret-shared-secret";
            published.clear();
            published.add(Map.of("kty", "oct", "k", Base64.getUrlEncoder().withoutPadding().encodeToString(secret.getBytes(StandardCharsets.UTF_8)), "kid", "hmac"));
            published.add(KEY_B.jwkWith("use", "enc"));
            JwtVerifier verifier = verifier(jwksConfig());
            assertEquals("anonymous", subOf(verifier, JwtTestSupport.signHmac(secret, "hmac", claims("sub", "mallory"))));
            assertEquals("anonymous", subOf(verifier, alice(KEY_B)));
        }

        @Test
        void yieldsAnonymousWhenTheJwksEndpointTimesOut() {
            Config config = jwksConfig();
            config.jwksUri = idp.url("/hang");
            config.timeout = Duration.ofMillis(200);
            assertEquals("anonymous", subOf(verifier(config), alice(KEY_A)));
            assertTrue(warnings().contains("JWKS fetch failed"), warnings());
        }

        @Test
        void neverLogsTheToken() {
            String token = sign(OUTSIDER, claims("sub", "mallory"));
            subOf(verifier(jwksConfig()), token);
            assertFalse(warnings().contains(token));
            assertFalse(warnings().contains(token.substring(0, 20)));
        }

        @Test
        void aMalformedTokenIsAnonymous() {
            assertEquals("anonymous", subOf(verifier(jwksConfig()), "not.a.token"));
            assertEquals("anonymous", subOf(verifier(jwksConfig()), "abc"));
            assertTrue(warnings().contains("jwt malformed"), warnings());
        }
    }

    @Nested
    class Algorithm {

        @BeforeEach
        void publish() {
            published.clear();
            published.addAll(List.of(KEY_A.jwk(), EC.jwk(), ED.jwk()));
        }

        @Test
        void verifiesRs256Es256AndEdDsaTokensAgainstTheSameSetWithNoAlgorithmConfigured() {
            JwtVerifier verifier = verifier(jwksConfig());
            assertEquals("rsa", subOf(verifier, sign(KEY_A, claims("sub", "rsa"))));
            assertEquals("ec", subOf(verifier, sign(EC, claims("sub", "ec"))));
            assertEquals("ed", subOf(verifier, sign(ED, claims("sub", "ed"))));
            assertEquals(1, idp.fetches("/jwks.json"));
            assertEquals("", warnings());
        }

        @Test
        void rejectsATokenWhoseKidIsNotInTheSet() {
            assertEquals("anonymous", subOf(verifier(jwksConfig()), sign(KEY_A.withKid("unknown"), claims("sub", "alice"))));
            assertTrue(warnings().contains("no JWKS key matches the token"), warnings());
        }

        @Test
        void rejectsATokenAnnouncingAnotherAlgorithmThanItsKey() throws Exception {
            JwtVerifier verifier = verifier(jwksConfig());
            // Each of these would verify if the token's alg were trusted.
            String rs384 = sign("RS384", KEY_A.kid(), KEY_A.pair().getPrivate(), claims("sub", "mallory"));
            String pem = "-----BEGIN PUBLIC KEY-----\n" + Base64.getMimeEncoder().encodeToString(KEY_A.pair().getPublic().getEncoded()) + "\n-----END PUBLIC KEY-----\n";
            String hs256 = JwtTestSupport.signHmac(pem, KEY_A.kid(), claims("sub", "mallory"));
            String none = JwtTestSupport.unsigned(KEY_A.kid(), claims("sub", "mallory"));
            for (String token : List.of(rs384, hs256, none)) {
                logged.clear();
                assertEquals("anonymous", subOf(verifier, token));
                assertTrue(warnings().contains("invalid algorithm"), warnings());
            }
        }

        @Test
        void usedAsAnAllowlistRejectsTheKeysOfAnyOtherAlgorithm() {
            Config config = jwksConfig();
            config.algorithm = List.of("RS256", "EdDSA");
            JwtVerifier verifier = verifier(config);
            assertEquals("alice", subOf(verifier, alice(KEY_A)));
            assertEquals("alice", subOf(verifier, alice(ED)));
            assertEquals("anonymous", subOf(verifier, alice(EC)));
            assertTrue(warnings().contains("invalid algorithm"), warnings());
            Config es256 = jwksConfig();
            es256.algorithm = List.of("ES256");
            assertEquals("alice", subOf(verifier(es256), alice(EC)));
            assertEquals("anonymous", subOf(verifier(es256), alice(KEY_A)));
        }

        @Test
        void refusesNoneAndHsAtStartupAndEdDsaWithoutAJwks() {
            Config hs = jwksConfig();
            hs.algorithm = List.of("HS256");
            assertThrows(IllegalStateException.class, () -> JwtSettings.of(hs), "HS256 cannot be used with jwks-uri");
            Config none = jwksConfig();
            none.algorithm = List.of("RS256", "none");
            assertTrue(assertThrows(IllegalStateException.class, () -> JwtSettings.of(none)).getMessage().contains("none"));
            Config pem = new Config();
            pem.publicKey = "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----";
            pem.algorithm = List.of("EdDSA");
            assertTrue(assertThrows(IllegalStateException.class, () -> JwtSettings.of(pem)).getMessage().contains("EdDSA is only supported"));
        }

        @Test
        void infersTheAlgorithmOfAKeyPublishedWithoutAlgFromItsType() {
            published.clear();
            published.addAll(List.of(KEY_A.jwkWithoutAlg(), EC.jwkWithoutAlg(), ED.jwkWithoutAlg()));
            JwtVerifier verifier = verifier(jwksConfig());
            assertEquals("alice", subOf(verifier, alice(KEY_A)));
            assertEquals("alice", subOf(verifier, alice(EC)));
            assertEquals("alice", subOf(verifier, alice(ED)));
            // An RSA key without alg is taken as RS256, whatever the token says.
            assertEquals("anonymous", subOf(verifier, sign("RS384", KEY_A.kid(), KEY_A.pair().getPrivate(), claims("sub", "alice"))));
        }

        @Test
        void letsTheAllowlistChooseTheAlgorithmOfAKeyPublishedWithoutAlg() {
            published.clear();
            published.add(KEY_A.jwkWithoutAlg());
            String ps256 = sign("PS256", KEY_A.kid(), KEY_A.pair().getPrivate(), claims("sub", "alice"));
            assertEquals("anonymous", subOf(verifier(jwksConfig()), ps256));
            Config allow = jwksConfig();
            allow.algorithm = List.of("PS256");
            assertEquals("alice", subOf(verifier(allow), ps256));
            assertEquals("anonymous", subOf(verifier(allow), alice(KEY_A)));
        }

        @Test
        void ignoresAKeyWhoseAlgItsTypeCannotVerify() {
            published.clear();
            published.addAll(List.of(KEY_A.jwkWith("alg", "ES256"), EC.jwkWith("alg", "HS256")));
            JwtVerifier verifier = verifier(jwksConfig());
            assertEquals("anonymous", subOf(verifier, alice(KEY_A)));
            assertEquals("anonymous", subOf(verifier, alice(EC)));
        }

        @Test
        void eddsaRejectsATamperedToken() {
            String[] parts = sign(ED, claims("sub", "alice")).split("\\.");
            String forged = parts[0] + "." + Base64.getUrlEncoder().withoutPadding().encodeToString("{\"sub\":\"mallory\"}".getBytes(StandardCharsets.UTF_8)) + "." + parts[2];
            assertEquals("anonymous", subOf(verifier(jwksConfig()), forged));
            assertTrue(warnings().contains("invalid signature"), warnings());
        }

        @Test
        void eddsaRejectsATokenSignedByAnotherEd25519Key() {
            assertEquals("anonymous", subOf(verifier(jwksConfig()), sign(ed("other").withKid(ED.kid()), claims("sub", "mallory"))));
        }

        @Test
        void eddsaChecksTheValidityDatesWithoutReFetching() {
            JwtVerifier verifier = verifier(jwksConfig());
            assertEquals("alice", subOf(verifier, sign(ED, claims("sub", "alice", "nbf", now() - 60, "exp", now() + 60))));
            advance(31_000);
            assertEquals("anonymous", subOf(verifier, sign(ED, claims("sub", "alice", "exp", now() - 60))));
            assertEquals("anonymous", subOf(verifier, sign(ED, claims("sub", "alice", "nbf", now() + 600))));
            assertEquals(1, idp.fetches("/jwks.json"));
            assertTrue(warnings().matches("(?s).*jwt expired.*jwt not active.*"), warnings());
        }

        @Test
        void eddsaChecksIssuerAndAudienceWhenConfigured() {
            Config config = jwksConfig();
            config.issuer = List.of("https://idp.acme", "https://gateway.acme");
            config.audience = List.of("/^orders-/");
            JwtVerifier verifier = verifier(config);
            Map<String, Object> ok = claims("sub", "alice", "iss", "https://gateway.acme", "aud", List.of("billing-api", "orders-api"));
            assertEquals("alice", subOf(verifier, sign(ED, ok)));
            assertEquals("anonymous", subOf(verifier, sign(ED, claims("sub", "alice", "iss", "https://evil.example", "aud", "orders-api"))));
            assertEquals("anonymous", subOf(verifier, sign(ED, claims("sub", "alice", "iss", "https://gateway.acme", "aud", "billing-api"))));
            assertEquals("anonymous", subOf(verifier, sign(ED, claims("sub", "alice"))));
            assertTrue(warnings().matches("(?s).*issuer invalid.*audience invalid.*"), warnings());
        }
    }

    @Nested
    class DiscoveryUris {

        final SigningKey keyIdpA = rsa("idp-a");
        final SigningKey keyIdpB = ec("idp-b");

        @BeforeEach
        void documents() {
            idp.discovery("/a/.well-known/openid-configuration", "https://idp-a", "/a/jwks");
            idp.discovery("/b/.well-known/openid-configuration", "https://idp-b", "/b/jwks");
            idp.routes.put("/a/jwks", () -> jwks(List.of(keyIdpA.jwk())));
            idp.routes.put("/b/jwks", () -> jwks(List.of(keyIdpB.jwk())));
        }

        Config twoProviders() {
            return new Config().provider(Provider.uri(idp.url("/a"))).provider(Provider.uri(idp.url("/b/.well-known/openid-configuration")));
        }

        @Test
        void verifiesTheTokensOfEachProviderWithItsOwnKeysUnderTheIssuerItsDocumentAnnounces() {
            JwtVerifier verifier = verifier(twoProviders());
            assertEquals("alice", subOf(verifier, sign(keyIdpA, claims("sub", "alice", "iss", "https://idp-a"))));
            assertEquals("bob", subOf(verifier, sign(keyIdpB, claims("sub", "bob", "iss", "https://idp-b"))));
            assertEquals(1, idp.fetches("/a/jwks"));
            assertEquals(1, idp.fetches("/b/jwks"));
        }

        @Test
        void neverVerifiesATokenWithTheKeysOfAnotherProviderThanItsIssuer() {
            JwtVerifier verifier = verifier(twoProviders());
            assertEquals("anonymous", subOf(verifier, sign(keyIdpA, claims("sub", "mallory", "iss", "https://idp-b"))));
        }

        @Test
        void rejectsAnUnknownIssuerWithoutFetchingAnyKeyAndNeverFetchesAUrlFromTheToken() throws Exception {
            JwtVerifier verifier = verifier(twoProviders());
            String token = sign(keyIdpA, claims("sub", "mallory", "iss", idp.url("/evil")));
            assertEquals("anonymous", subOf(verifier, token));
            assertEquals(0, idp.fetches("/a/jwks"));
            assertEquals(0, idp.fetches("/b/jwks"));
            assertEquals(0, idp.fetches("/evil"));
            assertEquals(0, idp.fetches("/evil/.well-known/openid-configuration"));
            assertTrue(warnings().contains("jwt issuer invalid. expected: "), warnings());
        }

        @Test
        void takesTheUrlTheDocumentLivesUnderWithOrWithoutATrailingSlash() {
            JwtVerifier verifier = verifier(new Config().provider(Provider.uri(idp.url("/a/"))));
            assertEquals("alice", subOf(verifier, sign(keyIdpA, claims("sub", "alice", "iss", "https://idp-a"))));
        }

        @Test
        void keepsServingTheOtherProvidersWhileOneDocumentFailsAndRetriesItAfterTheCooldown() {
            idp.status.put("/b/.well-known/openid-configuration", 500);
            JwtVerifier verifier = verifier(twoProviders());
            assertEquals("alice", subOf(verifier, sign(keyIdpA, claims("sub", "alice", "iss", "https://idp-a"))));
            assertEquals("anonymous", subOf(verifier, sign(keyIdpB, claims("sub", "bob", "iss", "https://idp-b"))));
            assertTrue(warnings().contains("OpenID configuration fetch failed"), warnings());
            idp.status.remove("/b/.well-known/openid-configuration");
            advance(31_000);
            assertEquals("bob", subOf(verifier, sign(keyIdpB, claims("sub", "bob", "iss", "https://idp-b"))));
        }

        @Test
        void rejectsADocumentWithoutIssuerOrJwksUri() {
            idp.routes.put("/a/.well-known/openid-configuration", () -> Map.of("issuer", "https://idp-a"));
            assertEquals("anonymous", subOf(verifier(new Config().provider(Provider.uri(idp.url("/a")))),
                    sign(keyIdpA, claims("sub", "alice", "iss", "https://idp-a"))));
            assertTrue(warnings().contains("no \"issuer\" or \"jwks_uri\" in the response"), warnings());
        }

        @Test
        void followsTheJwksUriOfAReFetchedDocument() {
            Config config = new Config().provider(Provider.uri(idp.url("/a")));
            config.maxAge = Duration.ofSeconds(60);
            JwtVerifier verifier = verifier(config);
            assertEquals("alice", subOf(verifier, sign(keyIdpA, claims("sub", "alice", "iss", "https://idp-a"))));
            SigningKey rotated = rsa("idp-a-2");
            idp.routes.put("/a/jwks-2", () -> jwks(List.of(rotated.jwk())));
            idp.discovery("/a/.well-known/openid-configuration", "https://idp-a", "/a/jwks-2");
            advance(61_000);
            assertEquals("alice", subOf(verifier, sign(rotated, claims("sub", "alice", "iss", "https://idp-a"))));
            assertEquals(1, idp.fetches("/a/jwks-2"));
        }

        @Test
        void checksTheAudienceOfEveryProviderAndOfAnEntryInPlaceOfTheGlobalOne() {
            Provider b = Provider.uri(idp.url("/b"));
            b.audience = List.of("billing-api");
            Config config = new Config().provider(Provider.uri(idp.url("/a"))).provider(b);
            config.audience = List.of("orders-api");
            JwtVerifier verifier = verifier(config);
            assertEquals("alice", subOf(verifier, sign(keyIdpA, claims("sub", "alice", "iss", "https://idp-a", "aud", "orders-api"))));
            assertEquals("anonymous", subOf(verifier, sign(keyIdpA, claims("sub", "alice", "iss", "https://idp-a", "aud", "billing-api"))));
            assertEquals("bob", subOf(verifier, sign(keyIdpB, claims("sub", "bob", "iss", "https://idp-b", "aud", "billing-api"))));
            assertEquals("anonymous", subOf(verifier, sign(keyIdpB, claims("sub", "bob", "iss", "https://idp-b", "aud", "orders-api"))));
        }

        @Test
        void cohabitsWithJwksUriWhoseKeysOnlyVerifyTheTokensOfItsIssuer() {
            Config config = twoProviders();
            config.jwksUri = idp.url("/jwks.json");
            config.issuer = List.of("https://legacy");
            JwtVerifier verifier = verifier(config);
            assertEquals("alice", subOf(verifier, sign(KEY_A, claims("sub", "alice", "iss", "https://legacy"))));
            assertEquals("anonymous", subOf(verifier, sign(KEY_A, claims("sub", "mallory", "iss", "https://idp-a"))));
            assertEquals("bob", subOf(verifier, sign(keyIdpB, claims("sub", "bob", "iss", "https://idp-b"))));
        }

        @Nested
        class BearerToken {

            @TempDir
            Path dir;

            @Test
            void sendsTheTokenToItsDocumentAndToTheJwksUriItAnnouncesNeverToAnotherProvider() throws Exception {
                Path file = Files.writeString(dir.resolve("token"), "sa-token\n");
                Provider a = Provider.uri(idp.url("/a"));
                a.bearerTokenFile = file.toString();
                JwtVerifier verifier = verifier(new Config().provider(a).provider(Provider.uri(idp.url("/b"))));
                assertEquals("alice", subOf(verifier, sign(keyIdpA, claims("sub", "alice", "iss", "https://idp-a"))));
                assertEquals("bob", subOf(verifier, sign(keyIdpB, claims("sub", "bob", "iss", "https://idp-b"))));
                assertEquals(List.of("Bearer sa-token"), idp.authorizations.get("/a/.well-known/openid-configuration"));
                assertEquals(List.of("Bearer sa-token"), idp.authorizations.get("/a/jwks"));
                assertEquals(java.util.Collections.singletonList(null), idp.authorizations.get("/b/.well-known/openid-configuration"));
                assertEquals(java.util.Collections.singletonList(null), idp.authorizations.get("/b/jwks"));
            }

            @Test
            void readsTheFileAtEveryFetchSoARotatedTokenIsPickedUp() throws Exception {
                Path file = Files.writeString(dir.resolve("token"), "first");
                Provider a = Provider.uri(idp.url("/a"));
                a.bearerTokenFile = file.toString();
                Config config = new Config().provider(a);
                config.maxAge = Duration.ofSeconds(60);
                JwtVerifier verifier = verifier(config);
                subOf(verifier, sign(keyIdpA, claims("sub", "alice", "iss", "https://idp-a")));
                Files.writeString(file, "second");
                advance(61_000);
                subOf(verifier, sign(keyIdpA, claims("sub", "alice", "iss", "https://idp-a")));
                assertEquals(List.of("Bearer first", "Bearer second"), idp.authorizations.get("/a/jwks"));
            }

            @Test
            void keepsServingTheOtherProvidersWhenTheTokenFileIsMissing() {
                Provider a = Provider.uri(idp.url("/a"));
                a.bearerTokenFile = dir.resolve("missing").toString();
                JwtVerifier verifier = verifier(new Config().provider(a).provider(Provider.uri(idp.url("/b"))));
                assertEquals("bob", subOf(verifier, sign(keyIdpB, claims("sub", "bob", "iss", "https://idp-b"))));
                assertEquals("anonymous", subOf(verifier, sign(keyIdpA, claims("sub", "alice", "iss", "https://idp-a"))));
            }

            @Test
            void refusesAnEntryWithoutAUrl() {
                Provider empty = new Provider();
                empty.bearerTokenFile = "/var/run/token";
                assertTrue(assertThrows(IllegalStateException.class, () -> JwtSettings.of(new Config().provider(empty))).getMessage().contains("needs a uri"));
            }
        }

        @Nested
        class GivenIssuerAndJwks {

            @TempDir
            Path dir;

            Provider kubernetes() {
                Provider provider = new Provider();
                provider.issuer = "https://kubernetes.default.svc.cluster.local";
                provider.jwksUri = idp.url("/k8s/jwks");
                provider.bypass = List.of("system:serviceaccount:my-namespace:*");
                return provider;
            }

            final SigningKey k8s = rsa("k8s");

            @BeforeEach
            void keys() {
                idp.routes.put("/k8s/jwks", () -> jwks(List.of(k8s.jwk())));
            }

            @Test
            void verifiesItsTokensWithTheGivenJwkSetReadingNoDiscoveryDocumentAndSendsTheTokenThere() throws Exception {
                Provider provider = kubernetes();
                provider.bearerTokenFile = Files.writeString(dir.resolve("token"), "sa").toString();
                JwtVerifier verifier = verifier(new Config().provider(provider));
                assertEquals("system:serviceaccount:my-namespace:reports",
                        subOf(verifier, sign(k8s, claims("sub", "system:serviceaccount:my-namespace:reports", "iss", provider.issuer))));
                assertEquals(List.of("Bearer sa"), idp.authorizations.get("/k8s/jwks"));
                assertEquals(0, idp.fetches("/k8s/.well-known/openid-configuration"));
            }

            @Test
            void keepsItsBypassAndGivesItToItsOwnTokensOnly() {
                JwtVerifier verifier = verifier(new Config().provider(kubernetes()).provider(Provider.uri(idp.url("/a"))));
                JwtVerifier.Verified sa = verifier.verify(sign(k8s, claims("sub", "system:serviceaccount:my-namespace:reports", "iss",
                        "https://kubernetes.default.svc.cluster.local")));
                assertTrue(sa.bypass());
                JwtVerifier.Verified same = verifier.verify(sign(keyIdpA, claims("sub", "system:serviceaccount:my-namespace:reports", "iss", "https://idp-a")));
                assertNotNull(same);
                assertFalse(same.bypass());
            }

            @Test
            void routesByTheGivenIssuerItsKeysNeverVerifyATokenClaimingAnother() {
                JwtVerifier verifier = verifier(new Config().provider(kubernetes()));
                assertEquals("anonymous", subOf(verifier, sign(k8s, claims("sub", "x", "iss", "https://elsewhere"))));
            }

            @Test
            void checksItsOwnAudience() {
                Provider provider = kubernetes();
                provider.audience = List.of("my-service");
                JwtVerifier verifier = verifier(new Config().provider(provider));
                assertEquals("anonymous", subOf(verifier, sign(k8s, claims("sub", "x", "iss", provider.issuer, "aud", "other"))));
                assertEquals("x", subOf(verifier, sign(k8s, claims("sub", "x", "iss", provider.issuer, "aud", "my-service"))));
            }

            @Test
            void refusesAnIssuerWithoutAJwkSetOrTheReverse() {
                Provider issuerOnly = new Provider();
                issuerOnly.issuer = "https://k8s";
                issuerOnly.uri = "https://k8s";
                assertThrows(IllegalStateException.class, () -> JwtSettings.of(new Config().provider(issuerOnly)));
                Provider jwksOnly = new Provider();
                jwksOnly.jwksUri = "https://k8s/jwks";
                assertThrows(IllegalStateException.class, () -> JwtSettings.of(new Config().provider(jwksOnly)));
            }
        }

        @Nested
        class Bypass {

            Config bypassing(String... patterns) {
                Provider a = Provider.uri(idp.url("/a"));
                a.bypass = List.of(patterns);
                return new Config().provider(a).provider(Provider.uri(idp.url("/b")));
            }

            @Test
            void flagsAVerifiedTokenOfItsProviderWhoseSubMatches() {
                JwtVerifier.Verified verified = verifier(bypassing("system:serviceaccount:ns:*"))
                        .verify(sign(keyIdpA, claims("sub", "system:serviceaccount:ns:reports", "iss", "https://idp-a")));
                assertTrue(verified.bypass());
            }

            @Test
            void ignoresASubOutsideThePatterns() {
                assertFalse(verifier(bypassing("system:serviceaccount:ns:*"))
                        .verify(sign(keyIdpA, claims("sub", "system:serviceaccount:other:reports", "iss", "https://idp-a"))).bypass());
            }

            @Test
            void neverFlagsTheSameSubFromAnotherProvider() {
                assertFalse(verifier(bypassing("system:serviceaccount:ns:*"))
                        .verify(sign(keyIdpB, claims("sub", "system:serviceaccount:ns:reports", "iss", "https://idp-b"))).bypass());
            }

            @Test
            void neverFlagsATokenThatFailsVerification() {
                assertNull(verifier(bypassing("*")).verify(sign(OUTSIDER.withKid("idp-a"), claims("sub", "system:serviceaccount:ns:x", "iss", "https://idp-a"))));
            }

            @Test
            void takesStarAsAnyRunOfCharactersAndTheRestLiterally() {
                JwtVerifier verifier = verifier(bypassing("svc.*-reader"));
                assertTrue(verifier.verify(sign(keyIdpA, claims("sub", "svc.orders-reader", "iss", "https://idp-a"))).bypass());
                assertFalse(verifier.verify(sign(keyIdpA, claims("sub", "svcXorders-reader", "iss", "https://idp-a"))).bypass());
            }
        }

        @Test
        void refusesAnAmbiguousConfigurationAtStartup() {
            Config pemAndDiscovery = twoProviders();
            pemAndDiscovery.publicKey = "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----";
            assertThrows(IllegalStateException.class, () -> JwtSettings.of(pemAndDiscovery));
            Config issuerWithoutJwks = twoProviders();
            issuerWithoutJwks.issuer = List.of("https://x");
            assertThrows(IllegalStateException.class, () -> JwtSettings.of(issuerWithoutJwks));
            Config jwksWithoutIssuer = twoProviders();
            jwksWithoutIssuer.jwksUri = idp.url("/jwks.json");
            assertThrows(IllegalStateException.class, () -> JwtSettings.of(jwksWithoutIssuer));
            Config jwksAndPem = jwksConfig();
            jwksAndPem.publicKey = "x";
            assertThrows(IllegalStateException.class, () -> JwtSettings.of(jwksAndPem));
            Config issuerWithoutKey = new Config();
            issuerWithoutKey.issuer = List.of("https://x");
            assertTrue(assertThrows(IllegalStateException.class, () -> JwtSettings.of(issuerWithoutKey)).getMessage().contains("need a key"));
        }
    }

    @Nested
    class PemKey {

        Config pem(SigningKey key, String... algorithms) {
            Config config = new Config();
            config.publicKey = "-----BEGIN PUBLIC KEY-----\n" + Base64.getMimeEncoder().encodeToString(key.pair().getPublic().getEncoded()) + "\n-----END PUBLIC KEY-----\n";
            config.algorithm = algorithms.length == 0 ? null : List.of(algorithms);
            return config;
        }

        @Test
        void defaultsToEs256WithAPemKey() {
            assertEquals("alice", subOf(verifier(pem(EC)), sign(EC, claims("sub", "alice"))));
            // An RSA key no longer works by default: RS256 has to be asked for.
            assertEquals("anonymous", subOf(verifier(pem(KEY_A)), alice(KEY_A)));
            assertEquals("alice", subOf(verifier(pem(KEY_A, "RS256")), alice(KEY_A)));
        }

        @Test
        void verifiesWithASharedSecretUnderHs256() {
            Config config = new Config();
            config.publicKey = "test-secret";
            config.algorithm = List.of("HS256");
            JwtVerifier verifier = verifier(config);
            assertEquals("alice", subOf(verifier, JwtTestSupport.signHmac("test-secret", null, claims("sub", "alice"))));
            assertEquals("anonymous", subOf(verifier, JwtTestSupport.signHmac("other-secret", null, claims("sub", "alice"))));
        }

        @Test
        void acceptsAListOfAlgorithms() {
            assertEquals("alice", subOf(verifier(pem(KEY_A, "RS384", "RS256")), alice(KEY_A)));
            assertEquals("anonymous", subOf(verifier(pem(KEY_A, "RS384", "RS512")), alice(KEY_A)));
        }

        @Test
        void yieldsAnonymousOnAFailedVerificationWrongKey() {
            assertEquals("anonymous", subOf(verifier(pem(KEY_B, "RS256")), alice(KEY_A)));
        }

        @Test
        void checksIssuerAndAudienceAndLeavesThemUncheckedWhenUnset() {
            Map<String, Object> claims = claims("sub", "alice", "iss", "https://gateway.acme", "aud", "orders-api");
            assertEquals("alice", subOf(verifier(pem(EC)), sign(EC, claims("sub", "alice", "iss", "https://elsewhere", "aud", "billing-api"))));
            Config checked = pem(EC);
            checked.issuer = List.of("https://idp.acme", "https://gateway.acme");
            checked.audience = List.of("/^orders-/");
            JwtVerifier verifier = verifier(checked);
            assertEquals("alice", subOf(verifier, sign(EC, claims)));
            assertEquals("anonymous", subOf(verifier, sign(EC, claims("sub", "alice", "iss", "https://evil.example", "aud", "orders-api"))));
            assertEquals("anonymous", subOf(verifier, sign(EC, claims("sub", "alice", "iss", "https://gateway.acme", "aud", "billing-api"))));
            assertTrue(warnings().matches("(?s).*issuer invalid.*audience invalid.*"), warnings());
        }

        @Test
        void neverLogsTheTokenOrTheKey() {
            Config config = new Config();
            config.publicKey = "other-secret";
            config.algorithm = List.of("HS256");
            String token = JwtTestSupport.signHmac("test-secret", null, claims("sub", "alice"));
            subOf(verifier(config), token);
            assertFalse(warnings().contains(token));
            assertFalse(warnings().contains("other-secret"));
        }
    }
}
