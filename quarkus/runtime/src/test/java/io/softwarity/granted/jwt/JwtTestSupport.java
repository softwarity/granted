package io.softwarity.granted.jwt;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.keys.HmacKey;

import javax.net.ssl.SSLContext;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;

import io.softwarity.granted.GrantedConfig;

/** Keys, tokens, a local IdP and a configuration to build - the fixtures of nestjs-granted's jwks.spec.ts. */
final class JwtTestSupport {

    private JwtTestSupport() {
    }

    /** A signing key: its private half, and its public half as a JWK with {@code kid}, {@code use} and {@code alg}. */
    record SigningKey(String kid, String alg, KeyPair pair, Map<String, Object> jwk) {

        SigningKey withKid(String other) {
            return new SigningKey(other, alg, pair, jwk);
        }

        /** The same key, published without {@code alg} - as Microsoft Entra ID does. */
        Map<String, Object> jwkWithoutAlg() {
            Map<String, Object> copy = new LinkedHashMap<>(jwk);
            copy.remove("alg");
            return copy;
        }

        Map<String, Object> jwkWith(String key, Object value) {
            Map<String, Object> copy = new LinkedHashMap<>(jwk);
            copy.put(key, value);
            return copy;
        }
    }

    static SigningKey rsa(String kid) {
        return key(kid, "RS256", generate("RSA", null));
    }

    static SigningKey ec(String kid) {
        return key(kid, "ES256", generate("EC", "secp256r1"));
    }

    static SigningKey ed(String kid) {
        return key(kid, "EdDSA", generate("Ed25519", null));
    }

    private static KeyPair generate(String type, String curve) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(type);
            if (curve != null) {
                generator.initialize(new ECGenParameterSpec(curve));
            } else if (type.equals("RSA")) {
                generator.initialize(2048);
            }
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static SigningKey key(String kid, String alg, KeyPair pair) {
        try {
            Map<String, Object> jwk = new LinkedHashMap<>(PublicJsonWebKey.Factory.newPublicJwk(pair.getPublic())
                    .toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY));
            jwk.put("kid", kid);
            jwk.put("use", "sig");
            jwk.put("alg", alg);
            return new SigningKey(kid, alg, pair, jwk);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static Map<String, Object> claims(Object... pairs) {
        Map<String, Object> claims = new LinkedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2) {
            claims.put((String) pairs[i], pairs[i + 1]);
        }
        return claims;
    }

    /** Signed with the key's own algorithm and kid. */
    static String sign(SigningKey key, Map<String, Object> claims) {
        return sign(key.alg(), key.kid(), key.pair().getPrivate(), claims);
    }

    static String sign(String alg, String kid, java.security.Key key, Map<String, Object> claims) {
        try {
            JsonWebSignature jws = new JsonWebSignature();
            jws.setPayload(JsonUtil.toJson(claims));
            jws.setAlgorithmHeaderValue(alg);
            if (kid != null) {
                jws.setKeyIdHeaderValue(kid);
            }
            jws.setKey(key);
            jws.setDoKeyValidation(false);
            return jws.getCompactSerialization();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static String signHmac(String secret, String kid, Map<String, Object> claims) {
        return sign("HS256", kid, new HmacKey(secret.getBytes(StandardCharsets.UTF_8)), claims);
    }

    /** {@code alg: none}: a header and a payload, no signature. */
    static String unsigned(String kid, Map<String, Object> claims) {
        java.util.Base64.Encoder base64 = java.util.Base64.getUrlEncoder().withoutPadding();
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", "none");
        header.put("kid", kid);
        return base64.encodeToString(JsonUtil.toJson(header).getBytes(StandardCharsets.UTF_8)) + "."
                + base64.encodeToString(JsonUtil.toJson(claims).getBytes(StandardCharsets.UTF_8)) + ".";
    }

    static PrivateKey privateKey(SigningKey key) {
        return key.pair().getPrivate();
    }

    static Map<String, Object> jwks(List<Map<String, Object>> keys) {
        return Map.of("keys", keys);
    }

    /** A local IdP: each path answers what its supplier gives, counts its fetches and keeps the Authorization headers. */
    static final class Idp implements AutoCloseable {

        final HttpServer server;

        final Map<String, Supplier<Object>> routes = new ConcurrentHashMap<>();

        final Map<String, Integer> status = new ConcurrentHashMap<>();

        final Map<String, AtomicInteger> fetches = new ConcurrentHashMap<>();

        final Map<String, List<String>> authorizations = new ConcurrentHashMap<>();

        /** {@code http://127.0.0.1}, or {@code https://<host>} when serving TLS. */
        private final String origin;

        Idp() throws IOException {
            this(null, null);
        }

        /** Over HTTPS, presenting the certificate of {@code tls}, reached as {@code host}. */
        Idp(SSLContext tls, String host) throws IOException {
            if (tls == null) {
                server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            } else {
                HttpsServer https = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
                https.setHttpsConfigurator(new HttpsConfigurator(tls));
                server = https;
            }
            origin = (tls == null ? "http://127.0.0.1" : "https://" + host) + ":" + server.getAddress().getPort();
            server.setExecutor(java.util.concurrent.Executors.newCachedThreadPool());
            server.createContext("/", exchange -> {
                String path = exchange.getRequestURI().getPath();
                if (path.equals("/hang")) {
                    try {
                        Thread.sleep(5_000);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                    exchange.close();
                    return;
                }
                fetches.computeIfAbsent(path, p -> new AtomicInteger()).incrementAndGet();
                authorizations.computeIfAbsent(path, p -> java.util.Collections.synchronizedList(new ArrayList<>()))
                        .add(exchange.getRequestHeaders().getFirst("Authorization"));
                Supplier<Object> route = routes.get(path);
                byte[] body = (route == null ? "{}" : JsonUtil.toJson(asMap(route.get()))).getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("content-type", "application/json");
                exchange.sendResponseHeaders(route == null ? 404 : status.getOrDefault(path, 200), body.length);
                try (OutputStream out = exchange.getResponseBody()) {
                    out.write(body);
                }
            });
            server.start();
        }

        @SuppressWarnings("unchecked")
        private static Map<String, ?> asMap(Object value) {
            return (Map<String, ?>) value;
        }

        String url(String path) {
            return origin + path;
        }

        int fetches(String path) {
            AtomicInteger count = fetches.get(path);
            return count == null ? 0 : count.get();
        }

        /** A discovery document at {@code path}, announcing {@code issuer} and the JWK Set at {@code jwksPath}. */
        void discovery(String path, String issuer, String jwksPath) {
            routes.put(path, () -> Map.of("issuer", issuer, "jwks_uri", url(jwksPath)));
        }

        @Override
        public void close() {
            server.stop(0);
        }
    }

    /** {@code granted.jwt.*}, as a test builds it. */
    static final class Config implements GrantedConfig.Jwt {

        String publicKey;
        List<String> algorithm;
        String jwksUri;
        List<GrantedConfig.Provider> discoveryUris = new ArrayList<>();
        Duration maxAge = Duration.ofMinutes(10);
        Duration cooldown = Duration.ofSeconds(30);
        Duration timeout = Duration.ofSeconds(5);
        List<String> issuer;
        List<String> audience;
        String tlsConfigurationName;

        Config provider(Provider provider) {
            discoveryUris.add(provider);
            return this;
        }

        @Override
        public Optional<GrantedConfig.Preset> preset() {
            return Optional.empty();
        }

        @Override
        public Optional<String> usernameClaim() {
            return Optional.empty();
        }

        @Override
        public Optional<String> rolesClaim() {
            return Optional.empty();
        }

        @Override
        public Optional<String> tenantClaim() {
            return Optional.empty();
        }

        @Override
        public Optional<String> publicKey() {
            return Optional.ofNullable(publicKey);
        }

        @Override
        public Optional<String> publicKeyFile() {
            return Optional.empty();
        }

        @Override
        public Optional<List<String>> algorithm() {
            return Optional.ofNullable(algorithm);
        }

        @Override
        public Optional<String> jwksUri() {
            return Optional.ofNullable(jwksUri);
        }

        @Override
        public List<GrantedConfig.Provider> discoveryUris() {
            return discoveryUris;
        }

        @Override
        public Duration jwksCacheMaxAge() {
            return maxAge;
        }

        @Override
        public Duration jwksCooldown() {
            return cooldown;
        }

        @Override
        public Duration jwksTimeout() {
            return timeout;
        }

        @Override
        public Optional<List<String>> issuer() {
            return Optional.ofNullable(issuer);
        }

        @Override
        public Optional<List<String>> audience() {
            return Optional.ofNullable(audience);
        }

        @Override
        public Optional<String> tlsConfigurationName() {
            return Optional.ofNullable(tlsConfigurationName);
        }
    }

    /** A {@code granted.jwt.discovery-uris[n]} entry. */
    static final class Provider implements GrantedConfig.Provider {

        String uri;
        String issuer;
        String jwksUri;
        String bearerTokenFile;
        List<String> audience;
        List<String> bypass;
        String tlsConfigurationName;
        boolean readiness = true;

        static Provider uri(String uri) {
            Provider provider = new Provider();
            provider.uri = uri;
            return provider;
        }

        @Override
        public Optional<String> uri() {
            return Optional.ofNullable(uri);
        }

        @Override
        public Optional<String> issuer() {
            return Optional.ofNullable(issuer);
        }

        @Override
        public Optional<String> jwksUri() {
            return Optional.ofNullable(jwksUri);
        }

        @Override
        public Optional<String> bearerTokenFile() {
            return Optional.ofNullable(bearerTokenFile);
        }

        @Override
        public Optional<List<String>> audience() {
            return Optional.ofNullable(audience);
        }

        @Override
        public Optional<List<String>> bypass() {
            return Optional.ofNullable(bypass);
        }

        @Override
        public Optional<String> tlsConfigurationName() {
            return Optional.ofNullable(tlsConfigurationName);
        }

        @Override
        public boolean readiness() {
            return readiness;
        }
    }

    static Map<String, Object> mutable(Map<String, Object> map) {
        return new HashMap<>(map);
    }
}
