package io.softwarity.granted.it.jwt;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;

import io.quarkus.test.common.QuarkusTestResourceLifecycleManager;

/**
 * A canopy service's world, over HTTPS: Meerkat's internal plane and the Kubernetes API server,
 * each with a certificate of its own CA - the two files of quarkus.tls.cluster.trust-store, as
 * TLS_CA_FILES gives them. The configuration is the one a canopy service runs with, the URLs local.
 *
 * <p>{@code /_control?jwks=503} makes Meerkat's JWK Set fail, {@code ?jwks=200} brings it back;
 * {@code /_fetches} counts the fetches of each path. Init arg {@code jwks}: Meerkat's status at
 * start; {@code cooldown}: granted.jwt.jwks-cooldown.
 */
public class CanopyIdp implements QuarkusTestResourceLifecycleManager {

    static final String MEERKAT = "https://meerkat.example";
    static final String KUBERNETES = "https://kubernetes.default.svc.cluster.local";

    private final List<HttpServer> servers = new ArrayList<>();
    private Map<String, String> args = Map.of();

    @Override
    public void init(Map<String, String> initArgs) {
        args = initArgs;
    }

    @Override
    public Map<String, String> start() {
        try {
            Path dir = Files.createTempDirectory("granted-canopy");
            KeyPair meerkatKey = Keys.generate("RSA");
            KeyPair k8sKey = Keys.generate("RSA");
            Keys.save(dir, "meerkat", meerkatKey);
            Keys.save(dir, "k8s", k8sKey);
            Path token = Files.writeString(dir.resolve("token"), "sa-token\n");
            TestCa meerkatCa = TestCa.create("meerkat internal CA");
            TestCa clusterCa = TestCa.create("kubernetes CA");
            Path meerkatCaFile = Files.writeString(dir.resolve("ca.crt"), meerkatCa.pem());
            Path clusterCaFile = Files.writeString(dir.resolve("serviceaccount-ca.crt"), clusterCa.pem());

            Map<String, Integer> status = new ConcurrentHashMap<>(Map.of("/jwks", Integer.parseInt(args.getOrDefault("jwks", "200"))));
            Map<String, Integer> fetches = new ConcurrentHashMap<>();
            Map<String, List<String>> authorizations = new ConcurrentHashMap<>();

            HttpsServer meerkat = https(meerkatCa);
            String meerkatUrl = "https://localhost:" + meerkat.getAddress().getPort();
            serve(meerkat, Map.of(
                    "/.well-known/openid-configuration", Map.of("issuer", MEERKAT, "jwks_uri", meerkatUrl + "/jwks"),
                    "/jwks", Map.of("keys", List.of(jwk(meerkatKey, "meerkat")))), status, fetches, authorizations);
            HttpsServer kubernetes = https(clusterCa);
            String kubernetesUrl = "https://localhost:" + kubernetes.getAddress().getPort();
            serve(kubernetes, Map.of("/openid/v1/jwks", Map.of("keys", List.of(jwk(k8sKey, "k8s")))), status, fetches, authorizations);

            // Plain HTTP, for the tests to steer and observe the IdPs.
            HttpServer control = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            control.createContext("/", exchange -> {
                String query = exchange.getRequestURI().getQuery();
                if (query != null && query.startsWith("jwks=")) {
                    status.put("/jwks", Integer.parseInt(query.substring(5)));
                }
                Map<String, Object> body = Map.of("fetches", fetches, "authorizations", authorizations);
                byte[] bytes = JsonUtil.toJson(body).getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("content-type", "application/json");
                exchange.sendResponseHeaders(200, bytes.length);
                try (OutputStream out = exchange.getResponseBody()) {
                    out.write(bytes);
                }
            });
            control.start();
            servers.add(control);

            Map<String, String> config = new LinkedHashMap<>();
            config.put("granted.source", "jwt");
            config.put("granted.jwt.tls-configuration-name", "cluster");
            config.put("granted.jwt.audience", "my-service");
            config.put("granted.jwt.discovery-uris[0].uri", meerkatUrl);
            config.put("granted.jwt.discovery-uris[1].issuer", KUBERNETES);
            config.put("granted.jwt.discovery-uris[1].jwks-uri", kubernetesUrl + "/openid/v1/jwks");
            config.put("granted.jwt.discovery-uris[1].bearer-token-file", token.toString());
            config.put("granted.jwt.discovery-uris[1].bypass", "system:serviceaccount:my-namespace:*");
            config.put("granted.jwt.discovery-uris[1].readiness", "false");
            config.put("granted.role-hierarchy.ROLE_ADMIN", "ROLE_USER");
            config.put("quarkus.tls.cluster.trust-store.pem.certs", meerkatCaFile + "," + clusterCaFile);
            config.put("granted.jwt.jwks-cooldown", args.getOrDefault("cooldown", "30S"));
            config.put("it.keys", dir.toString());
            config.put("it.control", "http://127.0.0.1:" + control.getAddress().getPort());
            config.put("it.meerkat", meerkatUrl);
            return config;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private HttpsServer https(TestCa ca) throws Exception {
        HttpsServer server = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(ca.issue("localhost", "127.0.0.1").serverContext()));
        servers.add(server);
        return server;
    }

    private static void serve(HttpServer server, Map<String, Object> routes, Map<String, Integer> status, Map<String, Integer> fetches,
            Map<String, List<String>> authorizations) {
        server.createContext("/", exchange -> {
            String path = exchange.getRequestURI().getPath();
            String authorization = exchange.getRequestHeaders().getFirst("Authorization");
            fetches.merge(path, 1, Integer::sum);
            authorizations.computeIfAbsent(path, p -> java.util.Collections.synchronizedList(new ArrayList<>())).add(authorization == null ? "-" : authorization);
            Object body = routes.get(path);
            int code = body == null ? 404 : path.startsWith("/openid") && !"Bearer sa-token".equals(authorization) ? 403 : status.getOrDefault(path, 200);
            byte[] bytes = JsonUtil.toJson(code == 200 ? asMap(body) : Map.of()).getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("content-type", "application/json");
            exchange.sendResponseHeaders(code, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        server.start();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, ?> asMap(Object body) {
        return (Map<String, ?>) body;
    }

    private static Map<String, Object> jwk(KeyPair pair, String kid) throws Exception {
        Map<String, Object> jwk = new LinkedHashMap<>(PublicJsonWebKey.Factory.newPublicJwk(pair.getPublic()).toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY));
        jwk.put("kid", kid);
        jwk.put("use", "sig");
        jwk.put("alg", "RS256");
        return jwk;
    }

    @Override
    public void stop() {
        servers.forEach(server -> server.stop(0));
    }
}
