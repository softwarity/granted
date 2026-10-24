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

import io.quarkus.test.common.QuarkusTestResourceLifecycleManager;

/**
 * Two OpenID Providers on one local server: {@code https://idp-a}, found by its discovery document,
 * and a Kubernetes API server whose issuer and JWK Set are given, which answers 403 without its
 * bearer token. {@code /_authorizations} tells the tests which Authorization each path received.
 */
public class LocalIdp implements QuarkusTestResourceLifecycleManager {

    static final String KUBERNETES = "https://kubernetes.default.svc.cluster.local";

    private HttpServer server;

    @Override
    public Map<String, String> start() {
        try {
            Path dir = Files.createTempDirectory("granted-idp");
            KeyPair idpA = Keys.generate("RSA");
            KeyPair k8s = Keys.generate("RSA");
            Keys.save(dir, "idp-a", idpA);
            Keys.save(dir, "k8s", k8s);
            Path token = Files.writeString(dir.resolve("sa-token"), "sa-token\n");

            Map<String, List<String>> authorizations = new ConcurrentHashMap<>();
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            String base = "http://127.0.0.1:" + server.getAddress().getPort();
            Map<String, Object> routes = Map.of(
                    "/a/.well-known/openid-configuration", Map.of("issuer", "https://idp-a", "jwks_uri", base + "/a/jwks"),
                    "/a/jwks", Map.of("keys", List.of(jwk(idpA, "idp-a", "RS256"))),
                    "/k8s/jwks", Map.of("keys", List.of(jwk(k8s, "k8s", "RS256"))));
            server.createContext("/", exchange -> {
                String path = exchange.getRequestURI().getPath();
                String authorization = exchange.getRequestHeaders().getFirst("Authorization");
                authorizations.computeIfAbsent(path, p -> java.util.Collections.synchronizedList(new ArrayList<>()))
                        .add(authorization == null ? "-" : authorization);
                Object body = path.equals("/_authorizations") ? authorizations : routes.get(path);
                int status = body == null ? 404 : path.startsWith("/k8s") && !"Bearer sa-token".equals(authorization) ? 403 : 200;
                byte[] bytes = JsonUtil.toJson(body == null ? Map.of() : asMap(body)).getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("content-type", "application/json");
                exchange.sendResponseHeaders(status, bytes.length);
                try (OutputStream out = exchange.getResponseBody()) {
                    out.write(bytes);
                }
            });
            server.start();

            Map<String, String> config = new LinkedHashMap<>();
            config.put("granted.source", "jwt");
            config.put("granted.jwt.preset", "keycloak");
            config.put("granted.jwt.discovery-uris[0].uri", base + "/a");
            config.put("granted.jwt.discovery-uris[1].issuer", KUBERNETES);
            config.put("granted.jwt.discovery-uris[1].jwks-uri", base + "/k8s/jwks");
            config.put("granted.jwt.discovery-uris[1].bearer-token-file", token.toString());
            config.put("granted.jwt.discovery-uris[1].bypass", "system:serviceaccount:my-namespace:*");
            config.put("it.keys", dir.toString());
            config.put("it.idp", base);
            return config;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, ?> asMap(Object body) {
        return (Map<String, ?>) body;
    }

    private static Map<String, Object> jwk(KeyPair pair, String kid, String alg) throws Exception {
        Map<String, Object> jwk = new LinkedHashMap<>(PublicJsonWebKey.Factory.newPublicJwk(pair.getPublic()).toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY));
        jwk.put("kid", kid);
        jwk.put("use", "sig");
        jwk.put("alg", alg);
        return jwk;
    }

    @Override
    public void stop() {
        if (server != null) {
            server.stop(0);
        }
    }
}
