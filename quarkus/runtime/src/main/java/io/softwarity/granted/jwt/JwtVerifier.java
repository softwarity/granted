package io.softwarity.granted.jwt;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.ConnectException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpTimeoutException;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.function.LongSupplier;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;

import org.jboss.logging.Logger;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.OctetKeyPairJsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.keys.HmacKey;
import org.jose4j.lang.JoseException;

import io.softwarity.granted.jwt.JwtSettings.Audience;

/**
 * Verifies a JWT the way nestjs-granted's {@code GrantedJwtPrincipalProvider} does: with a PEM key,
 * a JWK Set, or the JWK Sets of the OpenID Providers the token's {@code iss} routes it to. The key
 * is picked by the token's {@code kid} and verifies with its own algorithm - the token's
 * {@code alg} only has to agree with it. Taking it from the token is what {@code alg: none} and
 * RSA/HMAC confusion attacks rely on. The signature itself is jose4j's.
 */
public final class JwtVerifier {

    private static final Logger LOG = Logger.getLogger(JwtVerifier.class);

    /** A verified token: its claims, and whether its {@code sub} matched its provider's {@code bypass}. */
    public record Verified(Map<String, Object> claims, boolean bypass) {
    }

    /**
     * A provider as the readiness check sees it: its keys, or why it has none - a status, a TLS
     * handshake, a timeout. Never a token.
     */
    public record ProviderStatus(String label, int keys, String failure) {

        public boolean up() {
            return keys > 0;
        }
    }

    private final JwtSettings settings;

    private final LongSupplier clock;

    /** The client of each TLS configuration, by name; the JVM's authorities under {@code null}. */
    private final Map<String, HttpClient> clients = new java.util.HashMap<>();

    /** The key of a PEM configuration: a public key, or the HS* secret. */
    private final Key key;

    /** The JWK Sets to verify with: {@code jwks-uri}'s, then one per provider. Empty with a PEM key. */
    private final List<KeySource> sources;

    /**
     * @param tls the {@code SSLContext} of each TLS configuration the settings name, from Quarkus's
     *        TLS registry
     */
    public JwtVerifier(JwtSettings settings, Map<String, SSLContext> tls) {
        this(settings, tls, System::currentTimeMillis);
    }

    JwtVerifier(JwtSettings settings, Map<String, SSLContext> tls, LongSupplier clock) {
        this.settings = settings;
        this.clock = clock;
        Duration timeout = Duration.ofMillis(settings.policy().timeout());
        clients.put(null, HttpClient.newBuilder().connectTimeout(timeout).build());
        // The host name stays verified: the client checks it against the certificate, whatever context it has.
        tls.forEach((name, context) -> clients.put(name, HttpClient.newBuilder().connectTimeout(timeout).sslContext(context).build()));
        this.key = settings.key() == null ? null : key(settings.key(), settings.algorithms());
        List<KeySource> sources = new ArrayList<>();
        if (settings.jwksUri() != null) {
            sources.add(new KeySource(settings.jwksUri(), settings.issuer(), settings.audience(), List.of(), null, settings.tls(),
                    settings.jwksUri(), true, this, clock));
        }
        for (JwtSettings.ProviderSettings provider : settings.providers()) {
            sources.add(provider.jwksUri() != null
                    ? new KeySource(provider.jwksUri(), List.of(provider.issuer()), provider.audience(), provider.bypass(), provider.bearerTokenFile(),
                            provider.tls(), provider.label(), provider.readiness(), this, clock)
                    : new DiscoverySource(provider, this, clock));
        }
        this.sources = List.copyOf(sources);
    }

    /**
     * The providers the readiness check waits for, walked as a verification would: the discovery
     * document, then the JWK Set - through the same cache and cooldown. A source without keys asks
     * for them as an unknown {@code kid} would: never twice within the cooldown. Blocking.
     */
    public List<ProviderStatus> readiness() {
        return sources.stream().filter(source -> source.readiness).parallel().map(source -> {
            source.discover();
            if (source instanceof DiscoverySource && source.issuer == null) {
                return new ProviderStatus(source.label, 0, source.discoveryFailure());
            }
            List<JwksKey> keys = source.keys.get(false);
            if (keys.isEmpty()) {
                keys = source.keys.get(true);
            }
            String failure = source.keys.lastFailure();
            return new ProviderStatus(source.label, keys.size(),
                    keys.isEmpty() ? (failure == null ? "no key in the JWK Set" : "JWK Set: " + failure) : null);
        }).toList();
    }

    JwtSettings settings() {
        return settings;
    }

    /** The verified token, or {@code null} - a missing, malformed or invalid token gives an anonymous caller. */
    public Verified verify(String token) {
        try {
            JsonWebSignature unverified = parse(token);
            if (sources.isEmpty()) {
                return new Verified(verifySignature(token, unverified.getAlgorithmHeaderValue(), settings.algorithms(), key,
                        settings.issuer(), settings.audience()), false);
            }
            return verifyWithJwks(token, unverified);
        } catch (VerificationException e) {
            // Never the token, never the key material: the reason only.
            LOG.warnf("[quarkus-granted] JWT verification failed (%s): %s",
                    settings.algorithms() == null ? "JWKS" : String.join(", ", settings.algorithms()), e.getMessage());
            return null;
        }
    }

    /**
     * Routes the token to the JWK Set of its issuer and verifies it with the cached keys; on
     * failure, re-fetches the set once and retries - the IdP may have rotated its keys.
     */
    private Verified verifyWithJwks(String token, JsonWebSignature unverified) throws VerificationException {
        Object iss;
        try {
            iss = claims(unverified.getUnverifiedPayload()).get("iss");
        } catch (JoseException e) {
            throw new VerificationException("jwt malformed");
        }
        // Only the documents that may announce the token's issuer are fetched: a hung IdP doesn't slow the others down.
        List<KeySource> candidates = sourcesFor(iss);
        (candidates.isEmpty() ? sources : candidates).parallelStream().forEach(KeySource::discover);
        VerificationException failure = unknownIssuer();
        for (KeySource source : sourcesFor(iss)) {
            List<JwksKey> cached = source.keys.get(false);
            try {
                return verifiedBy(source, verifyWithKeys(token, unverified, cached, source));
            } catch (VerificationException e) {
                failure = e;
                List<JwksKey> refreshed = e.signatureMatched ? cached : source.keys.get(true);
                if (refreshed != cached) {
                    try {
                        return verifiedBy(source, verifyWithKeys(token, unverified, refreshed, source));
                    } catch (VerificationException retry) {
                        failure = retry;
                    }
                }
            }
        }
        throw failure;
    }

    /** The sources whose issuer is the token's {@code iss}: a key never verifies a token claiming another issuer. */
    private List<KeySource> sourcesFor(Object iss) {
        return sources.stream().filter(source -> source.accepts(iss)).toList();
    }

    private VerificationException unknownIssuer() {
        List<String> known = sources.stream().flatMap(source -> source.issuer == null ? java.util.stream.Stream.empty() : source.issuer.stream()).toList();
        return new VerificationException(known.isEmpty() ? "jwt issuer invalid: no OpenID configuration fetched yet"
                : "jwt issuer invalid. expected: " + String.join(" or ", known));
    }

    private static Verified verifiedBy(KeySource source, Map<String, Object> claims) {
        boolean bypass = claims.get("sub") instanceof String sub && source.bypass.stream().anyMatch(pattern -> pattern.matcher(sub).matches());
        return new Verified(claims, bypass);
    }

    /** Verifies with the key matching {@code kid} or, when the token has none, with each key in turn. */
    private Map<String, Object> verifyWithKeys(String token, JsonWebSignature unverified, List<JwksKey> keys, KeySource source)
            throws VerificationException {
        String kid = unverified.getKeyIdHeaderValue();
        String alg = unverified.getAlgorithmHeaderValue();
        VerificationException failure = new VerificationException("no JWKS key matches the token");
        for (JwksKey candidate : keys) {
            if (kid != null && !kid.equals(candidate.kid())) {
                continue;
            }
            try {
                return verifySignature(token, alg, candidate.algorithms(), candidate.key(), source.issuer, source.audience);
            } catch (VerificationException e) {
                if (e.signatureMatched) {
                    throw e;
                }
                failure = e;
            }
        }
        throw failure;
    }

    /**
     * The signature, with {@code key} and the token's {@code alg} - provided {@code alg} is one the
     * key verifies with - then the dates, the issuer and the audience.
     */
    private Map<String, Object> verifySignature(String token, String alg, List<String> algorithms, Key key, List<String> issuer,
            List<Audience> audience) throws VerificationException {
        if (alg == null || !algorithms.contains(alg)) {
            throw new VerificationException("invalid algorithm");
        }
        JsonWebSignature jws = parse(token);
        jws.setAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, alg));
        jws.setKey(key);
        // nestjs-granted takes an HS* secret of any length; the asymmetric keys are still checked.
        jws.setDoKeyValidation(!(key instanceof HmacKey));
        try {
            if (!jws.verifySignature()) {
                throw new VerificationException("invalid signature");
            }
        } catch (JoseException e) {
            throw new VerificationException("invalid signature");
        }
        Map<String, Object> claims;
        try {
            claims = claims(jws.getPayload());
        } catch (JoseException e) {
            throw new VerificationException("jwt malformed");
        }
        checkClaims(claims, issuer, audience);
        return claims;
    }

    /** {@code jsonwebtoken}'s checks, in its order and with its messages: no clock tolerance. */
    private void checkClaims(Map<String, Object> claims, List<String> issuer, List<Audience> audience) throws VerificationException {
        long now = clock.getAsLong() / 1000;
        Object nbf = claims.get("nbf");
        if (nbf != null) {
            if (!(nbf instanceof Number number)) {
                throw new VerificationException("invalid nbf value");
            }
            if (number.doubleValue() > now) {
                throw new VerificationException("jwt not active", true);
            }
        }
        Object exp = claims.get("exp");
        if (exp != null) {
            if (!(exp instanceof Number number)) {
                throw new VerificationException("invalid exp value");
            }
            if (now >= number.doubleValue()) {
                throw new VerificationException("jwt expired", true);
            }
        }
        if (audience != null) {
            Object aud = claims.get("aud");
            Collection<?> auds = aud instanceof Collection<?> list ? list : java.util.Collections.singletonList(aud);
            if (auds.stream().noneMatch(value -> audience.stream().anyMatch(accepted -> accepted.accepts(value)))) {
                throw new VerificationException("jwt audience invalid. expected: "
                        + String.join(" or ", audience.stream().map(Audience::value).toList()), true);
            }
        }
        if (!JwtSettings.issuerAccepted(issuer, claims.get("iss"))) {
            throw new VerificationException("jwt issuer invalid. expected: " + String.join(",", issuer), true);
        }
    }

    private static JsonWebSignature parse(String token) throws VerificationException {
        try {
            if (JsonWebStructure.fromCompactSerialization(token) instanceof JsonWebSignature jws) {
                // Read-only use of the header and the payload before any key is chosen.
                claims(jws.getUnverifiedPayload());
                return jws;
            }
        } catch (JoseException | RuntimeException e) {
            // Falls through.
        }
        throw new VerificationException("jwt malformed");
    }

    private static Map<String, Object> claims(String payload) throws JoseException {
        return JsonUtil.parseJson(payload);
    }

    /**
     * A JSON document over HTTP, with the TLS configuration given. A failure says what kind it is -
     * the status, a TLS handshake, a timeout, a refused connection - for the log and the readiness
     * check: never the token.
     */
    Object fetchJson(String url, String bearerTokenFile, JwtSettings.Tls tls) throws IOException, InterruptedException, JoseException {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofMillis(settings.policy().timeout())).GET();
        if (bearerTokenFile != null) {
            // Read at every fetch: a projected token is rotated on disk by the kubelet.
            request.header("Authorization", "Bearer " + Files.readString(Path.of(bearerTokenFile)).trim());
        }
        HttpResponse<String> response;
        try {
            response = clients.get(tls == null ? null : tls.name()).send(request.build(), HttpResponse.BodyHandlers.ofString());
        } catch (HttpTimeoutException e) {
            throw new IOException("timeout after " + settings.policy().timeout() + " ms");
        } catch (SSLException e) {
            throw new IOException("TLS handshake failed: " + e.getMessage());
        } catch (ConnectException e) {
            throw new IOException("connection refused");
        } catch (IOException e) {
            // The JDK client wraps a handshake failure in a plain IOException at times.
            if (e.getCause() instanceof SSLException ssl) {
                throw new IOException("TLS handshake failed: " + ssl.getMessage());
            }
            throw e;
        }
        if (response.statusCode() < 200 || response.statusCode() > 299) {
            throw new IOException("HTTP " + response.statusCode());
        }
        return JsonUtil.parseJson(response.body());
    }

    /**
     * The keys of a JWK Set. Encryption keys, and entries that aren't public keys (e.g. symmetric
     * {@code oct} ones, which would open the door to HS256 forgeries), are skipped.
     */
    @SuppressWarnings("unchecked")
    List<JwksKey> parseJwks(Object jwks) {
        if (!(jwks instanceof Map<?, ?> map) || !(map.get("keys") instanceof List<?> entries)) {
            throw new IllegalStateException("no \"keys\" array in the response");
        }
        List<JwksKey> keys = new ArrayList<>();
        for (Object entry : entries) {
            if (!(entry instanceof Map<?, ?> jwkMap) || "enc".equals(jwkMap.get("use"))) {
                continue;
            }
            try {
                if (JsonWebKey.Factory.newJwk((Map<String, Object>) jwkMap) instanceof PublicJsonWebKey jwk) {
                    keys.add(new JwksKey(jwk.getKeyId(), jwk.getPublicKey(), keyAlgorithms(jwk, jwkMap.get("alg"))));
                }
            } catch (JoseException | RuntimeException e) {
                // A key that can't be read verifies nothing.
            }
        }
        return List.copyOf(keys);
    }

    /**
     * The {@code alg} the JWK declares, provided its key type can verify it. Without {@code alg}:
     * the one the key type implies (RSA → RS256, EC → its curve's ES*, Ed25519 → EdDSA) or, when
     * {@code algorithm} is configured, whichever of those the key type can verify - an RSA key may
     * sign PS256 as well. Empty when nothing fits or the allowlist excludes it.
     */
    private List<String> keyAlgorithms(PublicJsonWebKey jwk, Object declared) {
        List<String> possible = possibleAlgorithms(jwk);
        List<String> allowlist = settings.algorithms();
        if (allowlist == null) {
            return declared == null ? possible.stream().limit(1).toList() : possible.stream().filter(declared::equals).toList();
        }
        return possible.stream().filter(alg -> allowlist.contains(alg) && (declared == null || alg.equals(declared))).toList();
    }

    private static List<String> possibleAlgorithms(PublicJsonWebKey jwk) {
        if (jwk instanceof RsaJsonWebKey) {
            return List.of("RS256", "RS384", "RS512", "PS256", "PS384", "PS512");
        }
        if (jwk instanceof EllipticCurveJsonWebKey ec) {
            return switch (ec.getCurveName()) {
                case "P-256" -> List.of("ES256");
                case "P-384" -> List.of("ES384");
                case "P-521" -> List.of("ES512");
                default -> List.of();
            };
        }
        if (jwk instanceof OctetKeyPairJsonWebKey okp) {
            return "Ed25519".equals(okp.getSubtype()) || "Ed448".equals(okp.getSubtype()) ? List.of("EdDSA") : List.of();
        }
        return List.of();
    }

    /** A PEM public key or certificate; with HS* algorithms, a string that isn't PEM is the shared secret. */
    private static Key key(String material, List<String> algorithms) {
        String pem = material.trim();
        if (!pem.startsWith("-----BEGIN")) {
            if (algorithms.stream().allMatch(JwtSettings.HMAC_ALGORITHMS::contains)) {
                return new HmacKey(material.getBytes(StandardCharsets.UTF_8));
            }
            throw new IllegalStateException("[quarkus-granted] granted.jwt.public-key is not a PEM public key");
        }
        byte[] der = Base64.getMimeDecoder().decode(pem.replaceAll("-----[A-Z0-9 ]+-----", ""));
        try {
            if (pem.startsWith("-----BEGIN CERTIFICATE")) {
                return CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der)).getPublicKey();
            }
        } catch (Exception e) {
            throw new IllegalStateException("[quarkus-granted] granted.jwt.public-key: the certificate can't be read", e);
        }
        for (String type : List.of("EC", "RSA", "Ed25519", "Ed448")) {
            try {
                PublicKey key = KeyFactory.getInstance(type).generatePublic(new X509EncodedKeySpec(der));
                return key;
            } catch (Exception e) {
                // Not this type.
            }
        }
        throw new IllegalStateException("[quarkus-granted] granted.jwt.public-key is not a PEM public key");
    }
}
