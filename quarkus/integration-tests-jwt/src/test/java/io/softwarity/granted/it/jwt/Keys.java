package io.softwarity.granted.it.jwt;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Map;

import org.eclipse.microprofile.config.ConfigProvider;
import org.jose4j.json.JsonUtil;
import org.jose4j.jws.JsonWebSignature;

/** The keys the local IdP publishes and the tests sign with: made at each run, in a directory both read. */
final class Keys {

    private Keys() {
    }

    static KeyPair generate(String type) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(type);
        if (type.equals("EC")) {
            generator.initialize(new ECGenParameterSpec("secp256r1"));
        } else {
            generator.initialize(2048);
        }
        return generator.generateKeyPair();
    }

    static void save(Path dir, String name, KeyPair pair) throws Exception {
        Files.writeString(dir.resolve(name + ".key"), pair.getPrivate().getAlgorithm() + ":" + Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()));
        Files.writeString(dir.resolve(name + ".pem"), "-----BEGIN PUBLIC KEY-----\n" + Base64.getMimeEncoder().encodeToString(pair.getPublic().getEncoded())
                + "\n-----END PUBLIC KEY-----\n");
    }

    /** A private key the IdP made, from the directory the running application was told about. */
    static PrivateKey privateKey(String name) throws Exception {
        String dir = ConfigProvider.getConfig().getValue("it.keys", String.class);
        String[] stored = Files.readString(Path.of(dir, name + ".key")).split(":", 2);
        return KeyFactory.getInstance(stored[0]).generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(stored[1])));
    }

    static String sign(String name, String alg, String kid, Map<String, Object> claims) {
        try {
            JsonWebSignature jws = new JsonWebSignature();
            jws.setPayload(JsonUtil.toJson(claims));
            jws.setAlgorithmHeaderValue(alg);
            jws.setKeyIdHeaderValue(kid);
            jws.setKey(privateKey(name));
            // A test may sign with an algorithm the key doesn't fit: that is what it checks.
            jws.setDoKeyValidation(false);
            return jws.getCompactSerialization();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
