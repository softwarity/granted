package io.softwarity.granted.it.jwt;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.concurrent.atomic.AtomicLong;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/** A certificate authority made for a test, and the server certificates it signs. */
final class TestCa {

    private static final AtomicLong SERIAL = new AtomicLong(System.currentTimeMillis());

    final KeyPair keys;

    final X509Certificate certificate;

    private TestCa(KeyPair keys, X509Certificate certificate) {
        this.keys = keys;
        this.certificate = certificate;
    }

    /** A server's key and the certificate the CA signed for it. */
    record Issued(KeyPair keys, X509Certificate certificate, X509Certificate ca) {

        /** The context an HTTPS server presents this certificate with. */
        SSLContext serverContext() throws Exception {
            KeyStore store = KeyStore.getInstance("PKCS12");
            store.load(null, null);
            store.setKeyEntry("server", keys.getPrivate(), "secret".toCharArray(), new X509Certificate[] { certificate, ca });
            KeyManagerFactory factory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            factory.init(store, "secret".toCharArray());
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(factory.getKeyManagers(), null, null);
            return context;
        }
    }

    static TestCa create(String name) throws Exception {
        KeyPair keys = rsa();
        X500Name subject = new X500Name("CN=" + name);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(subject, BigInteger.valueOf(SERIAL.incrementAndGet()),
                new Date(System.currentTimeMillis() - 60_000), new Date(System.currentTimeMillis() + 86_400_000L), subject, keys.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        return new TestCa(keys, sign(builder, keys));
    }

    /** A server certificate for these names - an IP address or a DNS name each. */
    Issued issue(String... names) throws Exception {
        KeyPair server = rsa();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(certificate, BigInteger.valueOf(SERIAL.incrementAndGet()),
                new Date(System.currentTimeMillis() - 60_000), new Date(System.currentTimeMillis() + 86_400_000L), new X500Name("CN=" + names[0]),
                server.getPublic());
        GeneralName[] alternatives = new GeneralName[names.length];
        for (int i = 0; i < names.length; i++) {
            alternatives[i] = new GeneralName(names[i].matches("[0-9.]+") ? GeneralName.iPAddress : GeneralName.dNSName, names[i]);
        }
        builder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(alternatives));
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        return new Issued(server, sign(builder, keys), certificate);
    }

    /** What a client trusting this CA - and only it - connects with. */
    SSLContext clientContext() throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, null);
        store.setCertificateEntry("ca", certificate);
        TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init(store);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, factory.getTrustManagers(), null);
        return context;
    }

    String pem() throws Exception {
        return "-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(certificate.getEncoded())
                + "\n-----END CERTIFICATE-----\n";
    }

    private static KeyPair rsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static X509Certificate sign(JcaX509v3CertificateBuilder builder, KeyPair issuer) throws Exception {
        return new JcaX509CertificateConverter().getCertificate(builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(issuer.getPrivate())));
    }
}
