package ee.cyber.cdoc2.server;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.List;

import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.util.BigIntegerUtils;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.slf4j.LoggerFactory;

import ee.cyber.cdoc2.auth.AuthTokenCreator;
import ee.cyber.cdoc2.auth.EtsiIdentifier;
import ee.cyber.cdoc2.auth.ShareAccessData;
import ee.cyber.cdoc2.auth.SshPublicKeyParser;


/**
 * Test helpers for "ruhnu/pk/" SSH public key recipients
 */
public final class SshPkTestData {

    public static final String AUDIT_LOGGER = "ee.cyber.cdoc2.server.audit";

    private SshPkTestData() {
    }

    /** P-256 key pair and its "ruhnu/pk/" recipient identifier */
    public record SshKey(KeyPair keyPair, String recipientId) {
        public static SshKey generate() {
            return generate("secp256r1", 32, "ecdsa-sha2-nistp256", "nistp256");
        }

        /** P-384 key, for testing unsupported keys */
        public static SshKey generateP384() {
            return generate("secp384r1", 48, "ecdsa-sha2-nistp384", "nistp384");
        }

        private static SshKey generate(String curve, int coordLen, String keyType, String curveName) {
            try {
                KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
                generator.initialize(new ECGenParameterSpec(curve));
                KeyPair keyPair = generator.generateKeyPair();
                ECPublicKey pub = (ECPublicKey) keyPair.getPublic();

                byte[] q = new byte[1 + 2 * coordLen];
                q[0] = 0x04;
                byte[] x = BigIntegerUtils.toBytesUnsigned(pub.getW().getAffineX());
                byte[] y = BigIntegerUtils.toBytesUnsigned(pub.getW().getAffineY());
                System.arraycopy(x, 0, q, 1 + coordLen - x.length, x.length);
                System.arraycopy(y, 0, q, 1 + 2 * coordLen - y.length, y.length);

                ByteArrayOutputStream blob = new ByteArrayOutputStream();
                for (byte[] field : List.of(keyType.getBytes(StandardCharsets.US_ASCII),
                    curveName.getBytes(StandardCharsets.US_ASCII), q)) {
                    blob.writeBytes(ByteBuffer.allocate(4).putInt(field.length).array());
                    blob.writeBytes(field);
                }
                // not validated, so that unsupported keys can be created
                String recipientId = SshPublicKeyParser.RECIPIENT_ID_PREFIX
                    + java.util.Base64.getEncoder().encodeToString(blob.toByteArray());
                return new SshKey(keyPair, recipientId);
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }

    /**
     * Create auth token for one share, "iss" = issuer, signed with signingKey (ES256 for P-256, ES384 for P-384)
     */
    public static String createAuthToken(
        String issuer, KeyPair signingKey, String serverBaseUrl, String shareId, String nonce
    ) {
        try {
            AuthTokenCreator creator = AuthTokenCreator.builder()
                .withIssuer(issuer)
                .withShareAccessData(new ShareAccessData(serverBaseUrl, shareId, nonce))
                .build();
            creator.sign(new ECDSASigner((ECPrivateKey) signingKey.getPrivate()));
            return creator.createToken(0);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Create auth token with ETSI identifier "iss" signed with a key that has no certificate. Takes the
     * Smart-ID/Mobile-ID verification path and fails there.
     */
    public static String createEtsiAuthToken(
        String etsiRecipient, String serverBaseUrl, String shareId, String nonce
    ) {
        try {
            AuthTokenCreator creator = AuthTokenCreator.builder()
                .withEtsiIdentifier(new EtsiIdentifier(etsiRecipient))
                .withShareAccessData(new ShareAccessData(serverBaseUrl, shareId, nonce))
                .build();
            creator.sign(new ECDSASigner((ECPrivateKey) SshKey.generate().keyPair().getPrivate()));
            return creator.createToken(0);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** Capture events of the release audit logger, call {@link #stopAuditLogCapture} when done */
    public static ListAppender<ILoggingEvent> startAuditLogCapture() {
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        ((Logger) LoggerFactory.getLogger(AUDIT_LOGGER)).addAppender(appender);
        return appender;
    }

    public static void stopAuditLogCapture(ListAppender<ILoggingEvent> appender) {
        ((Logger) LoggerFactory.getLogger(AUDIT_LOGGER)).detachAppender(appender);
        appender.stop();
    }
}
