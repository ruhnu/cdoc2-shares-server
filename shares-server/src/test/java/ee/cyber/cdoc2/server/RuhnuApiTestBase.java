package ee.cyber.cdoc2.server;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyStore;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;

import ee.cyber.cdoc2.server.model.entity.KeyShareDb;
import ee.cyber.cdoc2.server.model.entity.KeyShareNonceDb;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;


/**
 * Helpers for testing the ruhnu fork features over HTTP. Requests are sent as plain HTTP, because the
 * generated client requires the session headers.
 */
abstract class RuhnuApiTestBase extends KeyShareIntegrationTest {

    static final String ETSI_RECIPIENT = "etsi/PNOEE-48010010101";
    static final String SHARE_BASE64 = Base64.getEncoder().encodeToString(new byte[64]);

    HttpClient http;
    ListAppender<ILoggingEvent> auditLog;

    @BeforeEach
    void setUpHttpAndAuditLog() throws Exception {
        http = createHttpClient();
        auditLog = SshPkTestData.startAuditLogCapture();
    }

    @AfterEach
    void stopAuditLog() {
        SshPkTestData.stopAuditLogCapture(auditLog);
    }

    void assertRefused(int expectedStatus, HttpResponse<String> resp) {
        assertEquals(expectedStatus, resp.statusCode(), resp.body());
        assertFalse(resp.body().contains("\"share\""), resp.body());
        assertTrue(auditLog.list.isEmpty(), "audit log written for refused request");
    }

    static void assertAbout(Instant expected, Instant actual) {
        assertTrue(Duration.between(expected, actual).abs().compareTo(Duration.ofMinutes(1)) < 0,
            "expected about " + expected + ", was " + actual);
    }

    String saveShare(String recipient, Instant expiry) {
        return shareRepository.save(new KeyShareDb()
            .setShare(new byte[64])
            .setRecipient(recipient)
            .setExpiryTime(expiry)).getShareId();
    }

    String nonceFor(String shareId) {
        byte[] nonce = shareNonceRepository.save(new KeyShareNonceDb().setShareId(shareId)).getNonce();
        return Base64.getUrlEncoder().withoutPadding().encodeToString(nonce);
    }

    static String shareIdFrom(HttpResponse<String> resp) {
        String location = resp.headers().firstValue("Location").orElseThrow();
        return location.substring(location.lastIndexOf('/') + 1);
    }

    HttpResponse<String> createShare(String recipient, Instant expiry) throws Exception {
        HttpRequest.Builder req = HttpRequest.newBuilder(URI.create(baseUrl + "/key-shares"))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(
                "{\"share\":\"" + SHARE_BASE64 + "\",\"recipient\":\"" + recipient + "\"}"));
        if (expiry != null) {
            req.header("x-expiry-time", expiry.toString());
        }
        return http.send(req.build(), HttpResponse.BodyHandlers.ofString());
    }

    HttpResponse<String> createNonce(String shareId, Map<String, String> headers) throws Exception {
        HttpRequest.Builder req = HttpRequest.newBuilder(URI.create(baseUrl + "/key-shares/" + shareId + "/nonce"))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString("{}"));
        headers.forEach(req::header);
        return http.send(req.build(), HttpResponse.BodyHandlers.ofString());
    }

    HttpResponse<String> getShare(String shareId, String authToken) throws Exception {
        return getShare(shareId, authToken, Map.of());
    }

    HttpResponse<String> getShare(String shareId, String authToken, Map<String, String> headers)
        throws Exception {
        HttpRequest.Builder req = HttpRequest.newBuilder(URI.create(baseUrl + "/key-shares/" + shareId))
            .header("x-cdoc2-auth-token", authToken)
            .GET();
        headers.forEach(req::header);
        return http.send(req.build(), HttpResponse.BodyHandlers.ofString());
    }

    static HttpClient createHttpClient() throws Exception {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init((KeyStore) CLIENT_TRUST_STORE);
        SSLContext ssl = SSLContext.getInstance("TLS");
        ssl.init(null, tmf.getTrustManagers(), null);
        return HttpClient.newBuilder().sslContext(ssl).build();
    }
}
