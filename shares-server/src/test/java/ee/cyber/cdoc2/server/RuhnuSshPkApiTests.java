package ee.cyber.cdoc2.server;

import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.test.context.TestPropertySource;

import ch.qos.logback.classic.spi.ILoggingEvent;

import ee.cyber.cdoc2.auth.SshPublicKeyParser;
import ee.cyber.cdoc2.server.SshPkTestData.SshKey;
import ee.cyber.cdoc2.server.model.entity.KeyShareDb;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;


/**
 * "ruhnu/pk/" SSH public key recipients with {@code cdoc2.ruhnu.enabled=true}
 */
@TestPropertySource(properties = "cdoc2.ruhnu.enabled=true")
class RuhnuSshPkApiTests extends RuhnuApiTestBase {

    private final SshKey key = SshKey.generate();
    private final SshKey otherKey = SshKey.generate();

    // --- create and expiry ---

    @Test
    void shouldCreateSshPkShareWithFullRecipientAndDefaultExpiry() throws Exception {
        Instant before = Instant.now();
        HttpResponse<String> resp = createShare(key.recipientId(), null);

        assertEquals(201, resp.statusCode());
        assertEquals("false", resp.headers().firstValue("x-expiry-time-adjusted").orElseThrow());
        KeyShareDb stored = shareRepository.findById(shareIdFrom(resp)).orElseThrow();
        assertEquals(key.recipientId(), stored.getRecipient());
        assertTrue(key.recipientId().length() > 140, "length " + key.recipientId().length());
        assertAbout(before.plus(Duration.ofDays(14)), stored.getExpiryTime());
        // header has the in-memory value (nanos), DB rounds to micros
        Instant header = Instant.parse(resp.headers().firstValue("x-expiry-time").orElseThrow());
        assertTrue(Duration.between(header, stored.getExpiryTime()).abs().toMillis() < 1,
            header + " != " + stored.getExpiryTime());
    }

    @Test
    void shouldAcceptShorterRequestedExpiry() throws Exception {
        Instant requested = Instant.now().plus(Duration.ofDays(3)).truncatedTo(ChronoUnit.SECONDS);
        HttpResponse<String> resp = createShare(key.recipientId(), requested);

        assertEquals(201, resp.statusCode());
        assertEquals("false", resp.headers().firstValue("x-expiry-time-adjusted").orElseThrow());
        assertEquals(requested, shareRepository.findById(shareIdFrom(resp)).orElseThrow().getExpiryTime());
    }

    @Test
    void shouldCutLongerRequestedExpiryToMax() throws Exception {
        Instant before = Instant.now();
        HttpResponse<String> resp = createShare(key.recipientId(), Instant.now().plus(Duration.ofDays(365)));

        assertEquals(201, resp.statusCode());
        assertEquals("true", resp.headers().firstValue("x-expiry-time-adjusted").orElseThrow());
        assertAbout(before.plus(Duration.ofDays(14)),
            shareRepository.findById(shareIdFrom(resp)).orElseThrow().getExpiryTime());
    }

    @Test
    void etsiShareShouldKeepGlobalExpiry() throws Exception {
        Instant before = Instant.now();
        HttpResponse<String> resp = createShare(ETSI_RECIPIENT, null);

        assertEquals(201, resp.statusCode());
        assertAbout(before.plus(Duration.ofDays(1095)),
            shareRepository.findById(shareIdFrom(resp)).orElseThrow().getExpiryTime());
    }

    @Test
    void shouldRejectInvalidSshPkRecipient() throws Exception {
        String unpadded = key.recipientId().substring(0, key.recipientId().length() - 1);
        List<String> invalid = List.of(
            // ssh-keygen -t ed25519
            "ruhnu/pk/AAAAC3NzaC1lZDI1NTE5AAAAILWcEUGN1uqqDHo5611gZw30t3rU05Q9Y6zqOt8CMfDy",
            SshKey.generateP384().recipientId(),
            "ruhnu/pk/not*base64!",
            "ruhnu/pk/AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAy",
            unpadded);

        for (String recipient : invalid) {
            assertEquals(400, createShare(recipient, null).statusCode(), recipient);
        }
        assertEquals(0, shareRepository.count());
    }

    @Test
    void shouldRefuseDidRecipientWhenNoHostsConfigured() throws Exception {
        // this class configures no cdoc2.ruhnu.did.allowed-hosts
        String didRecipient = DidTestData.didRecipientId("did:web:example.org:p:alice", key);

        assertEquals(400, createShare(didRecipient, null).statusCode());
        assertEquals(0, shareRepository.count());
    }

    @Test
    void shouldStillRejectTooLongRecipient() throws Exception {
        assertEquals(400, createShare("ruhnu/pk/" + "A".repeat(247), null).statusCode());
        assertEquals(0, shareRepository.count());
    }

    // --- nonce ---

    @Test
    void shouldCreateNonceForSshPkShareWithoutSessionHeaders() throws Exception {
        String shareId = saveShare(key.recipientId(), Instant.now().plus(Duration.ofDays(1)));

        HttpResponse<String> resp = createNonce(shareId, Map.of());

        assertEquals(200, resp.statusCode());
        assertTrue(resp.body().contains("\"nonce\""), resp.body());
        assertEquals(1, shareNonceRepository.count());
    }

    @Test
    void shouldRefuseNonceWithoutSessionHeadersForEtsiShare() throws Exception {
        String shareId = saveShare(ETSI_RECIPIENT, Instant.now().plus(Duration.ofDays(1)));

        assertEquals(400, createNonce(shareId, Map.of()).statusCode());
        assertEquals(0, shareNonceRepository.count());
    }

    @Test
    void shouldReturn404ForNonceWithoutSessionHeadersForUnknownShare() throws Exception {
        assertEquals(404, createNonce("ff0102030405060708090a0b0c0e0dff", Map.of()).statusCode());
    }

    @Test
    void shouldReturn404ForNonceForExpiredSshPkShare() throws Exception {
        String shareId = saveShare(key.recipientId(), Instant.now().minusSeconds(1));

        assertEquals(404, createNonce(shareId, Map.of()).statusCode());
    }

    @Test
    void shouldTakeExistingPathWhenOneSessionHeaderPresent() throws Exception {
        String shareId = saveShare(key.recipientId(), Instant.now().plus(Duration.ofDays(1)));

        assertEquals(400, createNonce(shareId, Map.of("x-cdoc2-session-token", "token")).statusCode());
        assertEquals(400, createNonce(shareId, Map.of("x-cdoc2-session-x5c", "cert")).statusCode());
        assertEquals(0, shareNonceRepository.count());
    }

    // --- get share ---

    @Test
    void shouldReleaseSshPkShareForValidToken() throws Exception {
        String shareId = saveShare(key.recipientId(), Instant.now().plus(Duration.ofDays(1)));
        String token = SshPkTestData.createAuthToken(
            key.recipientId(), key.keyPair(), baseUrl, shareId, nonceFor(shareId));

        HttpResponse<String> resp = getShare(shareId, token);

        assertEquals(200, resp.statusCode());
        assertTrue(resp.body().contains(key.recipientId()), resp.body());
        assertTrue(resp.headers().firstValue("x-expiry-time").isPresent());

        List<ILoggingEvent> events = auditLog.list;
        assertEquals(1, events.size());
        String line = events.get(0).getFormattedMessage();
        assertTrue(line.contains("shareId=" + shareId), line);
        assertTrue(line.contains(
            "recipient=ruhnu/pk:" + SshPublicKeyParser.fingerprintFromRecipientId(key.recipientId())), line);
        assertFalse(line.contains(key.recipientId()), line);
        assertTrue(line.contains("time="), line);
    }

    @Test
    void shouldReturn401ForTokenSignedByDifferentKey() throws Exception {
        String shareId = saveShare(key.recipientId(), Instant.now().plus(Duration.ofDays(1)));
        String token = SshPkTestData.createAuthToken(
            key.recipientId(), otherKey.keyPair(), baseUrl, shareId, nonceFor(shareId));

        assertRefused(401, getShare(shareId, token));
    }

    @Test
    void shouldReturn404ForTokenOfAnotherRecipient() throws Exception {
        String shareId = saveShare(key.recipientId(), Instant.now().plus(Duration.ofDays(1)));
        String token = SshPkTestData.createAuthToken(
            otherKey.recipientId(), otherKey.keyPair(), baseUrl, shareId, nonceFor(shareId));

        assertRefused(404, getShare(shareId, token));
    }

    @Test
    void shouldReturn401ForUnsupportedAlgorithmOrKey() throws Exception {
        String shareId = saveShare(key.recipientId(), Instant.now().plus(Duration.ofDays(1)));
        SshKey p384 = SshKey.generateP384();
        String es384Token = SshPkTestData.createAuthToken(
            p384.recipientId(), p384.keyPair(), baseUrl, shareId, nonceFor(shareId));

        assertRefused(401, getShare(shareId, es384Token));
    }

    @Test
    void shouldReturn404ForUnknownNonce() throws Exception {
        String shareId = saveShare(key.recipientId(), Instant.now().plus(Duration.ofDays(1)));
        String unknownNonce = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(HexFormat.of().parseHex("000102030405060708090a0b0c0e0dff"));
        String token = SshPkTestData.createAuthToken(
            key.recipientId(), key.keyPair(), baseUrl, shareId, unknownNonce);

        assertRefused(404, getShare(shareId, token));
    }

    @Test
    void shouldReturn404ForNonceIssuedForAnotherShare() throws Exception {
        String shareId = saveShare(key.recipientId(), Instant.now().plus(Duration.ofDays(1)));
        String otherShareId = saveShare(key.recipientId(), Instant.now().plus(Duration.ofDays(1)));
        String token = SshPkTestData.createAuthToken(
            key.recipientId(), key.keyPair(), baseUrl, shareId, nonceFor(otherShareId));

        assertRefused(404, getShare(shareId, token));
    }

    @Test
    void shouldReturn401ForTokenForAnotherServer() throws Exception {
        String shareId = saveShare(key.recipientId(), Instant.now().plus(Duration.ofDays(1)));
        String token = SshPkTestData.createAuthToken(
            key.recipientId(), key.keyPair(), "https://localhost:1", shareId, nonceFor(shareId));

        assertRefused(401, getShare(shareId, token));
    }

    @Test
    void shouldReturn401ForTokenForAnotherShare() throws Exception {
        String shareId = saveShare(key.recipientId(), Instant.now().plus(Duration.ofDays(1)));
        String otherShareId = saveShare(key.recipientId(), Instant.now().plus(Duration.ofDays(1)));
        String token = SshPkTestData.createAuthToken(
            key.recipientId(), key.keyPair(), baseUrl, otherShareId, nonceFor(otherShareId));

        assertRefused(401, getShare(shareId, token));
    }

    @Test
    void shouldReturn404ForExpiredSshPkShare() throws Exception {
        String shareId = saveShare(key.recipientId(), Instant.now().plusSeconds(2));
        String token = SshPkTestData.createAuthToken(
            key.recipientId(), key.keyPair(), baseUrl, shareId, nonceFor(shareId));
        KeyShareDb share = shareRepository.findById(shareId).orElseThrow();
        shareRepository.save(share.setExpiryTime(Instant.now().minusSeconds(1)));

        assertRefused(404, getShare(shareId, token));
    }

    @Test
    void shouldReturn404ForSshTokenForEtsiShare() throws Exception {
        String shareId = saveShare(ETSI_RECIPIENT, Instant.now().plus(Duration.ofDays(1)));
        String token = SshPkTestData.createAuthToken(
            key.recipientId(), key.keyPair(), baseUrl, shareId, nonceFor(shareId));

        assertRefused(404, getShare(shareId, token));
    }

    @Test
    void shouldReturn400ForEtsiTokenWithoutSessionHeaders() throws Exception {
        String shareId = saveShare(ETSI_RECIPIENT, Instant.now().plus(Duration.ofDays(1)));
        String token = SshPkTestData.createEtsiAuthToken(ETSI_RECIPIENT, baseUrl, shareId, nonceFor(shareId));

        assertRefused(400, getShare(shareId, token, Map.of("x-cdoc2-auth-x5c", "cert")));
    }

    @Test
    void shouldReturn400ForEtsiTokenWithoutAuthX5c() throws Exception {
        String shareId = saveShare(ETSI_RECIPIENT, Instant.now().plus(Duration.ofDays(1)));
        String token = SshPkTestData.createEtsiAuthToken(ETSI_RECIPIENT, baseUrl, shareId, nonceFor(shareId));

        assertRefused(400, getShare(shareId, token,
            Map.of("x-cdoc2-session-token", "token", "x-cdoc2-session-x5c", "cert")));
    }
}
