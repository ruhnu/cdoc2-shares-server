package ee.cyber.cdoc2.server;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.test.context.TestPropertySource;

import ee.cyber.cdoc2.server.SshPkTestData.SshKey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;


/**
 * With {@code cdoc2.ruhnu.enabled=false} (the default) the server must respond as upstream, including the
 * header and recipient length checks that the upstream API document makes mandatory. Pinned to false, so that
 * the class also runs when the flag is switched on for the whole suite.
 */
@TestPropertySource(properties = {
    "cdoc2.ruhnu.enabled=false",
    // ignored while the flag is off
    "cdoc2.ruhnu.did.allowed-hosts=localhost:8444"
})
class RuhnuDisabledApiTests extends RuhnuApiTestBase {

    private static final String DID = "did:web:localhost%3A8444:p:alice";

    private final SshKey key = SshKey.generate();
    private final String didRecipient = DidTestData.didRecipientId(DID, key);

    @Test
    void shouldRefuseSshPkRecipientAndStoreNothing() throws Exception {
        assertEquals(400, createShare(key.recipientId(), null).statusCode());
        assertEquals(0, shareRepository.count());
    }

    @Test
    void shouldRefuseRecipientLongerThan32() throws Exception {
        assertEquals(400, createShare("etsi/PNOEE-" + "1".repeat(22), null).statusCode());
        assertEquals(201, createShare("etsi/PNOEE-" + "1".repeat(21), null).statusCode());
    }

    @Test
    void shouldUseGlobalExpiry() throws Exception {
        Instant before = Instant.now();
        var resp = createShare(ETSI_RECIPIENT, null);

        assertEquals(201, resp.statusCode());
        assertAbout(before.plus(Duration.ofDays(1095)),
            shareRepository.findById(shareIdFrom(resp)).orElseThrow().getExpiryTime());

        var cut = createShare(ETSI_RECIPIENT, Instant.now().plus(Duration.ofDays(3650)));
        assertEquals("true", cut.headers().firstValue("x-expiry-time-adjusted").orElseThrow());
        assertAbout(before.plus(Duration.ofDays(1825)),
            shareRepository.findById(shareIdFrom(cut)).orElseThrow().getExpiryTime());
    }

    @Test
    void nonceShouldRequireBothSessionHeaders() throws Exception {
        // a ruhnu/pk/ share can only exist if created while the flag was on
        String shareId = saveShare(key.recipientId(), Instant.now().plus(Duration.ofDays(1)));

        assertEquals(400, createNonce(shareId, Map.of()).statusCode());
        assertEquals(400, createNonce(shareId, Map.of("x-cdoc2-session-token", "token")).statusCode());
        assertEquals(400, createNonce(shareId, Map.of("x-cdoc2-session-x5c", "cert")).statusCode());
        assertEquals(0, shareNonceRepository.count());
    }

    @Test
    void getShareShouldRequireEachUpstreamMandatoryHeader() throws Exception {
        String shareId = saveShare(ETSI_RECIPIENT, Instant.now().plus(Duration.ofDays(1)));
        String token = SshPkTestData.createEtsiAuthToken(ETSI_RECIPIENT, baseUrl, shareId, nonceFor(shareId));
        Map<String, String> all = Map.of(
            "x-cdoc2-auth-x5c", "cert",
            "x-cdoc2-session-token", "token",
            "x-cdoc2-session-x5c", "cert");

        for (String missing : all.keySet()) {
            Map<String, String> headers = new java.util.HashMap<>(all);
            headers.remove(missing);
            assertRefused(400, getShare(shareId, token, headers));
        }
        // control: with all headers present the request gets past the header checks into session token
        // validation (which fails here, the auth server is not mocked in this test)
        var control = getShare(shareId, token, all);
        assertNotEquals(400, control.statusCode());
        assertEquals(0, auditLog.list.size());
    }

    @Test
    void shouldRefuseDidRecipientEvenForAllowedHostAndStoreNothing() throws Exception {
        assertEquals(400, createShare(didRecipient, null).statusCode());
        assertEquals(0, shareRepository.count());
    }

    @Test
    void nonceShouldRequireSessionHeadersForDidShare() throws Exception {
        // a ruhnu/did/ share can only exist if created while the flag was on
        String shareId = saveShare(didRecipient, Instant.now().plus(Duration.ofDays(1)));

        assertEquals(400, createNonce(shareId, Map.of()).statusCode());
        assertEquals(0, shareNonceRepository.count());
    }

    @Test
    void didTokenShouldNotBeAcceptedWhileDisabled() throws Exception {
        String shareId = saveShare(didRecipient, Instant.now().plus(Duration.ofDays(1)));
        String token = DidTestData.createDidAuthToken(didRecipient, key.keyPair(),
            (java.security.interfaces.ECPublicKey) key.keyPair().getPublic(), baseUrl, shareId, nonceFor(shareId));

        assertRefused(400, getShare(shareId, token));
    }

    @Test
    void sshPkTokenShouldNotBeAcceptedWhileDisabled() throws Exception {
        String shareId = saveShare(key.recipientId(), Instant.now().plus(Duration.ofDays(1)));
        String token = SshPkTestData.createAuthToken(
            key.recipientId(), key.keyPair(), baseUrl, shareId, nonceFor(shareId));

        assertRefused(400, getShare(shareId, token));
    }
}
