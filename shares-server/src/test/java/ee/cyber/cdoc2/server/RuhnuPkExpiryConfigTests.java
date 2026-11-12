package ee.cyber.cdoc2.server;

import java.time.Duration;
import java.time.Instant;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;

import ee.cyber.cdoc2.server.SshPkTestData.SshKey;
import ee.cyber.cdoc2.server.config.RuhnuConfigProperties;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;


/**
 * Operator configured "ruhnu/pk/" share lifetimes
 */
@TestPropertySource(properties = {
    "cdoc2.ruhnu.enabled=true",
    "cdoc2.ruhnu.pk.default-expiration-duration=P1D",
    "cdoc2.ruhnu.pk.max-expiration-duration=P7D",
    "cdoc2.ruhnu.did.allowed-hosts=did.example.org"
})
class RuhnuPkExpiryConfigTests extends RuhnuApiTestBase {

    @Autowired
    private RuhnuConfigProperties ruhnuConfig;

    private final SshKey key = SshKey.generate();

    @Test
    void propertiesShouldBind() {
        assertTrue(ruhnuConfig.enabled());
        assertEquals(Duration.ofDays(1), ruhnuConfig.pk().defaultExpirationDuration());
        assertEquals(Duration.ofDays(7), ruhnuConfig.pk().maxExpirationDuration());
    }

    @Test
    void shouldUseConfiguredDefault() throws Exception {
        Instant before = Instant.now();
        var resp = createShare(key.recipientId(), null);

        assertEquals(201, resp.statusCode());
        assertAbout(before.plus(Duration.ofDays(1)),
            shareRepository.findById(shareIdFrom(resp)).orElseThrow().getExpiryTime());
    }

    @Test
    void didShareShouldUseGlobalLifetimesNotPkLifetimes() throws Exception {
        String didRecipient = DidTestData.didRecipientId("did:web:did.example.org:p:alice", key);
        Instant before = Instant.now();

        var resp = createShare(didRecipient, null);
        assertEquals(201, resp.statusCode());
        assertEquals("false", resp.headers().firstValue("x-expiry-time-adjusted").orElseThrow());
        assertAbout(before.plus(Duration.ofDays(1095)),
            shareRepository.findById(shareIdFrom(resp)).orElseThrow().getExpiryTime());

        // 10 days is over the pk max (7 days) but under the global max, so it is not cut
        Instant tenDays = Instant.now().plus(Duration.ofDays(10)).truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
        var notCut = createShare(didRecipient, tenDays);
        assertEquals("false", notCut.headers().firstValue("x-expiry-time-adjusted").orElseThrow());
        assertEquals(tenDays, shareRepository.findById(shareIdFrom(notCut)).orElseThrow().getExpiryTime());

        var cut = createShare(didRecipient, Instant.now().plus(Duration.ofDays(3650)));
        assertEquals("true", cut.headers().firstValue("x-expiry-time-adjusted").orElseThrow());
        assertAbout(before.plus(Duration.ofDays(1825)),
            shareRepository.findById(shareIdFrom(cut)).orElseThrow().getExpiryTime());
    }

    @Test
    void shouldCutToConfiguredMax() throws Exception {
        Instant before = Instant.now();
        var resp = createShare(key.recipientId(), Instant.now().plus(Duration.ofDays(10)));

        assertEquals(201, resp.statusCode());
        assertEquals("true", resp.headers().firstValue("x-expiry-time-adjusted").orElseThrow());
        assertAbout(before.plus(Duration.ofDays(7)),
            shareRepository.findById(shareIdFrom(resp)).orElseThrow().getExpiryTime());
    }
}
