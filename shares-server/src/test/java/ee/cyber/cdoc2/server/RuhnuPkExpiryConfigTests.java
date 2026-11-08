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
    "cdoc2.ruhnu.pk.max-expiration-duration=P7D"
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
    void shouldCutToConfiguredMax() throws Exception {
        Instant before = Instant.now();
        var resp = createShare(key.recipientId(), Instant.now().plus(Duration.ofDays(10)));

        assertEquals(201, resp.statusCode());
        assertEquals("true", resp.headers().firstValue("x-expiry-time-adjusted").orElseThrow());
        assertAbout(before.plus(Duration.ofDays(7)),
            shareRepository.findById(shareIdFrom(resp)).orElseThrow().getExpiryTime());
    }
}
