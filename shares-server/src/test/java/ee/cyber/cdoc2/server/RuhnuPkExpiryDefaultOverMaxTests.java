package ee.cyber.cdoc2.server;

import java.time.Duration;
import java.time.Instant;

import org.junit.jupiter.api.Test;
import org.springframework.test.context.TestPropertySource;

import ee.cyber.cdoc2.server.SshPkTestData.SshKey;

import static org.junit.jupiter.api.Assertions.assertEquals;


/**
 * Operator lowered only the "ruhnu/pk/" maximum lifetime, the default stays at its built-in 14 days
 */
@TestPropertySource(properties = {
    "cdoc2.ruhnu.enabled=true",
    "cdoc2.ruhnu.pk.max-expiration-duration=P7D"
})
class RuhnuPkExpiryDefaultOverMaxTests extends RuhnuApiTestBase {

    private final SshKey key = SshKey.generate();

    @Test
    void defaultShouldNotExceedMax() throws Exception {
        Instant before = Instant.now();
        var resp = createShare(key.recipientId(), null);

        assertEquals(201, resp.statusCode());
        assertEquals("false", resp.headers().firstValue("x-expiry-time-adjusted").orElseThrow());
        assertAbout(before.plus(Duration.ofDays(7)),
            shareRepository.findById(shareIdFrom(resp)).orElseThrow().getExpiryTime());
    }
}
