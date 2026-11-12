package ee.cyber.cdoc2.server;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;

import ee.cyber.cdoc2.server.config.RuhnuConfigProperties;
import ee.cyber.cdoc2.server.did.DidHostAllowlist;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;


/**
 * Binding of {@code cdoc2.ruhnu.did.*} and parsing of {@code cdoc2.ruhnu.did.allowed-hosts}
 */
class RuhnuDidConfigTests {

    @Test
    void shouldBindDefaults() {
        RuhnuConfigProperties config = bind(Map.of("cdoc2.ruhnu.enabled", "true"));

        assertTrue(config.did().allowedHosts().isEmpty());
        assertEquals(Duration.ofSeconds(2), config.did().connectTimeout());
        assertEquals(Duration.ofSeconds(3), config.did().requestTimeout());
        assertEquals(RuhnuConfigProperties.Did.defaults(), config.did());
        assertTrue(new DidHostAllowlist(config.did().allowedHosts()).isEmpty());
    }

    @Test
    void shouldBindConfiguredValues() {
        RuhnuConfigProperties config = bind(Map.of(
            "cdoc2.ruhnu.enabled", "true",
            "cdoc2.ruhnu.did.allowed-hosts", "Example.org, did.example.com:8443",
            "cdoc2.ruhnu.did.connect-timeout", "PT1S",
            "cdoc2.ruhnu.did.request-timeout", "PT4S"));

        assertEquals(List.of("Example.org", "did.example.com:8443"), config.did().allowedHosts());
        assertEquals(Duration.ofSeconds(1), config.did().connectTimeout());
        assertEquals(Duration.ofSeconds(4), config.did().requestTimeout());
    }

    @Test
    void allowlistShouldCompareHostsCaseInsensitivelyAndPortsExactly() {
        DidHostAllowlist allowlist = new DidHostAllowlist(List.of("Example.org", " did.example.com:8443 "));

        assertTrue(allowlist.allows("example.org", 443));
        assertTrue(allowlist.allows("EXAMPLE.ORG", 443));
        assertFalse(allowlist.allows("example.org", 8443));
        assertTrue(allowlist.allows("did.example.com", 8443));
        assertFalse(allowlist.allows("did.example.com", 443));
        assertFalse(allowlist.allows("sub.example.org", 443));
        assertFalse(allowlist.allows(null, 443));
    }

    @Test
    void allowlistShouldRejectMalformedEntries() {
        for (String entry : List.of("", "https://example.org", "example.org/p", "example.org:0",
            "example.org:70000", "example.org:abc", "exa mple.org", "[::1]:443")) {
            assertThrows(IllegalArgumentException.class, () -> new DidHostAllowlist(List.of(entry)), entry);
        }
    }

    @Test
    void allowlistWildcardShouldMatchExactlyOneLabel() {
        DidHostAllowlist allowlist = new DidHostAllowlist(List.of("*.github.io", "*.Example.org:8443"));

        assertTrue(allowlist.allows("alice.github.io", 443));
        assertTrue(allowlist.allows("Alice.GitHub.io", 443));
        assertFalse(allowlist.allows("github.io", 443));
        assertFalse(allowlist.allows("a.b.github.io", 443));
        assertFalse(allowlist.allows("alicegithub.io", 443));
        assertFalse(allowlist.allows(".github.io", 443));
        assertFalse(allowlist.allows("alice.github.io", 8443));

        assertTrue(allowlist.allows("did.example.org", 8443));
        assertFalse(allowlist.allows("did.example.org", 443));
        assertFalse(allowlist.isEmpty());
    }

    @Test
    void allowlistShouldRejectMalformedWildcards() {
        for (String entry : List.of("*", "*.", "*.org", "*.org:443", "a.*.org", "*.*.example.org",
            "**.example.org", "*example.org", "*..example.org", "*.example..org", "*.example.org.")) {
            assertThrows(IllegalArgumentException.class, () -> new DidHostAllowlist(List.of(entry)), entry);
        }
    }

    private static RuhnuConfigProperties bind(Map<String, String> properties) {
        return new Binder(new MapConfigurationPropertySource(properties))
            .bind("cdoc2.ruhnu", RuhnuConfigProperties.class)
            .get();
    }
}
