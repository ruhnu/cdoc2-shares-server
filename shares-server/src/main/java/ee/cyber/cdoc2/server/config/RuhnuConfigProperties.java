package ee.cyber.cdoc2.server.config;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;


/**
 * Configuration of the ruhnu fork features. While {@code enabled} is false (default), the server behaves
 * like upstream cdoc2-shares-server: no "ruhnu/pk/" SSH public key recipients, no per recipient type
 * expiry and no share release audit log.
 *
 * @param enabled feature flag {@code cdoc2.ruhnu.enabled}
 * @param pk      expiry configuration for "ruhnu/pk/" recipients, used only while enabled
 */
@ConfigurationProperties(prefix = "cdoc2.ruhnu")
public record RuhnuConfigProperties(
    @DefaultValue("false") boolean enabled,
    @DefaultValue Pk pk
) {

    /**
     * Expiry for "ruhnu/pk/" recipient shares, {@link Duration#parse} format
     *
     * @param defaultExpirationDuration expiry used when client does not request one
     * @param maxExpirationDuration     longer requested expiry is cut to this
     */
    public record Pk(
        @DefaultValue("P14D") Duration defaultExpirationDuration,
        @DefaultValue("P14D") Duration maxExpirationDuration
    ) {
    }

    /**
     * @return configuration with the fork features disabled (upstream behaviour)
     */
    public static RuhnuConfigProperties disabled() {
        return new RuhnuConfigProperties(false, new Pk(Duration.ofDays(14), Duration.ofDays(14)));
    }
}
