package ee.cyber.cdoc2.server.config;

import java.time.Duration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

    private static final Logger log = LoggerFactory.getLogger(RuhnuConfigProperties.class);

    public RuhnuConfigProperties {
        if (enabled && pk.defaultExpirationDuration().compareTo(pk.maxExpirationDuration()) > 0) {
            log.warn("cdoc2.ruhnu.pk.default-expiration-duration ({}) is longer than "
                + "cdoc2.ruhnu.pk.max-expiration-duration ({}), the maximum is used as the default",
                pk.defaultExpirationDuration(), pk.maxExpirationDuration());
        }
    }

    /**
     * Expiry for "ruhnu/pk/" recipient shares, {@link Duration#parse} format
     *
     * @param defaultExpirationDuration expiry used when client does not request one. If longer than
     *                                  the maximum, the maximum is used instead
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
