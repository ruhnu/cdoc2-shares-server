package ee.cyber.cdoc2.server.config;

import java.time.Duration;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;


/**
 * Configuration of the ruhnu fork features. While {@code enabled} is false (default), the server behaves
 * like upstream cdoc2-shares-server: no "ruhnu/pk/" SSH public key or "ruhnu/did/" DID recipients, no per
 * recipient type expiry and no share release audit log.
 *
 * @param enabled feature flag {@code cdoc2.ruhnu.enabled}
 * @param pk      expiry configuration for "ruhnu/pk/" recipients, used only while enabled
 * @param did     DID host allowlist and DID resolution timeouts for "ruhnu/did/" recipients, used only while
 *                enabled
 */
@ConfigurationProperties(prefix = "cdoc2.ruhnu")
public record RuhnuConfigProperties(
    @DefaultValue("false") boolean enabled,
    @DefaultValue Pk pk,
    @DefaultValue Did did
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
     * "ruhnu/did/" recipients. The server stores DID recipient shares, and fetches DID documents, only for
     * the allowed hosts.
     *
     * @param allowedHosts   DID hosts, each "host" or "host:port" (port 443 when omitted); empty by default, so
     *                       no DID recipient share can be created until an operator names hosts
     * @param connectTimeout connect timeout for fetching a DID document
     * @param requestTimeout overall deadline for fetching a DID document (connect, headers and body)
     */
    public record Did(
        @DefaultValue List<String> allowedHosts,
        @DefaultValue("PT2S") Duration connectTimeout,
        @DefaultValue("PT3S") Duration requestTimeout
    ) {
        public Did {
            allowedHosts = (allowedHosts == null) ? List.of() : List.copyOf(allowedHosts);
        }

        /**
         * @return defaults: no allowed hosts, 2 s connect timeout, 3 s deadline
         */
        public static Did defaults() {
            return new Did(List.of(), Duration.ofSeconds(2), Duration.ofSeconds(3));
        }
    }

    /**
     * @return configuration with the fork features disabled (upstream behaviour)
     */
    public static RuhnuConfigProperties disabled() {
        return new RuhnuConfigProperties(false, new Pk(Duration.ofDays(14), Duration.ofDays(14)), Did.defaults());
    }
}
