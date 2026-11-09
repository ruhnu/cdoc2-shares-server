package ee.cyber.cdoc2.server.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;


/**
 * Key Shares nonce configuration properties
 */
@ConfigurationProperties(prefix = "cdoc2.nonce")
public record NonceConfigProperties(
    @DefaultValue("300") long expirationSeconds
) {
}
