package ee.cyber.cdoc2.server.config;

import jakarta.validation.constraints.NotBlank;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;


/**
 * Configuration properties for key share. {@code Duration#parse} format is implemented for
 * extracting duration dates.
 *
 * @param defaultExpirationDuration default value for share expiration duration
 * @param maxExpirationDuration     max allowed value for share expiration duration
 */
@Validated
@ConfigurationProperties(prefix = "key-share")
public record KeyShareExpiryConfigProperties(
    @NotBlank @DefaultValue("P1095D") String defaultExpirationDuration,
    @NotBlank @DefaultValue("P1825D") String maxExpirationDuration
) {
}
