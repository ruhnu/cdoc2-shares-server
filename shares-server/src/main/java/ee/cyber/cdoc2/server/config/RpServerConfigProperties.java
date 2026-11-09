package ee.cyber.cdoc2.server.config;


import jakarta.validation.constraints.NotBlank;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "cdoc2.rp-server")
public record RpServerConfigProperties(
    @NotBlank String rpName,
    @NotBlank String schemeName
) {
}
