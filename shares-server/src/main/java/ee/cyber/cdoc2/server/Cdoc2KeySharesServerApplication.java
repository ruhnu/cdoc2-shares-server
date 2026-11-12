package ee.cyber.cdoc2.server;

import java.util.Map;

import io.micrometer.core.instrument.MeterRegistry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.micrometer.metrics.autoconfigure.MeterRegistryCustomizer;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.info.BuildProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.scheduling.annotation.EnableScheduling;

import ee.cyber.cdoc2.server.config.AuthCertificateConfigProperties;
import ee.cyber.cdoc2.server.config.DbConnectionConfigProperties;
import ee.cyber.cdoc2.server.config.MonitoringConfigProperties;
import ee.cyber.cdoc2.server.config.NonceConfigProperties;
import ee.cyber.cdoc2.server.config.RpServerConfigProperties;


@SpringBootApplication
@ConfigurationPropertiesScan
@Configuration
@EnableJpaAuditing
@Slf4j
@RequiredArgsConstructor
@EnableConfigurationProperties({
    MonitoringConfigProperties.class,
    DbConnectionConfigProperties.class,
    AuthCertificateConfigProperties.class,
    NonceConfigProperties.class,
    RpServerConfigProperties.class
})
@EnableScheduling
public class Cdoc2KeySharesServerApplication implements CommandLineRunner {

    /**
     * Defaults that application.properties can override. The jar ships no application.properties (all
     * configuration is external), so the defaults are set here.
     * <p>
     * {@code spring.jpa.open-in-view=false}: Spring Boot's default {@code true} holds a JDBC connection for the
     * whole request once the request has used the database. A "ruhnu/did/" get-share fetches the DID document
     * (up to {@code cdoc2.ruhnu.did.request-timeout}) after reading the share, so slow DID hosts could otherwise
     * exhaust the connection pool and stall all endpoints. The server uses no lazy loading outside transactions.
     */
    static final Map<String, Object> DEFAULT_PROPERTIES = Map.of(
        "spring.jpa.open-in-view", "false"
    );

    final BuildProperties buildProperties;

    public static void main(String[] args) {
        SpringApplication app = new SpringApplication(Cdoc2KeySharesServerApplication.class);
        app.setDefaultProperties(DEFAULT_PROPERTIES);
        // capture startup events for startup actuator endpoint
        app.setApplicationStartup(MonitoringUtil.getApplicationStartupInfo());
        app.run(args);
    }

    @Override
    public void run(final String... args) throws Exception {
        log.info("CDOC2 key shares server is running.");
    }

    @Bean
    MeterRegistryCustomizer<MeterRegistry> metricsCommonTags() {
        // 'application' tag for all metrics
        return registry -> registry.config()
            .commonTags("application", buildProperties.getArtifact() // shares-server
            );
    }

}
