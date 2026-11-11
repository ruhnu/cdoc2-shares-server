package ee.cyber.cdoc2.server;

import jakarta.validation.ConstraintViolationException;

import java.security.KeyStore;
import java.time.Instant;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.util.TestPropertyValues;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.postgresql.PostgreSQLContainer;

import com.github.dockerjava.api.model.PruneType;

import ee.cyber.cdoc2.server.model.repository.KeyShareNonceRepository;
import ee.cyber.cdoc2.server.model.repository.KeyShareRepository;
import ee.cyber.cdoc2.server.model.repository.SessionNonceRepository;
import lombok.extern.slf4j.Slf4j;

import static org.junit.jupiter.api.Assertions.*;

// Starts server on https
// Starts PostgreSQL running on docker
@Slf4j
@ExtendWith(SpringExtension.class)
@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    // start through main(), so that tests get its default properties (spring.jpa.open-in-view=false)
    useMainMethod = SpringBootTest.UseMainMethod.ALWAYS,
    properties = {"management.server.port=0"}
)
@ContextConfiguration(initializers = BaseInitializationTest.Initializer.class)
abstract class BaseInitializationTest {
    protected static final Instant EXPIRY_TIME = Instant.now().plusSeconds(86400);
    protected static final KeyStore CLIENT_TRUST_STORE = TestData.loadKeyStore(
        "JKS",
        TestData.getKeysDirectory().resolve("clienttruststore.jks"),
        "passwd"
    );

    private static PostgreSQLContainer postgresContainer;

    @BeforeAll
    public static void startPostgresContainer() {
        // Container is shared (not restarted) across all test classes extending this base class,
        // as each subclass's @BeforeAll would otherwise start (and leak, since withReuse(true)
        // opts out of Ryuk cleanup) a separate container, exhausting CI disk space.
        if (postgresContainer != null && postgresContainer.isRunning()) {
            return;
        }

        // Reclaim disk from containers/volumes left behind by earlier CI runs on this
        // runner (its docker storage persists across jobs) before starting a new one.
        try {
            DockerClientFactory.lazyClient().pruneCmd(PruneType.CONTAINERS).exec();
            DockerClientFactory.lazyClient().pruneCmd(PruneType.VOLUMES).exec();
        } catch (Exception e) {
            log.warn("Failed to prune stale docker containers/volumes", e);
        }

        postgresContainer = new PostgreSQLContainer("postgres:14.17") //Jammy 22.04 default version
            .withDatabaseName("integration-tests-db")
            .withUsername("sa")
            .withPassword("sa");
        postgresContainer.start();
    }

    static class Initializer
        implements ApplicationContextInitializer<ConfigurableApplicationContext> {
        public void initialize(ConfigurableApplicationContext configurableApplicationContext) {
            TestPropertyValues.of(
                "spring.datasource.url=" + postgresContainer.getJdbcUrl(),
                "spring.datasource.username=" + postgresContainer.getUsername(),
                "spring.datasource.password=" + postgresContainer.getPassword()
            ).applyTo(configurableApplicationContext.getEnvironment());
        }
    }

    @Value("https://localhost:${local.server.port}")
    protected String baseUrl;

    @Autowired
    protected KeyShareRepository shareRepository;

    @Autowired
    protected KeyShareNonceRepository shareNonceRepository;

    @Autowired
    protected SessionNonceRepository sessionNonceRepository;

    @Test
    void contextLoads() {
        // tests that server is configured properly (no exceptions means success)
        // In case configuration errors, spring fails run-time during initialization
        assertNotNull(shareRepository);
        assertNotNull(shareNonceRepository);
        assertNotNull(sessionNonceRepository);
        assertTrue(postgresContainer.isRunning());
    }

    void assertThrowsConstraintViolationException(Throwable cause) {
        while (cause.getCause() != null) {
            cause = cause.getCause();
        }

        assertEquals(ConstraintViolationException.class, cause.getClass());
        assertNotNull(cause.getMessage());
    }

}
