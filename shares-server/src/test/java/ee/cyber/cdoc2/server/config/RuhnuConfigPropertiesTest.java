package ee.cyber.cdoc2.server.config;

import java.time.Duration;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;

import ee.cyber.cdoc2.server.config.RuhnuConfigProperties.Pk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;


class RuhnuConfigPropertiesTest {

    private final Logger logger = (Logger) LoggerFactory.getLogger(RuhnuConfigProperties.class);
    private final ListAppender<ILoggingEvent> appender = new ListAppender<>();

    @BeforeEach
    void startLogCapture() {
        appender.start();
        logger.addAppender(appender);
    }

    @AfterEach
    void stopLogCapture() {
        logger.detachAppender(appender);
        appender.stop();
    }

    @Test
    void shouldWarnWhenDefaultIsLongerThanMax() {
        new RuhnuConfigProperties(true, new Pk(Duration.ofDays(14), Duration.ofDays(7)));

        List<ILoggingEvent> events = appender.list;
        assertEquals(1, events.size());
        assertEquals(Level.WARN, events.get(0).getLevel());
        assertEquals("cdoc2.ruhnu.pk.default-expiration-duration (PT336H) is longer than "
            + "cdoc2.ruhnu.pk.max-expiration-duration (PT168H), the maximum is used as the default",
            events.get(0).getFormattedMessage());
    }

    @Test
    void shouldNotWarnWhenDefaultIsWithinMax() {
        new RuhnuConfigProperties(true, new Pk(Duration.ofDays(1), Duration.ofDays(7)));
        new RuhnuConfigProperties(true, new Pk(Duration.ofDays(7), Duration.ofDays(7)));

        assertTrue(appender.list.isEmpty());
    }

    @Test
    void shouldNotWarnWhenDisabled() {
        new RuhnuConfigProperties(false, new Pk(Duration.ofDays(14), Duration.ofDays(7)));

        assertTrue(appender.list.isEmpty());
    }
}
