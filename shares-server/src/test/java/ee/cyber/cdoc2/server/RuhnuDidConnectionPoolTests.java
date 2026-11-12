package ee.cyber.cdoc2.server;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.interfaces.ECPublicKey;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import com.github.tomakehurst.wiremock.WireMockServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.orm.jpa.support.OpenEntityManagerInViewInterceptor;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.convention.TestBean;

import ee.cyber.cdoc2.server.SshPkTestData.SshKey;
import ee.cyber.cdoc2.server.config.DidResolverConfiguration;

import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;


/**
 * The DID document fetch of a "ruhnu/did/" get-share must not hold a JDBC connection
 * ({@code spring.jpa.open-in-view=false}): with a pool of one connection, a request that needs the database
 * is served while a get-share waits for a slow DID host.
 */
@TestPropertySource(properties = {
    "cdoc2.ruhnu.enabled=true",
    "spring.datasource.hikari.maximum-pool-size=1",
    // a request waiting for the only connection fails fast instead of waiting for the DID fetch
    "spring.datasource.hikari.connection-timeout=1000"
})
class RuhnuDidConnectionPoolTests extends RuhnuApiTestBase {

    private static final int DID_DELAY_MILLIS = 2500;
    private static final WireMockServer DID_HOST = DidTestData.startDidHost();

    @TestBean(name = DidResolverConfiguration.DID_HTTP_CLIENT)
    HttpClient didHttpClient;

    @Autowired
    ApplicationContext context;

    private final SshKey alice = SshKey.generate();
    private final String did = "did:web:localhost%3A" + DID_HOST.httpsPort() + ":p:alice";
    private final String docPath = "/p/alice/did.json";
    private final String recipient = DidTestData.didRecipientId(did, alice);

    static HttpClient didHttpClient() {
        return DidTestData.didHttpClientTrustingTestCerts();
    }

    @DynamicPropertySource
    static void allowDidHost(DynamicPropertyRegistry registry) {
        registry.add("cdoc2.ruhnu.did.allowed-hosts", () -> "localhost:" + DID_HOST.httpsPort());
    }

    @BeforeEach
    void resetDidHost() {
        DID_HOST.resetAll();
    }

    @AfterAll
    static void stopDidHost() {
        DID_HOST.stop();
    }

    @Test
    void shouldNotOpenEntityManagerInView() {
        assertTrue(context.getBeansOfType(OpenEntityManagerInViewInterceptor.class).isEmpty());
    }

    @Test
    void shouldServeOtherRequestsWhileDidDocumentIsFetched() throws Exception {
        DID_HOST.stubFor(get(urlEqualTo(docPath))
            .willReturn(okJson(DidTestData.didDocument(did, alice)).withFixedDelay(DID_DELAY_MILLIS)));
        String shareId = saveShare(recipient, EXPIRY_TIME);
        String token = DidTestData.createDidAuthToken(recipient, alice.keyPair(),
            (ECPublicKey) alice.keyPair().getPublic(), baseUrl, shareId, nonceFor(shareId));

        CompletableFuture<HttpResponse<String>> didGet = http.sendAsync(
            HttpRequest.newBuilder(URI.create(baseUrl + "/key-shares/" + shareId))
                .header("x-cdoc2-auth-token", token)
                .GET()
                .build(),
            HttpResponse.BodyHandlers.ofString());
        awaitDidRequest();

        // the get-share has used the database (nonce, share) and now waits for the DID host
        long start = System.nanoTime();
        HttpResponse<String> create = createShare(ETSI_RECIPIENT, null);
        long elapsedMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);

        assertEquals(201, create.statusCode(), create.body());
        assertTrue(elapsedMillis < DID_DELAY_MILLIS / 2,
            "create waited " + elapsedMillis + " ms for the DID fetch of a concurrent get-share");
        assertFalse(didGet.isDone(), "DID fetch finished before the concurrent request");

        HttpResponse<String> released = didGet.get(10, TimeUnit.SECONDS);
        assertEquals(200, released.statusCode(), released.body());
    }

    private void awaitDidRequest() throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (DID_HOST.countRequestsMatching(getRequestedFor(urlEqualTo(docPath)).build()).getCount() == 0) {
            assertTrue(System.nanoTime() < deadline, "DID document was not requested");
            Thread.sleep(20);
        }
    }
}
