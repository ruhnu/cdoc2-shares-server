package ee.cyber.cdoc2.server;

import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.security.interfaces.ECPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.http.Fault;
import com.github.tomakehurst.wiremock.stubbing.Scenario;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.convention.TestBean;

import ch.qos.logback.classic.spi.ILoggingEvent;

import ee.cyber.cdoc2.server.SshPkTestData.SshKey;
import ee.cyber.cdoc2.server.config.DidResolverConfiguration;
import ee.cyber.cdoc2.server.model.entity.KeyShareDb;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.anyRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.anyUrl;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;


/**
 * "ruhnu/did/" DID recipients with {@code cdoc2.ruhnu.enabled=true}. The DID host is a WireMock HTTPS stub on
 * localhost, in {@code cdoc2.ruhnu.did.allowed-hosts}. Each test uses its own DID paths, so that a late request
 * of an earlier test (for example one cancelled at the deadline) cannot count as a request of the next one.
 */
@TestPropertySource(properties = {
    "cdoc2.ruhnu.enabled=true",
    "cdoc2.ruhnu.did.request-timeout=PT3S"
})
class RuhnuDidApiTests extends RuhnuApiTestBase {

    private static final WireMockServer DID_HOST = DidTestData.startDidHost();

    @TestBean(name = DidResolverConfiguration.DID_HTTP_CLIENT)
    HttpClient didHttpClient;

    private final SshKey alice = SshKey.generate();
    private final SshKey bob = SshKey.generate();
    // unique per test, part of every DID path the test uses
    private final String testId = UUID.randomUUID().toString().substring(0, 8);
    private final String did = didFor("alice");
    private final String docPath = "/p/alice-" + testId + "/did.json";
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

    // --- create ---

    @Test
    void shouldCreateDidShareForAllowedHostWithGlobalExpiry() throws Exception {
        Instant before = Instant.now();
        HttpResponse<String> resp = createShare(recipient, null);

        assertEquals(201, resp.statusCode(), resp.body());
        KeyShareDb stored = shareRepository.findById(shareIdFrom(resp)).orElseThrow();
        assertEquals(recipient, stored.getRecipient());
        // global key-share.default-expiration-duration=P1095D, not the 14 day "ruhnu/pk/" default
        assertAbout(before.plus(Duration.ofDays(1095)), stored.getExpiryTime());
        assertNoDidRequest();
    }

    @Test
    void shouldCutDidShareExpiryToGlobalMax() throws Exception {
        Instant before = Instant.now();
        HttpResponse<String> resp = createShare(recipient, Instant.now().plus(Duration.ofDays(3650)));

        assertEquals(201, resp.statusCode(), resp.body());
        assertEquals("true", resp.headers().firstValue("x-expiry-time-adjusted").orElseThrow());
        assertAbout(before.plus(Duration.ofDays(1825)),
            shareRepository.findById(shareIdFrom(resp)).orElseThrow().getExpiryTime());
    }

    @Test
    void shouldAcceptShorterRequestedExpiry() throws Exception {
        Instant requested = Instant.now().plus(Duration.ofDays(3)).truncatedTo(ChronoUnit.SECONDS);
        HttpResponse<String> resp = createShare(recipient, requested);

        assertEquals(201, resp.statusCode(), resp.body());
        assertEquals(requested, shareRepository.findById(shareIdFrom(resp)).orElseThrow().getExpiryTime());
    }

    @Test
    void shouldRefuseDidShareForHostOrPortNotInList() throws Exception {
        for (String otherDid : List.of(
            "did:web:example.org:p:alice",
            "did:web:localhost%3A" + (DID_HOST.httpsPort() + 1) + ":p:alice",
            "did:web:localhost:p:alice")) {
            HttpResponse<String> resp = createShare(DidTestData.didRecipientId(otherDid, alice), null);

            assertEquals(400, resp.statusCode(), otherDid);
        }
        assertEquals(0, shareRepository.count());
        assertNoDidRequest();
    }

    @Test
    void shouldRefuseMalformedDidRecipients() throws Exception {
        String fingerprint = recipient.substring(recipient.lastIndexOf('/') + 1);
        for (String malformed : List.of(
            "ruhnu/did/did:key:zDnaeXyz/hash/" + fingerprint,
            "ruhnu/did/did:web:192.0.2.1/hash/" + fingerprint,
            "ruhnu/did/" + did + "/hash/" + fingerprint.substring(1),
            "ruhnu/did/" + did + "/hash/" + fingerprint + "=",
            "ruhnu/did/" + did + "/extra/hash/" + fingerprint)) {
            HttpResponse<String> resp = createShare(malformed, null);

            assertEquals(400, resp.statusCode(), malformed);
        }
        assertEquals(0, shareRepository.count());
        assertNoDidRequest();
    }

    // --- nonce ---

    @Test
    void shouldCreateNonceForDidShareWithoutResolvingDid() throws Exception {
        DID_HOST.stubFor(get(anyUrl()).willReturn(aResponse().withFault(Fault.CONNECTION_RESET_BY_PEER)));
        String shareId = saveShare(recipient, EXPIRY_TIME);

        HttpResponse<String> resp = createNonce(shareId, Map.of());

        assertEquals(200, resp.statusCode(), resp.body());
        assertTrue(resp.body().contains("\"nonce\""), resp.body());
        assertNoDidRequest();
    }

    @Test
    void shouldReturn404ForNonceForExpiredDidShare() throws Exception {
        String shareId = saveShare(recipient, Instant.now().minusSeconds(60));

        assertEquals(404, createNonce(shareId, Map.of()).statusCode());
    }

    // --- get share ---

    @Test
    void shouldReleaseDidShareWhenKeyListed() throws Exception {
        serveDidDocument(DidTestData.didDocument(did, bob, alice));
        String shareId = saveShare(recipient, EXPIRY_TIME);

        HttpResponse<String> resp = getShare(shareId, aliceToken(shareId));

        assertEquals(200, resp.statusCode(), resp.body());
        assertTrue(resp.body().contains("\"share\""), resp.body());
        DID_HOST.verify(1, getRequestedFor(urlEqualTo(docPath)));

        List<ILoggingEvent> events = auditLog.list;
        assertEquals(1, events.size());
        String line = events.get(0).getFormattedMessage();
        assertTrue(line.contains("shareId=" + shareId), line);
        assertTrue(line.contains("recipient=" + recipient), line);
        assertTrue(line.contains("time="), line);
    }

    @Test
    void shouldReturn404WhenKeyRemovedFromDidDocument() throws Exception {
        serveDidDocument(DidTestData.didDocument(did, bob));
        String shareId = saveShare(recipient, EXPIRY_TIME);

        assertRefused(404, getShare(shareId, aliceToken(shareId)));
        DID_HOST.verify(1, getRequestedFor(urlEqualTo(docPath)));
    }

    @Test
    void shouldReturn404WhenDidNotFound() throws Exception {
        // no stub: WireMock answers 404
        String shareId = saveShare(recipient, EXPIRY_TIME);

        assertRefused(404, getShare(shareId, aliceToken(shareId)));
        DID_HOST.verify(1, getRequestedFor(urlEqualTo(docPath)));
    }

    @Test
    void shouldReturn404ForDocumentOfAnotherDid() throws Exception {
        serveDidDocument(DidTestData.didDocument(didFor("bob"), alice));
        String shareId = saveShare(recipient, EXPIRY_TIME);

        assertRefused(404, getShare(shareId, aliceToken(shareId)));
    }

    @Test
    void shouldReturn503WhenDidHostUnavailable() throws Exception {
        String shareId = saveShare(recipient, EXPIRY_TIME);

        DID_HOST.stubFor(get(urlEqualTo(docPath)).willReturn(aResponse().withStatus(503)));
        assertRefused(503, getShare(shareId, aliceToken(shareId)));

        DID_HOST.stubFor(get(urlEqualTo(docPath)).willReturn(aResponse().withFault(Fault.CONNECTION_RESET_BY_PEER)));
        assertRefused(503, getShare(shareId, aliceToken(shareId)));

        // slower than cdoc2.ruhnu.did.request-timeout=PT3S
        DID_HOST.stubFor(get(urlEqualTo(docPath))
            .willReturn(okJson(DidTestData.didDocument(did, alice)).withFixedDelay(6000)));
        assertRefused(503, getShare(shareId, aliceToken(shareId)));
    }

    @Test
    void shouldReleaseShareOnRetryAfterOutage() throws Exception {
        DID_HOST.stubFor(get(urlEqualTo(docPath)).inScenario("outage")
            .whenScenarioStateIs(Scenario.STARTED)
            .willReturn(aResponse().withStatus(503))
            .willSetStateTo("recovered"));
        DID_HOST.stubFor(get(urlEqualTo(docPath)).inScenario("outage")
            .whenScenarioStateIs("recovered")
            .willReturn(okJson(DidTestData.didDocument(did, alice))));
        String shareId = saveShare(recipient, EXPIRY_TIME);
        String token = aliceToken(shareId);

        assertRefused(503, getShare(shareId, token));
        // same token, same nonce
        HttpResponse<String> retry = getShare(shareId, token);

        assertEquals(200, retry.statusCode(), retry.body());
        assertEquals(1, auditLog.list.size());
    }

    @Test
    void shouldReturn401ForHeaderKeyNotMatchingFingerprint() throws Exception {
        serveDidDocument(DidTestData.didDocument(did, alice, bob));
        String shareId = saveShare(recipient, EXPIRY_TIME);
        // "iss" pins alice, the header and the signature are bob's
        String token = DidTestData.createDidAuthToken(recipient, bob.keyPair(), publicKey(bob), baseUrl, shareId,
            nonceFor(shareId));

        assertRefused(401, getShare(shareId, token));
        assertNoDidRequest();
    }

    @Test
    void shouldReturn401ForTokenSignedByDifferentKey() throws Exception {
        serveDidDocument(DidTestData.didDocument(did, alice, bob));
        String shareId = saveShare(recipient, EXPIRY_TIME);
        String token = DidTestData.createDidAuthToken(recipient, bob.keyPair(), publicKey(alice), baseUrl, shareId,
            nonceFor(shareId));

        assertRefused(401, getShare(shareId, token));
        assertNoDidRequest();
    }

    @Test
    void shouldReturn401ForMissingOrUnsupportedHeaderKey() throws Exception {
        serveDidDocument(DidTestData.didDocument(did, alice));
        String shareId = saveShare(recipient, EXPIRY_TIME);

        String noJwk = DidTestData.createDidAuthToken(recipient, alice.keyPair(), null, baseUrl, shareId,
            nonceFor(shareId));
        assertRefused(401, getShare(shareId, noJwk));

        SshKey p384 = SshKey.generateP384();
        String es384 = DidTestData.createDidAuthToken(recipient, p384.keyPair(), publicKey(p384), baseUrl, shareId,
            nonceFor(shareId));
        assertRefused(401, getShare(shareId, es384));
        assertNoDidRequest();
    }

    @Test
    void shouldReturn404ForTokenOfAnotherDidRecipient() throws Exception {
        serveDidDocument(DidTestData.didDocument(did, alice, bob));
        String shareId = saveShare(recipient, EXPIRY_TIME);

        // validly signed, but for bob's identifier in the same DID
        String bobRecipient = DidTestData.didRecipientId(did, bob);
        String bobToken = DidTestData.createDidAuthToken(bobRecipient, bob.keyPair(), publicKey(bob), baseUrl,
            shareId, nonceFor(shareId));
        assertRefused(404, getShare(shareId, bobToken));

        // validly signed with alice's key, but for another DID
        String otherDid = DidTestData.didRecipientId(didFor("eve"), alice);
        String otherDidToken = DidTestData.createDidAuthToken(otherDid, alice.keyPair(), publicKey(alice), baseUrl,
            shareId, nonceFor(shareId));
        assertRefused(404, getShare(shareId, otherDidToken));
        assertNoDidRequest();
    }

    @Test
    void shouldReturn401ForTokenForAnotherServerOrShare() throws Exception {
        serveDidDocument(DidTestData.didDocument(did, alice));
        String shareId = saveShare(recipient, EXPIRY_TIME);
        String otherShareId = saveShare(recipient, EXPIRY_TIME);

        String otherServer = DidTestData.createDidAuthToken(recipient, alice.keyPair(), publicKey(alice),
            "https://other.example.org:8443", shareId, nonceFor(shareId));
        assertRefused(401, getShare(shareId, otherServer));

        String otherShare = DidTestData.createDidAuthToken(recipient, alice.keyPair(), publicKey(alice), baseUrl,
            otherShareId, nonceFor(otherShareId));
        assertRefused(401, getShare(shareId, otherShare));
        assertNoDidRequest();
    }

    @Test
    void shouldReturn404ForDidTokenForSshPkShareOfSameKey() throws Exception {
        serveDidDocument(DidTestData.didDocument(did, alice));
        String shareId = saveShare(alice.recipientId(), EXPIRY_TIME);

        assertRefused(404, getShare(shareId, aliceToken(shareId)));
        assertNoDidRequest();
    }

    @Test
    void shouldReturn404ForExpiredDidShare() throws Exception {
        serveDidDocument(DidTestData.didDocument(did, alice));
        String shareId = saveShare(recipient, Instant.now().minusSeconds(60));

        assertRefused(404, getShare(shareId, aliceToken(shareId)));
        assertNoDidRequest();
    }

    @Test
    void shouldReturn404WhenHostRemovedFromList() throws Exception {
        // stored while its host was allowed; the host is not in the list now
        String removedHostDid = "did:web:localhost%3A" + (DID_HOST.httpsPort() + 1) + ":p:alice";
        String removedHostRecipient = DidTestData.didRecipientId(removedHostDid, alice);
        String shareId = saveShare(removedHostRecipient, EXPIRY_TIME);
        String token = DidTestData.createDidAuthToken(removedHostRecipient, alice.keyPair(), publicKey(alice),
            baseUrl, shareId, nonceFor(shareId));

        assertRefused(404, getShare(shareId, token));
        assertNoDidRequest();
    }

    @Test
    void shouldReturn400ForEtsiTokenWithoutSessionHeaders() throws Exception {
        String shareId = saveShare(ETSI_RECIPIENT, EXPIRY_TIME);
        String token = SshPkTestData.createEtsiAuthToken(ETSI_RECIPIENT, baseUrl, shareId, nonceFor(shareId));

        assertRefused(400, getShare(shareId, token));
        assertNoDidRequest();
    }

    private String aliceToken(String shareId) {
        return DidTestData.createDidAuthToken(recipient, alice.keyPair(), publicKey(alice), baseUrl, shareId,
            nonceFor(shareId));
    }

    private static ECPublicKey publicKey(SshKey key) {
        return (ECPublicKey) key.keyPair().getPublic();
    }

    private String didFor(String user) {
        return "did:web:localhost%3A" + DID_HOST.httpsPort() + ":p:" + user + "-" + testId;
    }

    private void serveDidDocument(String json) {
        DID_HOST.stubFor(get(urlEqualTo(docPath)).willReturn(okJson(json)));
    }

    /** No request of this test reached the DID host */
    private void assertNoDidRequest() {
        DID_HOST.verify(0, anyRequestedFor(urlPathMatching(".*-" + testId + "/.*")));
    }
}
