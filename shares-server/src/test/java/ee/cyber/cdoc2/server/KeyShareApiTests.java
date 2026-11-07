package ee.cyber.cdoc2.server;

import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.junit5.WireMockExtension;

import ee.cyber.cdoc2.client.Cdoc2KeySharesApiClient;
import ee.cyber.cdoc2.client.api.ApiException;
import ee.cyber.cdoc2.client.model.KeyShare;
import ee.cyber.cdoc2.client.model.NonceResponse;
import ee.cyber.cdoc2.server.api.KeyShareApiService;
import ee.cyber.cdoc2.server.config.KeyShareExpiryConfigProperties;
import ee.cyber.cdoc2.server.config.MonitoringConfigProperties;
import ee.cyber.cdoc2.server.model.entity.KeyShareDb;
import ee.cyber.cdoc2.server.model.entity.SessionNonceDb;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static ee.cyber.cdoc2.server.TestData.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;


@Slf4j
class KeyShareApiTests extends KeyShareIntegrationTest {
    private static final byte[] SHARE = new byte[128];
    private static final String SHARE_RECIPIENT = TEST_ETSI_RECIPIENT;
    private static final Instant INSTANT_NOW_SESSION_TOKEN_NOT_EXPIRED =
        Instant.parse("2026-04-22T12:30:00Z");
    private static final Instant INSTANT_AFTER_SESSION_TOKEN_EXPIRED =
        Instant.parse("2027-01-01T00:00:00Z");
    private static final int WIREMOCK_PORT = 8090;

    @SuppressWarnings("checkstyle:LineLength")
    private static final String SIGNATURE_VALIDATION_PARAMS_BASE64URL =
        "eyJpbnRlcmFjdGlvbnNEaWdlc3QiOiI0QTNRS0Rxam1xQXR4Rmo2U2lZNWtiVHBMYURZN3BQRnAzb0RBNXFBYy84PSIsImludGVyYWN0aW9uVHlwZVVzZWQiOiJjb25maXJtYXRpb25NZXNzYWdlQW5kVmVyaWZpY2F0aW9uQ29kZUNob2ljZSIsInNpZ25hdHVyZSI6eyJzZXJ2ZXJSYW5kb20iOiJBcmRTanNUTlFnYkRNNFdza2ttWUFJU1UiLCJ1c2VyQ2hhbGxlbmdlIjoiRmI0VGtKUmZTbDdoaGZBSElpc0lZaVhzWDFRTjhyVEg4RHdoTnNKeC1hZyIsInNpZ25hdHVyZUFsZ29yaXRobSI6InJzYXNzYS1wc3MiLCJmbG93VHlwZSI6Ik5vdGlmaWNhdGlvbiIsInNpZ25hdHVyZUFsZ29yaXRobVBhcmFtZXRlcnMiOnsiaGFzaEFsZ29yaXRobSI6IlNIQS0yNTYiLCJtYXNrR2VuQWxnb3JpdGhtIjp7ImFsZ29yaXRobSI6ImlkLW1nZjEiLCJwYXJhbWV0ZXJzIjp7Imhhc2hBbGdvcml0aG0iOiJTSEEtMjU2In19LCJzYWx0TGVuZ3RoIjozMiwidHJhaWxlckZpZWxkIjoiMHhiYyJ9fX0=";

    @RegisterExtension
    static WireMockExtension wiremock = WireMockExtension.newInstance()
        .options(wireMockConfig().port(WIREMOCK_PORT))
        .build();

    @Autowired
    private MonitoringConfigProperties configProperties;

    @Autowired
    private ResourceLoader resourceLoader;

    private Cdoc2KeySharesApiClient client;

    @MockitoBean
    private Clock clock;

    @Autowired
    private KeyShareApiService keyShareApiService;

    @MockitoSpyBean
    private ValidateAuthToken validateAuthToken;

    @Autowired
    private KeyShareExpiryConfigProperties keyShareExpiryConfig;

    @BeforeEach
    public void setup() throws Exception {
        client = createClient();

        Resource resource = resourceLoader.getResource("classpath:auth-server-well-known.json");
        String keysResponseBody = resource.getContentAsString(StandardCharsets.UTF_8);

        wiremock.stubFor(
            WireMock.get(urlEqualTo("/.well-known/jwks.jws"))
                .willReturn(aResponse()
                    .withStatus(HttpStatus.OK.value())
                    .withBody(keysResponseBody)
                )
        );

        saveNonceForSessionToken();
        when(clock.instant()).thenReturn(INSTANT_NOW_SESSION_TOKEN_NOT_EXPIRED);
    }

    //TODO Figure out a way to dynamically create RPv3-signed auth tokens (maybe not too difficult),
    // and/or move testing of this usecase to some external functional testing suite.
    @Test
    @Disabled
    void shouldGetKeyShare() throws Exception {
        KeyShare keyShare = createKeyShare();
        keyShare.setRecipient(SHARE_RECIPIENT);

        String shareId = this.saveKeyShare(keyShare).getShareId();
        String nonce = client.createNonce(
            shareId,
            SESSION_TOKEN_WITH_FILTERED_DISCLOSURES_BASE64URL,
            SID_SIGNING_CERTIFICATE_BASE64URL
        ).getNonce();
        String xAuthToken = TestData.generateTestAuthToken(TestData.TEST_IDENTIFIER, baseUrl, shareId, nonce);

        Optional<KeyShare> response = client.getKeyShare(shareId, xAuthToken,
            TestData.TEST_CERT_PEM,
            SESSION_TOKEN_WITH_FILTERED_DISCLOSURES_BASE64URL,
            SID_SIGNING_CERTIFICATE_BASE64URL,
            SIGNATURE_VALIDATION_PARAMS_BASE64URL,
            new Cdoc2KeySharesApiClient.RpCountersignatureParams(
                null, null, null, null
            )
        );

        assertTrue(response.isPresent());
        KeyShare savedKeyShare = response.get();
        assertEquals(keyShare.getRecipient(), savedKeyShare.getRecipient());
        assertArrayEquals(keyShare.getShare(), savedKeyShare.getShare());
    }

    @Test
    void shouldFailToGetKeyShareWithBadRequest() {
        String shareId = "short";
        String xAuthToken = "";
        String xAuthCert = "";

        ApiException ex = assertThrows(
            ApiException.class,
            () -> client.getKeyShare(shareId, xAuthToken, xAuthCert,
                SESSION_TOKEN_WITH_FILTERED_DISCLOSURES_BASE64URL,
                SID_SIGNING_CERTIFICATE_BASE64URL,
                SIGNATURE_VALIDATION_PARAMS_BASE64URL,
                new Cdoc2KeySharesApiClient.RpCountersignatureParams(
                    null, null, null, null
                )
            )
        );

        assertBadRequest(ex.getCode());
    }

    @Test
    void shouldFailWith400WhenGetKeyShareCertParamIsEmpty() throws Exception {
        KeyShare keyShare = createKeyShare();
        keyShare.setRecipient(SHARE_RECIPIENT);

        String shareId = this.saveKeyShare(keyShare).getShareId();
        String nonce = client.createNonce(
            shareId,
            SESSION_TOKEN_WITH_FILTERED_DISCLOSURES_BASE64URL,
            SID_SIGNING_CERTIFICATE_BASE64URL
        ).getNonce();
        String xAuthToken = TestData.generateTestAuthToken(TestData.TEST_CERT_IDENTIFIER, baseUrl, shareId, nonce);

        ApiException ex = assertThrows(
            ApiException.class,
            // null is checked by openapi generated code, but "" resulted NullPointerException, because
            // jose X509CertUtils.parseWithException("") returns null
            () -> client.getKeyShare(shareId, xAuthToken, "",
                SESSION_TOKEN_WITH_FILTERED_DISCLOSURES_BASE64URL,
                SID_SIGNING_CERTIFICATE_BASE64URL,
                SIGNATURE_VALIDATION_PARAMS_BASE64URL,
                new Cdoc2KeySharesApiClient.RpCountersignatureParams(
                    null, null, null, null
                )
            )
        );

        assertBadRequest(ex.getCode());
    }

    @Test
    void shouldFailWith400WhenGetKeyShareAuthTokenParamIsEmpty() {
        KeyShare keyShare = createKeyShare();
        keyShare.setRecipient(SHARE_RECIPIENT);

        String shareId = this.saveKeyShare(keyShare).getShareId();

        ApiException ex = assertThrows(
            ApiException.class,
            () -> client.getKeyShare(shareId, "", TestData.TEST_CERT_PEM,
                SESSION_TOKEN_WITH_FILTERED_DISCLOSURES_BASE64URL,
                SID_SIGNING_CERTIFICATE_BASE64URL,
                SIGNATURE_VALIDATION_PARAMS_BASE64URL,
                new Cdoc2KeySharesApiClient.RpCountersignatureParams(
                    null, null, null, null
                )
            )
        );

        assertEquals(HttpStatus.BAD_REQUEST.value(), ex.getCode());
    }


    //TODO Figure out a way to dynamically create RPv3-signed auth tokens (maybe not too difficult),
    // and/or move testing of this usecase to some external functional testing suite.
    @Test
    @Disabled
    void shouldFailToGetKeyShareWithNotFound() throws ApiException {
        String shareId = "SHARE_ID_MIN_LENGTH_SHOULD_BE_32";

        String nonce = "random";
        String xAuthToken = TestData.generateTestAuthToken(TEST_CERT_IDENTIFIER, baseUrl, shareId, nonce);

        Optional<KeyShare> keyShare = client.getKeyShare(
            shareId,
            xAuthToken,
            pemCertToBase64Url(TestData.TEST_CERT_PEM),
            SESSION_TOKEN_WITH_FILTERED_DISCLOSURES_BASE64URL,
            SID_SIGNING_CERTIFICATE_BASE64URL,
            SIGNATURE_VALIDATION_PARAMS_BASE64URL,
            new Cdoc2KeySharesApiClient.RpCountersignatureParams(
                null, null, null, null
            ));

        assertTrue(keyShare.isEmpty());
    }

    @Test
    void shouldCreateKeyShare() throws Exception {
        var keyShare = createKeyShare();

        String response = client.createKeyShare(keyShare, null);

        assertKeyShare(keyShare, response);
    }

    @Test
    void shouldCreateKeyShareWithExplicitExpiryTimeWithinMax() {
        var serverKeyShare = new ee.cyber.cdoc2.server.generated.model.KeyShare();
        serverKeyShare.setShare(SHARE);
        serverKeyShare.setRecipient(SHARE_RECIPIENT);

        // half the configured max — guaranteed to be within max regardless of its value
        Duration maxDuration = Duration.parse(keyShareExpiryConfig.maxExpirationDuration());
        LocalDateTime expiryTime = LocalDateTime.now().plus(maxDuration.dividedBy(2));

        var resp = keyShareApiService.createKeyShare(serverKeyShare, expiryTime);

        assertEquals(HttpStatus.CREATED.value(), resp.getStatusCode().value());
        assertEquals("false", resp.getHeaders().getFirst(Constants.X_EXPIRY_TIME_ADJUSTED));
        assertExpiryTimeStoredInDb(resp, expiryTime.toInstant(ZoneOffset.UTC));
    }

    @Test
    void shouldCreateKeyShareWithExpiryTimeAdjustedWhenExceedingMax() {
        var serverKeyShare = new ee.cyber.cdoc2.server.generated.model.KeyShare();
        serverKeyShare.setShare(SHARE);
        serverKeyShare.setRecipient(SHARE_RECIPIENT);

        // double the configured max — guaranteed to exceed it regardless of its value
        Duration maxDuration = Duration.parse(keyShareExpiryConfig.maxExpirationDuration());
        LocalDateTime expiryTime = LocalDateTime.now().plus(maxDuration.multipliedBy(2));
        Instant expectedAdjustedExpiry = Instant.now().plus(maxDuration);

        var resp = keyShareApiService.createKeyShare(serverKeyShare, expiryTime);

        assertEquals(HttpStatus.CREATED.value(), resp.getStatusCode().value());
        assertEquals("true", resp.getHeaders().getFirst(Constants.X_EXPIRY_TIME_ADJUSTED));
        assertExpiryTimeStoredInDb(resp, expectedAdjustedExpiry);
    }

    @Test
    void shouldFailToCreateKeyShareWithShortShare() {
        byte[] shortShare = new byte[10];
        var keyShare = new ee.cyber.cdoc2.client.model.KeyShare()
            .recipient(SHARE_RECIPIENT)
            .share(shortShare);

        assertThrowsBadRequest(keyShare);
    }

    @Test
    void shouldFailToCreateKeyShareWithTooLongShare() {
        byte[] tooLongShare = new byte[254];
        var keyShare = new ee.cyber.cdoc2.client.model.KeyShare()
            .recipient(SHARE_RECIPIENT)
            .share(tooLongShare);

        assertThrowsBadRequest(keyShare);
    }

    @Test
    void shouldFailToCreateKeyShareWithShortRecipient() {
        var keyShare = new ee.cyber.cdoc2.client.model.KeyShare()
            .recipient("short")
            .share(SHARE);

        assertThrowsBadRequest(keyShare);
    }

    @Test
    void shouldFailToCreateKeyShareWithTooLongRecipient() {
        var keyShare = new ee.cyber.cdoc2.client.model.KeyShare()
            .recipient("Tooooooooooooooooooooooooooo_looooooooooooooooooooooooong_recipient")
            .share(SHARE);

        assertThrowsBadRequest(keyShare);
    }

    @Test
    void shouldCreateKeyShareNonce() throws Exception {
        var keyShare = createKeyShare();

        String shareId = this.saveKeyShare(keyShare).getShareId();

        NonceResponse response = client.createNonce(
            shareId,
            SESSION_TOKEN_WITH_FILTERED_DISCLOSURES_BASE64URL,
            SID_SIGNING_CERTIFICATE_BASE64URL
        );
        assertNotNull(response);
    }

    @Test
    void shouldFailToCreateKeyShareNonceWithNotFoundKeyShareId() {
        String shareId = "SHARE_ID_MIN_LENGTH_SHOULD_BE_32";

        ApiException ex = assertThrows(
            ApiException.class,
            () -> client.createNonce(
                shareId,
                SESSION_TOKEN_WITH_FILTERED_DISCLOSURES_BASE64URL,
                SID_SIGNING_CERTIFICATE_BASE64URL
            )
        );

        assertEquals(HttpStatus.NOT_FOUND.value(), ex.getCode());
    }

    @Test
    void createNonceShouldReturnNotFoundForExpiredKeyShare() {
        String shareId = this.saveKeyShare(
            createKeyShare(),
            INSTANT_NOW_SESSION_TOKEN_NOT_EXPIRED.minus(Duration.ofHours(1))
        ).getShareId();

        ApiException ex = assertThrows(
            ApiException.class,
            () -> client.createNonce(
                shareId,
                SESSION_TOKEN_WITH_FILTERED_DISCLOSURES_BASE64URL,
                SID_SIGNING_CERTIFICATE_BASE64URL
            )
        );

        assertEquals(HttpStatus.NOT_FOUND.value(), ex.getCode());
        assertEquals(0, this.shareNonceRepository.count());
    }

    @Test
    void createNonceShouldReturnNotFoundForKeyShareExpiringNow() {
        String shareId = this.saveKeyShare(
            createKeyShare(),
            INSTANT_NOW_SESSION_TOKEN_NOT_EXPIRED
        ).getShareId();

        ApiException ex = assertThrows(
            ApiException.class,
            () -> client.createNonce(
                shareId,
                SESSION_TOKEN_WITH_FILTERED_DISCLOSURES_BASE64URL,
                SID_SIGNING_CERTIFICATE_BASE64URL
            )
        );

        assertEquals(HttpStatus.NOT_FOUND.value(), ex.getCode());
        assertEquals(0, this.shareNonceRepository.count());
    }

    @Test
    void shouldCreateKeyShareNonceForKeyShareNotYetExpired() throws Exception {
        String shareId = this.saveKeyShare(
            createKeyShare(),
            INSTANT_NOW_SESSION_TOKEN_NOT_EXPIRED.plusSeconds(1)
        ).getShareId();

        NonceResponse response = client.createNonce(
            shareId,
            SESSION_TOKEN_WITH_FILTERED_DISCLOSURES_BASE64URL,
            SID_SIGNING_CERTIFICATE_BASE64URL
        );

        assertNotNull(response);
        assertEquals(1, this.shareNonceRepository.count());
    }

    @Test
    void createNonceForExpiredKeyShareShouldReturnUnauthorizedWhenSessionTokenExpired() {
        // the share is expired as well, but the session token is checked first,
        // so the caller gets the same 401 as for an unexpired share
        String shareId = this.saveKeyShare(
            createKeyShare(),
            INSTANT_NOW_SESSION_TOKEN_NOT_EXPIRED
        ).getShareId();
        when(clock.instant()).thenReturn(INSTANT_AFTER_SESSION_TOKEN_EXPIRED);

        ApiException ex = assertThrows(
            ApiException.class,
            () -> client.createNonce(
                shareId,
                SESSION_TOKEN_WITH_FILTERED_DISCLOSURES_BASE64URL,
                SID_SIGNING_CERTIFICATE_BASE64URL
            )
        );

        assertEquals(HttpStatus.UNAUTHORIZED.value(), ex.getCode());
    }

    @Test
    void createNonceShouldReturnUnauthorizedWhenSessionTokenExpired() {
        String shareId = "SHARE_ID_MIN_LENGTH_SHOULD_BE_32";
        when(clock.instant()).thenReturn(INSTANT_AFTER_SESSION_TOKEN_EXPIRED);

        ApiException ex = assertThrows(
            ApiException.class,
            () -> client.createNonce(
                shareId,
                SESSION_TOKEN_WITH_FILTERED_DISCLOSURES_BASE64URL,
                SID_SIGNING_CERTIFICATE_BASE64URL
            )
        );

        assertEquals(HttpStatus.UNAUTHORIZED.value(), ex.getCode());
    }

    @Test
    void createNonceShouldReturnUnauthorizedWhenSessionNonceMissing() {
        String shareId = "SHARE_ID_MIN_LENGTH_SHOULD_BE_32";
        sessionNonceRepository.deleteAll();

        ApiException ex = assertThrows(
            ApiException.class,
            () -> client.createNonce(
                shareId,
                SESSION_TOKEN_WITH_FILTERED_DISCLOSURES_BASE64URL,
                SID_SIGNING_CERTIFICATE_BASE64URL
            )
        );

        assertEquals(HttpStatus.UNAUTHORIZED.value(), ex.getCode());
    }

    @Test
    void getKeyShareShouldReturnUnauthorizedWhenSessionNonceMissing() throws ApiException {
        var keyShare = createKeyShare();
        String shareId = this.saveKeyShare(keyShare).getShareId();

        String nonce = client.createNonce(
            shareId,
            SESSION_TOKEN_WITH_FILTERED_DISCLOSURES_BASE64URL,
            SID_SIGNING_CERTIFICATE_BASE64URL
        ).getNonce();
        String xAuthToken =
            TestData.generateTestAuthToken(TestData.TEST_CERT_IDENTIFIER, baseUrl, shareId, nonce);

        sessionNonceRepository.deleteAll();

        ApiException ex = assertThrows(
            ApiException.class,
            () -> client.getKeyShare(
                shareId,
                xAuthToken,
                pemCertToBase64Url(TestData.TEST_CERT_PEM),
                SESSION_TOKEN_WITH_FILTERED_DISCLOSURES_BASE64URL,
                SID_SIGNING_CERTIFICATE_BASE64URL,
                SIGNATURE_VALIDATION_PARAMS_BASE64URL,
                new Cdoc2KeySharesApiClient.RpCountersignatureParams(null, null, null, null)
            )
        );

        assertEquals(HttpStatus.UNAUTHORIZED.value(), ex.getCode());
        // the 401 must come from session token validation, before auth token is even looked at,
        // otherwise this test would also pass on an invalid/unparseable auth token, which is a
        // different failure than the missing session nonce it is meant to cover
        verifyNoInteractions(validateAuthToken);
    }

    @Test
    void getKeyShareShouldReturnUnauthorizedWhenSessionTokenExpired() throws ApiException {
        var keyShare = createKeyShare();
        String shareId = this.saveKeyShare(keyShare).getShareId();

        String nonce = client.createNonce(
            shareId,
            SESSION_TOKEN_WITH_FILTERED_DISCLOSURES_BASE64URL,
            SID_SIGNING_CERTIFICATE_BASE64URL
        ).getNonce();
        String xAuthToken =
            TestData.generateTestAuthToken(TestData.TEST_CERT_IDENTIFIER, baseUrl, shareId, nonce);

        when(clock.instant()).thenReturn(INSTANT_AFTER_SESSION_TOKEN_EXPIRED);

        ApiException ex = assertThrows(
            ApiException.class,
            () -> client.getKeyShare(
                shareId,
                xAuthToken,
                TestData.TEST_CERT_PEM,
                SESSION_TOKEN_WITH_FILTERED_DISCLOSURES_BASE64URL,
                SID_SIGNING_CERTIFICATE_BASE64URL,
                SIGNATURE_VALIDATION_PARAMS_BASE64URL,
                new Cdoc2KeySharesApiClient.RpCountersignatureParams(null, null, null, null)
            )
        );

        assertEquals(HttpStatus.UNAUTHORIZED.value(), ex.getCode());
        // same rationale as in getKeyShareShouldReturnUnauthorizedWhenSessionNonceMissing:
        // pin the 401 to the expired session token, not to an invalid auth token
        verifyNoInteractions(validateAuthToken);
    }

    private Cdoc2KeySharesApiClient createClient() throws Exception {
        var builder = Cdoc2KeySharesApiClient.builder();
        builder.withBaseUrl(baseUrl);
        builder.withUsername(configProperties.username());
        builder.withPassword(configProperties.password());
        builder.withTrustKeyStore(CLIENT_TRUST_STORE);
        builder.withReadTimeoutMs(10_000);
        builder.withConnectTimeoutMs(10_000);
        builder.withDebuggingEnabled(true);

        return builder.build();
    }

    private void assertKeyShare(KeyShare keyShare, String shareId) {
        assertNotNull(shareId);

        this.assertShareExistsInDb(shareId, keyShare);
    }

    private void assertThrowsBadRequest(KeyShare keyShare) {
        ApiException ex = assertThrows(
            ApiException.class,
            () -> client.createKeyShare(keyShare, null)
        );
        assertBadRequest(ex.getCode());
    }

    private void assertBadRequest(int responseCode) {
        assertEquals(HttpStatus.BAD_REQUEST.value(), responseCode);
    }

    private void assertShareExistsInDb(String shareId, KeyShare keyShare) {
        var keyShareDb = this.shareRepository.findById(shareId);
        assertTrue(keyShareDb.isPresent());
        var dbCapsule = keyShareDb.get();

        assertEquals(keyShare.getRecipient(), dbCapsule.getRecipient());
        assertArrayEquals(keyShare.getShare(), dbCapsule.getShare());
    }

    private ee.cyber.cdoc2.client.model.KeyShare createKeyShare() {
        return new ee.cyber.cdoc2.client.model.KeyShare()
            .recipient(SHARE_RECIPIENT)
            .share(SHARE);
    }

    /**
     * Saves the key share into database
     *
     * @param dto the key share dto
     * @return the saved key share
     */
    protected KeyShareDb saveKeyShare(ee.cyber.cdoc2.client.model.KeyShare dto) {
        return saveKeyShare(dto, EXPIRY_TIME);
    }

    /**
     * Saves the key share into database with the given expiry time
     *
     * @param dto the key share dto
     * @param expiryTime the expiry time of the key share
     * @return the saved key share
     */
    protected KeyShareDb saveKeyShare(ee.cyber.cdoc2.client.model.KeyShare dto, Instant expiryTime) {
        return this.shareRepository.save(
            new KeyShareDb()
                .setRecipient(dto.getRecipient())
                .setShare(dto.getShare())
                .setExpiryTime(expiryTime)
        );
    }

    private void saveNonceForSessionToken() {
        SessionNonceDb entity = new SessionNonceDb();
        entity.setNonce(Base64.getUrlDecoder().decode(SESSION_NONCE_FOR_TOKEN));
        entity.setCreatedAt(Instant.now());
        this.sessionNonceRepository.save(entity);
    }

    private void assertExpiryTimeStoredInDb(
        org.springframework.http.ResponseEntity<Void> resp,
        Instant expectedExpiry
    ) {
        String path = resp.getHeaders().getLocation().getPath();
        String shareId = path.substring(path.lastIndexOf('/') + 1);

        Optional<KeyShareDb> saved = shareRepository.findById(shareId);
        assertTrue(saved.isPresent());
        assertEquals(
            expectedExpiry.truncatedTo(ChronoUnit.SECONDS),
            saved.get().getExpiryTime().truncatedTo(ChronoUnit.SECONDS)
        );
    }
}
