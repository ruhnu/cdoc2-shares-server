package ee.cyber.cdoc2.server.api;

import jakarta.annotation.Nullable;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Optional;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.NativeWebRequest;

import com.nimbusds.jose.util.X509CertUtils;

import ee.cyber.cdoc2.auth.TokenVerificationResponse;
import ee.cyber.cdoc2.auth.exception.VerificationException;
import ee.cyber.cdoc2.server.Constants;
import ee.cyber.cdoc2.server.ValidateAuthToken;
import ee.cyber.cdoc2.server.ValidateSessionToken;
import ee.cyber.cdoc2.server.config.AuthCertificateConfigProperties;
import ee.cyber.cdoc2.server.config.KeyShareExpiryConfigProperties;
import ee.cyber.cdoc2.server.generated.api.KeySharesApi;
import ee.cyber.cdoc2.server.generated.api.KeySharesApiController;
import ee.cyber.cdoc2.server.generated.api.KeySharesApiDelegate;
import ee.cyber.cdoc2.server.generated.model.KeyShare;
import ee.cyber.cdoc2.server.generated.model.NonceResponse;
import ee.cyber.cdoc2.server.model.entity.KeyShareDb;
import ee.cyber.cdoc2.server.model.entity.KeyShareNonceDb;
import ee.cyber.cdoc2.server.model.repository.KeyShareNonceRepository;
import ee.cyber.cdoc2.server.model.repository.KeyShareRepository;

import static ee.cyber.cdoc2.server.Utils.createNonceResponse;
import static ee.cyber.cdoc2.server.Utils.getPathAndQueryPart;
import static org.springframework.hateoas.server.mvc.WebMvcLinkBuilder.linkTo;
import static org.springframework.hateoas.server.mvc.WebMvcLinkBuilder.methodOn;


/**
 * Implements API for getting and creating CDOC2 key shares {@link KeySharesApi}
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class KeyShareApiService implements KeySharesApiDelegate {
    private final AuthCertificateConfigProperties certificateConfig;
    private final KeyShareExpiryConfigProperties keyShareExpiryConfig;
    private final NativeWebRequest nativeWebRequest;
    private final KeyShareRepository keyShareRepository;
    private final KeyShareNonceRepository shareNonceRepository;
    private final ValidateSessionToken validateSessionToken;
    private final ValidateAuthToken validateAuthToken;
    private final Clock clock;

    @Override
    public Optional<NativeWebRequest> getRequest() {
        return Optional.of(this.nativeWebRequest);
    }

    @Override
    public ResponseEntity<Void> createKeyShare(
        KeyShare keyShare,
        @Nullable LocalDateTime xExpiryTime
    ) {
        log.trace("createKeyShare(share={} bytes, recipient={} bytes)",
            keyShare.getShare().length, keyShare.getRecipient()
        );

        ExpiryTimeData expiryTimeData = getExpiryTime(xExpiryTime);

        try {
            var saved = this.keyShareRepository.save(
                new KeyShareDb()
                    .setShare(keyShare.getShare())
                    .setRecipient(keyShare.getRecipient())
                    .setExpiryTime(expiryTimeData.xExpiryTime.toInstant())
            );

            log.info("KeyShare(shareId={}) created", saved.getShareId());

            URI created = getResourceLocation(saved.getShareId());

            return ResponseEntity.created(created)
                .header(Constants.X_EXPIRY_TIME_HEADER, DateTimeFormatter.ISO_INSTANT.format(saved.getExpiryTime()))
                .header(Constants.X_EXPIRY_TIME_ADJUSTED, String.valueOf(expiryTimeData.expiryTimeAdjusted))
                .build();
        } catch (Exception e) {
            log.error(
                "Failed to save key share(share={} bytes, recipient={})",
                keyShare.getShare().length,
                keyShare.getRecipient(),
                e
            );
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @Override
    public ResponseEntity<NonceResponse> createNonce(
        String shareId,
        String xSessionToken,
        String xSessionCert,
        Object body
    ) {
        log.trace(
            "createNonce(shareId={},xSessionToken={},xSessionCert={} body={})",
            shareId,
            xSessionToken,
            xSessionCert,
            body
        );

        TokenVerificationResponse verificationResponse;
        try {
            verificationResponse = validateSessionToken.execute(xSessionToken, xSessionCert);
        } catch (VerificationException e) {
            logAuthValidationFailure(e);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED.value()).build();
        }

        Optional<KeyShareDb> keyShareOptional = findUnexpiredShare(shareId);

        if (keyShareOptional.isEmpty()) {
            log.warn("Key share with shareId {} not found", shareId);
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        KeyShareDb keyShare = keyShareOptional.get();

        if (!keyShare.getRecipient().equals(verificationResponse.identifier().toString())) {
            log.warn("Key share with shareId {} doesn't match "
                    + "session token subject",
                shareId);
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }

        try {
            var saved = this.shareNonceRepository.save(
                new KeyShareNonceDb().setShareId(keyShare.getShareId())
            );

            log.info("KeyShareNonce(shareId = {}, nonce = {}) created", shareId, saved.getNonce());

            return ResponseEntity.ok(createNonceResponse(saved.getNonce()));
        } catch (Exception e) {
            log.error(
                "Failed to create key share nonce for share ID {}", shareId, e
            );
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @Override
    @SuppressWarnings("checkstyle:ParameterNumber")
    public ResponseEntity<KeyShare> getKeyShareByShareId(
        String shareId,
        String xAuthToken,
        String xAuthCert,
        String xSessionToken,
        String xSessionCert,
        String xSidRpv3SignatureParameters,
        String xRpSignedHash,
        String xRpName,
        String signatureInput,
        String signature
    ) {
        // openapi generator adds check for @NotNull, but not for isEmpty()
        // X509CertUtils.parseWithException will return null, when cert is empty string ("")
        if (xAuthCert == null || xAuthCert.isEmpty()) {
            log.warn("xAuthCert header missing or empty");
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }

        // empty ("") xAuthToken will eventually fail with IllegalArgumentException (401) when parsing sd-jwt
        // Fail here fast and be consistent with empty xAuthCert
        if (xAuthToken == null || xAuthToken.isEmpty()) {
            log.warn("xAuthToken header missing or empty");
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }

        try {
            validateSessionToken.execute(xSessionToken, xSessionCert);
        } catch (VerificationException e) {
            logAuthValidationFailure(e);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED.value()).build();
        }

        // check xAuthToken
        String tokenRecipient; // "etsi/PNOEE-30303039914"
        try {
            if (certificateConfig.signCertForbidden()) {
                // parseWithException returns null, when cert is empty string ("")
                X509Certificate cert = X509CertUtils.parseWithException(
                    Base64.getUrlDecoder().decode(xAuthCert)
                );
                verifyCertificateUsagePurpose(cert);
            }

            ValidateAuthToken.HttpSignatureParams httpSignatureParams =
                new ValidateAuthToken.HttpSignatureParams(
                    xRpSignedHash,
                    xRpName,
                    signatureInput,
                    signature
                );

            TokenVerificationResponse verificationResponse = validateAuthToken.execute(
                shareId,
                xAuthToken,
                xAuthCert,
                xSidRpv3SignatureParameters,
                httpSignatureParams,
                extractRequestURL(this.nativeWebRequest)
            );

            tokenRecipient = verificationResponse.identifier().toString();
        } catch (CertificateException | VerificationException | MalformedURLException ex) {
            logAuthValidationFailure(ex);
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }

        Optional<KeyShareDb> shareDbOpt = findUnexpiredShare(shareId);
        if (shareDbOpt.isEmpty()) {
            log.warn("Key share with shareId {} not found", shareId);
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }

        KeyShareDb shareDb = shareDbOpt.get();
        //check that keyShare can be accessed by auth token issuer
        if (!tokenRecipient.equals(shareDb.getRecipient())) {
            log.warn("Key share with shareId {} doesn't match token issuer", shareId);
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }

        return ResponseEntity.ok()
            .header(
                Constants.X_EXPIRY_TIME_HEADER,
                DateTimeFormatter.ISO_INSTANT.format(shareDb.getExpiryTime())
            )
            .body(createKeyShare(shareDb));
    }

    /**
     * Find a key share that has not expired yet. A share whose expiry time has passed is treated
     * as not found, even if the clean-up job has not deleted it yet.
     *
     * @param shareId share id
     * @return the key share, or empty if it does not exist or has expired
     */
    private Optional<KeyShareDb> findUnexpiredShare(String shareId) {
        Instant now = Instant.now(this.clock);
        return this.keyShareRepository.findById(shareId)
            .filter(share -> now.isBefore(share.getExpiryTime()));
    }

    private static void logAuthValidationFailure(Exception ex) {
        log.warn("Auth validation has failed: {}", ex.getMessage());
    }

    private ExpiryTimeData getExpiryTime(LocalDateTime xExpiryTime) {
        OffsetDateTime xMaxExpiryTime = getCapsuleExpirationTime(
            keyShareExpiryConfig.maxExpirationDuration()
        );

        if (null != xExpiryTime) {
            if (toOffsetDateTime(xExpiryTime).isAfter(xMaxExpiryTime)) {
                return new ExpiryTimeData(xMaxExpiryTime, true);
            }

            return new ExpiryTimeData(toOffsetDateTime(xExpiryTime), false);
        } else {
            return new ExpiryTimeData(
                getCapsuleExpirationTime(keyShareExpiryConfig.defaultExpirationDuration()),
                false
            );
        }
    }

    private static OffsetDateTime getCapsuleExpirationTime(String duration) {
        Duration expiryDuration = Duration.parse(duration);

        return OffsetDateTime.now()
            .toInstant()
            .atZone(ZoneOffset.UTC)
            .plus(expiryDuration)
            .toOffsetDateTime();
    }

    private OffsetDateTime toOffsetDateTime(LocalDateTime expiryTime) {
        return OffsetDateTime.of(expiryTime, ZoneOffset.UTC);
    }

    private static KeyShare createKeyShare(KeyShareDb share) {
        var response = new KeyShare();
        response.setRecipient(share.getRecipient());
        response.setShare(share.getShare());

        return response;
    }

    /**
     * Get URI for getting Key Share resource (Location).
     *
     * @param id Share id example: KC9b7036de0c9fce889850c4bbb1e23482
     * @return URI (path and query) example: /key-shares/KC9b7036de0c9fce889850c4bbb1e23482
     * @throws URISyntaxException in case of URI syntax error
     */
    private static URI getResourceLocation(String id) throws URISyntaxException {
        return getPathAndQueryPart(
            linkTo(methodOn(
                KeySharesApiController.class
                // xAuthtoken and xAuthCertificate are not part of url as these are header params
            ).getKeyShareByShareId(id, "", "", "", "", "",
                null, null, null, null)).toUri()
        );
    }

    private static URL extractRequestURL(NativeWebRequest nativeWebRequest) throws MalformedURLException {
        if (nativeWebRequest == null) {
            throw new IllegalArgumentException("nativeRequest not initialized"); // http 500, should not happen normally
        }

        HttpServletRequest req = nativeWebRequest.getNativeRequest(HttpServletRequest.class);

        if (req != null) {
            //when running behind proxy, then "X-Forwarded-*" headers should be set
            String forwardedScheme = req.getHeader("X-Forwarded-Proto");
            String forwardedHost = req.getHeader("X-Forwarded-Host");
            String forwardedPort = req.getHeader("X-Forwarded-Port");

            String scheme = (forwardedScheme != null) ? forwardedScheme : req.getScheme(); //https
            String hostname = (forwardedHost != null) ? forwardedHost : req.getServerName();
            String port = (forwardedPort != null) ? forwardedPort : String.valueOf(req.getServerPort());

            String path = req.getRequestURI(); //without query params
            //String params = req.getQueryString(); // Query parameters, if any

            String url = scheme + "://" + hostname
                + ":" + port // port should be explicitly be part of url even for port 80/443
                + path;
            //+ ((params == null) ? "": "?" + params)

            log.debug("Request url {}", url);
            return new URL(url);
        } else {
            log.error("Failed to convert nativeWebRequest to HttpServletRequest");
        }

        throw new MalformedURLException("Failed to extract request URL");
    }

    /**
     * Checks user certificate purpose and verifies that signing certificate is not used for
     * authentication.
     *
     * @param cert certificate to check. {@link KeyUsage#nonRepudiation} value of keyUsage means
     *             that certificate has a signing purpose. Authentication purpose keyUsage would be
     *             {@link KeyUsage#digitalSignature} or {@link KeyUsage#keyEncipherment} or
     *             {@link KeyUsage#dataEncipherment}.
     * @throws VerificationException if certificate is not valid for authentication or its purpose
     *                               extraction has failed
     */
    private void verifyCertificateUsagePurpose(X509Certificate cert) throws VerificationException {
        boolean[] keyUsages = cert.getKeyUsage();
        if (null == keyUsages) {
            throw new VerificationException(
                "Required extension keyUsage for certificate purpose is missing"
            );
        }
        final int signingCertBits = KeyUsage.nonRepudiation;
        try {
            Certificate bcCert = Certificate.getInstance(ASN1Primitive.fromByteArray(cert.getEncoded()));
            X509CertificateHolder bcX509Cert = new X509CertificateHolder(bcCert);
            boolean isSigningCert =
                KeyUsage.fromExtensions(bcX509Cert.getExtensions()).hasUsages(signingCertBits);
            if (isSigningCert) {
                throw new VerificationException("Signing certificate cannot be used for authentication");
            }
        } catch (CertificateEncodingException | IOException ex) {
            throw new VerificationException("Failed to check certificate usage purpose", ex);
        }
    }

    private record ExpiryTimeData(
        OffsetDateTime xExpiryTime,
        boolean expiryTimeAdjusted
    ) {
    }
}
