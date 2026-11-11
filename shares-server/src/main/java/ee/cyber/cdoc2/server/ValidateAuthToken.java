package ee.cyber.cdoc2.server;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.time.Instant;
import java.util.Base64;
import java.util.Objects;
import java.util.Optional;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import com.authlete.sd.SDJWT;
import com.nimbusds.jwt.SignedJWT;

import ee.cyber.cdoc2.auth.AuthTokenVerifier;
import ee.cyber.cdoc2.auth.DidAuthTokenVerifier;
import ee.cyber.cdoc2.auth.RpHttpSignatureVerifier;
import ee.cyber.cdoc2.auth.ShareAccessData;
import ee.cyber.cdoc2.auth.SshPkAuthTokenVerifier;
import ee.cyber.cdoc2.auth.SshPkTokenVerificationResponse;
import ee.cyber.cdoc2.auth.TokenVerificationResponse;
import ee.cyber.cdoc2.auth.exception.VerificationException;
import ee.cyber.cdoc2.server.config.AuthCertificateConfigProperties;
import ee.cyber.cdoc2.server.config.NonceConfigProperties;
import ee.cyber.cdoc2.server.config.RpServerConfigProperties;
import ee.cyber.cdoc2.server.config.RpServerJwkConf;
import ee.cyber.cdoc2.server.config.TrustedIssuers;
import ee.cyber.cdoc2.server.model.entity.KeyShareNonceDb;
import ee.cyber.cdoc2.server.model.repository.KeyShareNonceRepository;

@Slf4j
@Component
@RequiredArgsConstructor
public class ValidateAuthToken {
    private final TrustedIssuers trustedIssuers;
    private final AuthCertificateConfigProperties certificateConfig;
    private final RpServerConfigProperties rpServerConfigProperties;
    private final KeyShareNonceRepository shareNonceRepository;
    private final NonceConfigProperties nonceConfigProperties;
    private final RpServerJwkConf rpServerJwkConf;

    /**
     * CSS server receives the compact SD-JWT presentation (<Issuer-signed JWT>~<Disclosure 1>~) and performs following
     * authentication and authorization checks:
     *
     * <ul>
     * <li>Verify that SD-JWT is signed by the key pair, whose public key is included in the certificate, presented
     * in the API method "GET /key-shares/{shareId}" parameter "x-cdoc2-auth-x5c".
     * <li>Verify that certificate is issued by trustworthy CA.
     * <li>Verify that certificate is valid at current point of time and is not revoked.
     * <li>Verify that SD-JWT contains claim aud, which is an array, which contains exactly one JSON string.
     * <li>Parse the aud value from SD-JWT (something like
     *     "https://css.example-org1.ee:443/key-shares/9EE90F2D-D946-4D54-9C3D-F4C68F7FFAE3?nonce=59b314d4815f257694b6")
     *      into components serverBaseURL, key-share and nonce.
     * <li>Verify that serverBaseURL is correct for this CSS server (actual requested URL is extracted from low level
     *     <code>nativeWebRequest</code>).
     * <li>Verify that this CSS server has previously generated a nonce for this key-share and nonce is not expired
     * <li>Verify that recipient_id (etsi/PNOEE-xyz) from the KeySharesCapsule matches with the subject SERIALNUMBER
     *     (PNOEE-xyz) from the X.509 certificate.
     * <li>Verify RFC9421 HTTP signature, if present.
     * </ul>
     * <p>
     * If all checks are positive, then the authentication and access control decision is successful and CSS server can
     * return the capsule.
     *
     * @param shareId                    requested shareId (will be compared to shareId in xAuthToken)
     * @param xAuthToken                 SD-JWT auth token that was generated for requested <code>shareId</code>
     * @param xAuthCert                  X.509 certificate. Certificate subject/SERIALNUMBER must match
     *                                   <code>xAuthToken</code> body "iss" without "etsi/" prefix.
     * @param sidRpv3SignatureParameters additional parameters needed to validate a SID RPv3
     *                                   signature
     * @param httpSignatureParams        components of an RFC9421 HTTP signature. can have null
     *                                   values for SID RPv3-signed auth tokens
     * @param requestUrl                 URL of the endpoint receiving the request for a key share
     * @return a TokenVerificationResponse object containing a nonce URI
     * and the ETSI identifier of the key share recipient
     * @throws VerificationException verification exception with message
     */
    public TokenVerificationResponse execute(
        String shareId,
        String xAuthToken,
        String xAuthCert,
        String sidRpv3SignatureParameters,
        HttpSignatureParams httpSignatureParams,
        URL requestUrl
    ) throws VerificationException {
        AuthTokenVerifier tokenVerifier = new AuthTokenVerifier(
            trustedIssuers.getTrustStore(),
            certificateConfig.revocationChecksEnabled()
        );

        TokenVerificationResponse verificationResponse = tokenVerifier.verify(
            xAuthToken,
            xAuthCert,
            sidRpv3SignatureParameters != null
                ? new AuthTokenVerifier.SidAuthTokenVerificationParams(
                sidRpv3SignatureParameters,
                rpServerConfigProperties.rpName(),
                rpServerConfigProperties.schemeName()
            )
                : null,
            createParamsForHttpSignatureVerification(httpSignatureParams)
        );

        ShareAccessData shareAccessData;
        try {
            shareAccessData = ShareAccessData.fromURL(verificationResponse.nonceUri().toURL());
        } catch (MalformedURLException e) {
            String message = "Unable to parse nonce URI: " + verificationResponse.nonceUri();
            throw new VerificationException(message);
        }

        checkTokenAudience(shareId, shareAccessData, requestUrl);

        return verificationResponse;
    }

    /**
     * Verifies auth token signed by an SSH public key recipient ("ruhnu/pk/" "iss"): JWS signature with the key
     * from "iss", then the same "aud" checks (server URL, shareId, nonce) as {@link #execute}. Caller must
     * check that the returned identifier equals the share recipient.
     *
     * @param shareId    requested shareId (will be compared to shareId in xAuthToken)
     * @param xAuthToken SD-JWT auth token that was generated for requested <code>shareId</code>
     * @param requestUrl URL of the endpoint receiving the request for a key share
     * @return verified "ruhnu/pk/" identifier and nonce URI
     * @throws VerificationException verification exception with message
     */
    public SshPkTokenVerificationResponse executeSshPk(
        String shareId,
        String xAuthToken,
        URL requestUrl
    ) throws VerificationException {
        return checkAudience(shareId, new SshPkAuthTokenVerifier().verify(xAuthToken), requestUrl);
    }

    /**
     * Verifies auth token of a DID recipient ("ruhnu/did/" "iss"): the key in the JWS "jwk" header must match the
     * fingerprint in "iss" and verify the signature, then the same "aud" checks (server URL, shareId, nonce) as
     * {@link #execute}. Does not contact the DID host. Caller must check that the returned identifier equals the
     * share recipient, and then that the DID document still lists the key.
     *
     * @param shareId    requested shareId (will be compared to shareId in xAuthToken)
     * @param xAuthToken SD-JWT auth token that was generated for requested <code>shareId</code>
     * @param requestUrl URL of the endpoint receiving the request for a key share
     * @return verified "ruhnu/did/" identifier and nonce URI
     * @throws VerificationException verification exception with message
     */
    public SshPkTokenVerificationResponse executeDid(
        String shareId,
        String xAuthToken,
        URL requestUrl
    ) throws VerificationException {
        return checkAudience(shareId, new DidAuthTokenVerifier().verify(xAuthToken), requestUrl);
    }

    private SshPkTokenVerificationResponse checkAudience(
        String shareId,
        SshPkTokenVerificationResponse verificationResponse,
        URL requestUrl
    ) throws VerificationException {
        // Anyone can sign a token with a self-generated key, so "aud" is untrusted input here:
        // whatever fails to parse must end as VerificationException (401), not as a runtime exception (500)
        ShareAccessData shareAccessData;
        try {
            shareAccessData = ShareAccessData.fromURL(verificationResponse.nonceUri().toURL());
            Base64.getUrlDecoder().decode(shareAccessData.getNonce());
        } catch (MalformedURLException | RuntimeException e) {
            throw new VerificationException("Unable to parse nonce URI: " + verificationResponse.nonceUri());
        }

        checkTokenAudience(shareId, shareAccessData, requestUrl);

        return verificationResponse;
    }

    /**
     * Unverified read of the auth token "iss" kind: "ruhnu/pk/", "ruhnu/did/" or neither. Used only to choose the
     * verification path; the security decision is the comparison of the verified identity with the share
     * recipient.
     *
     * @param xAuthToken SD-JWT auth token
     * @return kind of the token "iss"; {@link RuhnuRecipientKind#NONE} if the token does not parse
     */
    public static RuhnuRecipientKind ruhnuTokenKind(String xAuthToken) {
        if (xAuthToken == null || xAuthToken.isEmpty()) {
            return RuhnuRecipientKind.NONE;
        }
        try {
            String iss = SignedJWT.parse(SDJWT.parse(xAuthToken).getCredentialJwt())
                .getJWTClaimsSet()
                .getIssuer();
            return RuhnuRecipientKind.of(iss);
        } catch (ParseException | RuntimeException e) {
            return RuhnuRecipientKind.NONE;
        }
    }

    private RpHttpSignatureVerifier.RpHttpSignatureParams createParamsForHttpSignatureVerification(
        HttpSignatureParams httpSignatureParams
    ) {
        if (httpSignatureParams.rpSignedHash == null || httpSignatureParams.rpName == null
            || httpSignatureParams.singingInput == null || httpSignatureParams.signature == null) {
            return null;
        }

        return new RpHttpSignatureVerifier.RpHttpSignatureParams(
            httpSignatureParams.rpSignedHash,
            httpSignatureParams.rpName,
            httpSignatureParams.singingInput,
            httpSignatureParams.signature,
            rpServerJwkConf.getPublicKeys()
        );
    }

    /**
     * Check that token "aud" claim matches url in request
     *
     * @param shareId         shareId from request
     * @param shareAccessData ShareAccessData derived from URL returned by auth token
     *                        verification response
     * @throws VerificationException if token "aud" claim validation has failed
     */
    private void checkTokenAudience(
        String shareId,
        ShareAccessData shareAccessData,
        URL requestUrl
    )
        throws VerificationException {

        Objects.requireNonNull(shareId);

        try {
            URL tokenBaseURL = new URL(shareAccessData.getServerBaseUrl());

            int tokenPort = tokenBaseURL.getPort() == -1
                ? tokenBaseURL.getDefaultPort()
                : tokenBaseURL.getPort();

            // check protocol, host and port
            if ((tokenBaseURL.getHost() == null) || !tokenBaseURL.getHost().equals(requestUrl.getHost())
                || tokenBaseURL.getProtocol() == null || !tokenBaseURL.getProtocol().equals(requestUrl.getProtocol())
                || tokenPort != requestUrl.getPort()
            ) {
                throw new VerificationException("protocol, host or port in token and request don't match ("
                    + shareAccessData.getServerBaseUrl() + "!="
                    + requestUrl + ")");
            }

            if (!shareId.equals(shareAccessData.getShareId())) {
                throw new VerificationException("token and request shareId don't match");
            }

            checkNonceFromDB(shareAccessData.getShareId(), shareAccessData.getNonce());
        } catch (MalformedURLException ex) {
            throw new VerificationException("Error validating \"aud\" data", ex);
        }
    }

    /**
     * Checks that tokenNonce exists in DB and is not older than <code>nonceExpirationSeconds</code>
     *
     * @param tokenShareId shareId extracted from sd-jwt
     * @param tokenNonce   nonce extracted from sd-jwt
     * @throws ResponseStatusException with status NOT_FOUND, when nonce is not found from DB or is expired
     */
    private void checkNonceFromDB(String tokenShareId, String tokenNonce) {
        byte[] nonceBytes = Base64.getUrlDecoder().decode(tokenNonce);
        Optional<KeyShareNonceDb> dbNonceOpt = this.shareNonceRepository
            .findByShareIdAndNonce(tokenShareId, nonceBytes);

        if (dbNonceOpt.isPresent()) {
            KeyShareNonceDb dbNonce = dbNonceOpt.get();
            long nonceExpirationSeconds = nonceConfigProperties.expirationSeconds();
            Instant now = Instant.now();
            long nonceAgeSeconds = now.getEpochSecond() - dbNonce.getCreatedAt().getEpochSecond();
            if (nonceAgeSeconds > nonceExpirationSeconds) {
                log.debug("nonce {} is expired. now({})-nonce.createdAt({})={} > {}", tokenNonce,
                    now, dbNonce.getCreatedAt(), nonceAgeSeconds, nonceExpirationSeconds);
                throw new ResponseStatusException(HttpStatus.NOT_FOUND);
            }
        } else {
            log.info("nonce {} not found for share {}", tokenNonce, tokenShareId);
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
    }

    public record HttpSignatureParams(
        String rpSignedHash,
        String rpName,
        String singingInput,
        String signature
    ) {
    }
}
