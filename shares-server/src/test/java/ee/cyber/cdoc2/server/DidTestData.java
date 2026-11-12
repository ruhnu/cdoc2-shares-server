package ee.cyber.cdoc2.server;

import java.net.http.HttpClient;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.time.Duration;
import java.util.StringJoiner;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;

import ee.cyber.cdoc2.auth.AuthTokenCreator;
import ee.cyber.cdoc2.auth.DidRecipientId;
import ee.cyber.cdoc2.auth.ShareAccessData;
import ee.cyber.cdoc2.auth.SshPublicKeyParser;
import ee.cyber.cdoc2.server.SshPkTestData.SshKey;

import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;


/**
 * Test helpers for "ruhnu/did/" DID recipients
 */
public final class DidTestData {

    private DidTestData() {
    }

    /**
     * @param did did:web DID
     * @param key P-256 key
     * @return "ruhnu/did/&lt;did&gt;/hash/&lt;fingerprint&gt;" identifier of the key
     */
    public static String didRecipientId(String did, SshKey key) {
        return DidRecipientId.of(did, SshPublicKeyParser.blobFromRecipientId(key.recipientId())).toString();
    }

    /**
     * DID document whose "authentication" lists the keys (P-256 publicKeyJwk, controller = did)
     * @param id   document "id"
     * @param keys keys to list
     * @return DID document JSON
     */
    public static String didDocument(String id, SshKey... keys) {
        StringJoiner methods = new StringJoiner(",");
        StringJoiner refs = new StringJoiner(",");
        for (int i = 0; i < keys.length; i++) {
            methods.add("{\"id\":\"" + id + "#key-" + i + "\",\"type\":\"JsonWebKey2020\",\"controller\":\"" + id
                + "\",\"publicKeyJwk\":" + publicJwk((ECPublicKey) keys[i].keyPair().getPublic()).toJSONString()
                + "}");
            refs.add("\"#key-" + i + "\"");
        }
        return "{\"@context\":[\"https://www.w3.org/ns/did/v1\"],\"id\":\"" + id + "\",\"verificationMethod\":["
            + methods + "],\"authentication\":[" + refs + "]}";
    }

    /**
     * Auth token for one share of a DID recipient
     * @param issuer     token "iss"
     * @param signingKey key that signs the token
     * @param headerKey  public key put into the JWS "jwk" header, null for no "jwk" header
     */
    public static String createDidAuthToken(
        String issuer, KeyPair signingKey, ECPublicKey headerKey, String serverBaseUrl, String shareId, String nonce
    ) {
        try {
            AuthTokenCreator.Builder builder = AuthTokenCreator.builder()
                .withIssuer(issuer)
                .withShareAccessData(new ShareAccessData(serverBaseUrl, shareId, nonce));
            if (headerKey != null) {
                builder.withHeaderJwk(publicJwk(headerKey));
            }
            AuthTokenCreator creator = builder.build();
            creator.sign(new ECDSASigner((ECPrivateKey) signingKey.getPrivate()));
            return creator.createToken(0);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Start an HTTPS DID host stub on a free port, with the test server certificate ("localhost"), which
     * {@link BaseInitializationTest#CLIENT_TRUST_STORE} trusts.
     */
    public static WireMockServer startDidHost() {
        WireMockServer server = new WireMockServer(wireMockConfig()
            .httpDisabled(true)
            .dynamicHttpsPort()
            .keystorePath(TestData.getKeysDirectory().resolve("cdoc2server.p12").toString())
            .keystoreType("PKCS12")
            .keystorePassword("passwd")
            .keyManagerPassword("passwd"));
        server.start();
        return server;
    }

    /**
     * HTTP client for DID resolution that trusts the DID host stub, to replace the "didHttpClient" bean
     */
    public static HttpClient didHttpClientTrustingTestCerts() {
        try {
            HttpClient trusting = RuhnuApiTestBase.createHttpClient();
            return HttpClient.newBuilder()
                .sslContext(trusting.sslContext())
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(1))
                .build();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static ECKey publicJwk(ECPublicKey key) {
        return new ECKey.Builder(Curve.forECParameterSpec(key.getParams()), key).build();
    }
}
