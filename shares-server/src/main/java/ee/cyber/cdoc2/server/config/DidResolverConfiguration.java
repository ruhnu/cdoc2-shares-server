package ee.cyber.cdoc2.server.config;

import java.net.http.HttpClient;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import ee.cyber.cdoc2.auth.DidWebResolver;
import ee.cyber.cdoc2.server.did.DidHostAllowlist;


/**
 * DID resolution for "ruhnu/did/" recipients. The HTTP client is a separate bean, so that tests can replace it
 * with one that trusts a test DID host.
 */
@Configuration
public class DidResolverConfiguration {

    /** Name of the HTTP client bean used for fetching DID documents */
    public static final String DID_HTTP_CLIENT = "didHttpClient";

    /**
     * @param ruhnuConfig fork configuration
     * @return HTTP client for DID documents: no redirects, default proxy selector and trusted CAs
     */
    @Bean(DID_HTTP_CLIENT)
    HttpClient didHttpClient(RuhnuConfigProperties ruhnuConfig) {
        return DidWebResolver.createHttpClient(ruhnuConfig.did().connectTimeout());
    }

    /**
     * @param ruhnuConfig fork configuration
     * @return allowed DID hosts
     */
    @Bean
    DidHostAllowlist didHostAllowlist(RuhnuConfigProperties ruhnuConfig) {
        return new DidHostAllowlist(ruhnuConfig.did().allowedHosts());
    }

    /**
     * @param httpClient  HTTP client for DID documents
     * @param ruhnuConfig fork configuration
     * @param allowlist   allowed DID hosts, also enforced by the resolver before any request
     * @return DID resolver
     */
    @Bean
    DidWebResolver didWebResolver(
        @Qualifier(DID_HTTP_CLIENT) HttpClient httpClient,
        RuhnuConfigProperties ruhnuConfig,
        DidHostAllowlist allowlist
    ) {
        return new DidWebResolver(httpClient, ruhnuConfig.did().requestTimeout(),
            DidWebResolver.DEFAULT_MAX_DOCUMENT_BYTES, allowlist);
    }
}
