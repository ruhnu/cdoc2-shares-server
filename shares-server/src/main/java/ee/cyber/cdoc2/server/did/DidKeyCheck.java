package ee.cyber.cdoc2.server.did;

import lombok.extern.slf4j.Slf4j;

import java.util.List;
import java.util.Objects;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import ee.cyber.cdoc2.auth.DidRecipientId;
import ee.cyber.cdoc2.auth.DidResolution;
import ee.cyber.cdoc2.auth.DidWebResolver;


/**
 * Decides whether a "ruhnu/did/" recipient's DID document lists the recipient's key right now. The DID host must
 * be in {@code cdoc2.ruhnu.did.allowed-hosts}; the document is fetched on every call, nothing is cached.
 */
@Slf4j
@Component
public final class DidKeyCheck {

    /** Result of {@link #check(DidRecipientId)} */
    public enum Outcome {
        /** the DID document lists the key */
        LISTED,
        /** the DID document was retrieved but does not list the key */
        NOT_LISTED,
        /** the DID was not found (missing document, document for another DID, redirect, ...) */
        NOT_FOUND,
        /** the DID host could not be reached, timed out, or responded 5xx/429 */
        UNAVAILABLE,
        /** the DID host is not in the allowlist; nothing was fetched */
        HOST_NOT_ALLOWED
    }

    private final DidWebResolver resolver;
    private final DidHostAllowlist allowlist;

    @Autowired
    public DidKeyCheck(DidWebResolver resolver, DidHostAllowlist allowlist) {
        this.resolver = Objects.requireNonNull(resolver);
        this.allowlist = Objects.requireNonNull(allowlist);
    }

    private DidKeyCheck(DidHostAllowlist emptyAllowlist) {
        this.resolver = null;
        this.allowlist = emptyAllowlist;
    }

    /**
     * @return check that allows no DID host and never sends a request, for services built without Spring
     */
    public static DidKeyCheck disabled() {
        return new DidKeyCheck(new DidHostAllowlist(List.of()));
    }

    /**
     * @param recipientId DID recipient
     * @return true if the recipient's DID host and port are in the allowlist
     */
    public boolean isAllowed(DidRecipientId recipientId) {
        return allowlist.allows(recipientId.didWeb().host(), recipientId.didWeb().port());
    }

    /**
     * Resolve the recipient's DID and check that its document lists the recipient's key.
     * @param recipientId DID recipient
     * @return outcome
     */
    public Outcome check(DidRecipientId recipientId) {
        if (resolver == null || !isAllowed(recipientId)) {
            log.warn("DID host of {} is not in cdoc2.ruhnu.did.allowed-hosts", recipientId.did());
            return Outcome.HOST_NOT_ALLOWED;
        }

        DidResolution resolution = resolver.resolve(recipientId.didWeb());
        if (resolution instanceof DidResolution.Unavailable unavailable) {
            log.warn("DID host of {} unavailable: {}", recipientId.did(), unavailable.reason());
            return Outcome.UNAVAILABLE;
        }
        if (resolution instanceof DidResolution.NotFound notFound) {
            log.warn("DID {} not found: {}", recipientId.did(), notFound.reason());
            return Outcome.NOT_FOUND;
        }
        DidResolution.Found found = (DidResolution.Found) resolution;
        if (found.keys().find(recipientId.fingerprint()).isEmpty()) {
            log.warn("DID document of {} does not list key {}", recipientId.did(), recipientId.openSshFingerprint());
            return Outcome.NOT_LISTED;
        }
        return Outcome.LISTED;
    }
}
