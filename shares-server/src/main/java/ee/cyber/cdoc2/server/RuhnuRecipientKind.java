package ee.cyber.cdoc2.server;

import ee.cyber.cdoc2.auth.DidRecipientId;
import ee.cyber.cdoc2.auth.SshPublicKeyParser;


/**
 * Kind of a recipient identifier (stored share recipient or auth token "iss"), decided by its prefix only.
 * Says nothing about whether the identifier is valid.
 */
public enum RuhnuRecipientKind {
    /** "ruhnu/pk/&lt;blob&gt;" SSH public key recipient */
    PK,
    /** "ruhnu/did/&lt;did&gt;/hash/&lt;fingerprint&gt;" DID recipient */
    DID,
    /** any other identifier, for example "etsi/PNOEE-..." */
    NONE;

    /**
     * @param identifier recipient identifier or token issuer, may be null
     * @return kind of the identifier
     */
    public static RuhnuRecipientKind of(String identifier) {
        if (identifier == null) {
            return NONE;
        }
        if (identifier.startsWith(SshPublicKeyParser.RECIPIENT_ID_PREFIX)) {
            return PK;
        }
        if (DidRecipientId.isDidRecipientId(identifier)) {
            return DID;
        }
        return NONE;
    }
}
