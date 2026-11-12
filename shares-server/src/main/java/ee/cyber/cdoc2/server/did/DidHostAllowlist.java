package ee.cyber.cdoc2.server.did;

import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ee.cyber.cdoc2.auth.DidHostPolicy;
import ee.cyber.cdoc2.auth.DidWeb;


/**
 * DID hosts from {@code cdoc2.ruhnu.did.allowed-hosts}. Each entry is "host" or "host:port"; a missing port means
 * 443. Hosts compare case-insensitively, ports exactly. A host may be a wildcard "*.domain", where domain has at
 * least two labels; it matches a host of exactly one DNS label followed by ".domain", as in TLS certificates.
 */
public final class DidHostAllowlist implements DidHostPolicy {

    private static final Pattern ENTRY = Pattern.compile("(\\*\\.)?([A-Za-z0-9.-]+)(?::([0-9]{1,5}))?");
    /** Domain of a wildcard entry: at least two non-empty labels */
    private static final Pattern WILDCARD_DOMAIN = Pattern.compile("[A-Za-z0-9-]+(\\.[A-Za-z0-9-]+)+");
    private static final int MAX_PORT = 65535;

    private final Set<String> hostPorts;
    /** Wildcard entries, as "domain:port" of "*.domain" */
    private final Set<String> wildcardDomainPorts;

    /**
     * @param allowedHosts entries "host", "host:port", "*.domain" or "*.domain:port"
     * @throws IllegalArgumentException if an entry is malformed
     */
    public DidHostAllowlist(List<String> allowedHosts) {
        Set<String> exact = new HashSet<>();
        Set<String> wildcards = new HashSet<>();
        for (String entry : allowedHosts) {
            Matcher matcher = ENTRY.matcher(entry.strip());
            if (!matcher.matches()) {
                throw new IllegalArgumentException("Invalid cdoc2.ruhnu.did.allowed-hosts entry \"" + entry
                    + "\", expected \"host\", \"host:port\", \"*.domain\" or \"*.domain:port\"");
            }
            int port = (matcher.group(3) == null) ? DidWeb.DEFAULT_PORT : Integer.parseInt(matcher.group(3));
            if (port < 1 || port > MAX_PORT) {
                throw new IllegalArgumentException("Invalid port in cdoc2.ruhnu.did.allowed-hosts entry \""
                    + entry + "\"");
            }
            String host = matcher.group(2);
            if (matcher.group(1) == null) {
                exact.add(key(host, port));
            } else if (WILDCARD_DOMAIN.matcher(host).matches()) {
                wildcards.add(key(host, port));
            } else {
                throw new IllegalArgumentException("Invalid wildcard in cdoc2.ruhnu.did.allowed-hosts entry \""
                    + entry + "\", the domain after \"*.\" needs at least two labels");
            }
        }
        this.hostPorts = Set.copyOf(exact);
        this.wildcardDomainPorts = Set.copyOf(wildcards);
    }

    @Override
    public boolean allows(String host, int port) {
        if (host == null) {
            return false;
        }
        if (hostPorts.contains(key(host, port))) {
            return true;
        }
        // a wildcard covers exactly one label: compare the host without its first label
        int firstDot = host.indexOf('.');
        return firstDot > 0 && wildcardDomainPorts.contains(key(host.substring(firstDot + 1), port));
    }

    /**
     * @return true if no host is allowed
     */
    public boolean isEmpty() {
        return hostPorts.isEmpty() && wildcardDomainPorts.isEmpty();
    }

    private static String key(String host, int port) {
        return host.toLowerCase(Locale.ROOT) + ":" + port;
    }
}
