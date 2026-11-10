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
 * 443. Hosts compare case-insensitively, ports exactly.
 */
public final class DidHostAllowlist implements DidHostPolicy {

    private static final Pattern ENTRY = Pattern.compile("([A-Za-z0-9.-]+)(?::([0-9]{1,5}))?");
    private static final int MAX_PORT = 65535;

    private final Set<String> hostPorts;

    /**
     * @param allowedHosts entries "host" or "host:port"
     * @throws IllegalArgumentException if an entry is malformed
     */
    public DidHostAllowlist(List<String> allowedHosts) {
        Set<String> parsed = new HashSet<>();
        for (String entry : allowedHosts) {
            Matcher matcher = ENTRY.matcher(entry.strip());
            if (!matcher.matches()) {
                throw new IllegalArgumentException("Invalid cdoc2.ruhnu.did.allowed-hosts entry \"" + entry
                    + "\", expected \"host\" or \"host:port\"");
            }
            int port = (matcher.group(2) == null) ? DidWeb.DEFAULT_PORT : Integer.parseInt(matcher.group(2));
            if (port < 1 || port > MAX_PORT) {
                throw new IllegalArgumentException("Invalid port in cdoc2.ruhnu.did.allowed-hosts entry \""
                    + entry + "\"");
            }
            parsed.add(key(matcher.group(1), port));
        }
        this.hostPorts = Set.copyOf(parsed);
    }

    @Override
    public boolean allows(String host, int port) {
        return host != null && hostPorts.contains(key(host, port));
    }

    /**
     * @return true if no host is allowed
     */
    public boolean isEmpty() {
        return hostPorts.isEmpty();
    }

    private static String key(String host, int port) {
        return host.toLowerCase(Locale.ROOT) + ":" + port;
    }
}
