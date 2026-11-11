# CDOC2 Key Shares Server Administration Guide

This document describes how to configure and run `cdoc2-shares-server`.

## Running

To run without Docker, see [getting-started.md](getting-started.md)

### Running in Docker

Docker images are using `Java 21` as Java base image. To fully use Java 21 improvements
enable virtual threads by adding `spring.threads.virtual.enabled=true` into `application.properties`.

To get better throughput it's recommended to give at least 2 CPUs and 1GB of memory per `server` instance.
2 GB of memory per process is even better (some additional throughput gains).

In nutshell run `cdoc2-shares-server`:

```bash
docker run -v /path/to/config/application.properties:/app/config/application.properties \
    -e SPRING_CONFIG_ADDITIONAL_LOCATION=optional:file:/app/config/application.properties \
    ghcr.io/open-eid/cdoc2-shares-server:latest
```

Sample `application.properties` files are in [shares-server/config](shares-server/config)

For full sample setups using `docker compose` and `docker run` see:
* [cdoc2-gatling-tests/cdoc2-shares-server/setup-load-testing](https://github.com/open-eid/cdoc2-gatling-tests/tree/master/cdoc2-shares-server) for `docker run`
* [cdoc2-java-ref-impl/test/config/shares-server/docker-compose.yml](https://github.com/open-eid/cdoc2-java-ref-impl/tree/v2.0.0/test/config/shares-server) for `docker compose` example


## Database

The cdoc2-shares-server requires a pre-installed PostgreSQL database to store data.

### DB creation

The creation and updating of the database schema is easiest to complete with prebuilt `cdoc2-shares-server-liquibase` 
Docker image:

```bash
docker run --rm \
  --env DB_URL=jdbc:postgresql://cdoc2-shares-psql/cdoc2-shares \
  --env DB_PASSWORD=secret \
  --env DB_USER=postgres \
  ghcr.io/open-eid/cdoc2-shares-server-liquibase:latest
```

More info in [postgres.README.md](postgres.README.md).

Alternatively create/update DB with `mvn liquibase:update`, see [getting_started.md](getting-started.md)
for more info.

### DB configuration

`application.properties`:
```
# Database configuration
spring.datasource.url=jdbc:postgresql://cdoc2-shares-psql/cdoc2-shares
spring.datasource.username=postgres
spring.datasource.password=secret
spring.datasource.driver-class-name=org.postgresql.Driver
```

## TLS setup

Instruction for acquiring production TLS certificates is out of scope for this document, but test
certificates and private keys can be generated as:

### TLS Keystore Creation

The servers require a keystore file to secure HTTP connections using TLS.

The keystore file is created with the `keytool` utility
(included with Java Runtime).

To generate a keystore file `cdoc2server.p12` with password `passwd`, alias `cdoc2-server` and validity of 3650 days:
```
keytool -genkeypair -alias cdoc2-server -keyalg ec -groupname secp384r1 -sigalg SHA512withECDSA -keystore cdoc2server.p12 -storepass passwd -validity 3650
```

### TLS configuration
Server TLS certificates/private keys are configured in `application.properties`:
```
server.ssl.key-store-type=PKCS12
# The path to the keystore containing the certificate
server.ssl.key-store=../keys/cdoc2server.p12
# The password used to generate the certificate
server.ssl.key-store-password=passwd
# The alias mapped to the certificate
server.ssl.key-alias=cdoc2-server

server.ssl.enabled=true
# enable TLSv1.3 only
server.ssl.enabled-protocols=TLSv1.3
```

## Trusted  auth token certificate issuers

When key shares are downloaded, then downloader must provide his/her certificate in `x-cdoc2-auth-x5c`
[HTTP header parameter](https://github.com/open-eid/cdoc2-openapi/blob/55a0b02adae0d8c61f2589a47555a93e4cf31971/cdoc2-key-shares-openapi.yaml#L54C17-L54C33). 
These certificates are only accepted, when they are issued by 
trusted certificate issuers. `x-cdoc2-auth-x5c` trusted issuers are configured through 
`application.properties`:
```
# Enable/disable certificate revocation checking for auth ticket certificates using
# Certificate revocation URL is in certificate AIA extension using OCSP.
# When certificate doesn't have AIA extension and revocation checks are enabled, then authentication
# will fail
cdoc2.auth-x5c.revocation-checks-enabled=false
# Forbid authentication to /key-shares API with sid/mid certificate for signing purpose.
# Certificates are allowed with only digital authentication purpose, not with digital signature.
# Default value is 'true'
cdoc2.auth-x5c.sign-cert-forbidden=true

# https://docs.spring.io/spring-boot/reference/features/ssl.html#features.ssl.pem
# Smart-ID/Mobile-ID certificate trusted issuer
spring.ssl.bundle.jks.trusted-issuers.truststore.location=src/test/resources/trusted-issuers/test_trusted_issuers.jks
spring.ssl.bundle.jks.trusted-issuers.truststore.password=changeit
spring.ssl.bundle.jks.trusted-issuers.truststore.type=jks
```

### Creating auth token certificate trusted issuers truststore

Maintaining trusted certificate issuers is out of scope of this document (depends on other infra),
but for testing purposes [create-truststore_with_certs.sh](shares-server/src/test/resources/trusted-issuers/create-truststore_with_certs.sh)
script generates truststore for auth token issuers.

## Nonce expiry and clean-up

`application.properties`:
```
# nonce validity time in seconds, default 300
cdoc2.nonce.expiration-seconds=300

# Expired share nonce removing job executes every 5 minutes every day
key-share-nonce.expired.clean-up.cron=0 0/5 * * * ?
```

## SSH public key recipients (ruhnu fork, `cdoc2.ruhnu.*`)

Fork features are switched on with one feature flag, off by default:

`application.properties`:
```
# Enable SSH public key recipients, per recipient type expiry and the share release audit log.
# Default false: the server behaves as upstream cdoc2-shares-server.
cdoc2.ruhnu.enabled=false

# Expiry of "ruhnu/pk/" shares, used only while cdoc2.ruhnu.enabled=true.
# Format P(n)DT(n)H(n)M(n)S, both default to 14 days
cdoc2.ruhnu.pk.default-expiration-duration=P14D
cdoc2.ruhnu.pk.max-expiration-duration=P14D
```

**Flag off equals upstream.** With `cdoc2.ruhnu.enabled=false` every request gets the same response status as
from upstream. The key-shares API document no longer makes `x-cdoc2-auth-x5c`, `x-cdoc2-session-token` and
`x-cdoc2-session-x5c` mandatory and allows recipients up to 255 characters, so the server repeats the upstream
checks in code: a missing header gives `400`, and a recipient longer than 32 characters gives `400` on create.
Two changes are not behind the flag: the wider `key_material_share.recipient` column (Liquibase changeset 011)
and the relaxed API document. Both only widen what is accepted.

**With the flag on:**
- Shares can be created for recipients `ruhnu/pk/<base64 OpenSSH public key blob>`. The key must be ECDSA
  P-256 (`ecdsa-sha2-nistp256`) and the blob padded standard base64, otherwise create responds `400`.
  Any other recipient starting with `ruhnu/`, apart from `ruhnu/did/` (see DID recipients below), gets `400`,
  and other recipients are still limited to 32 characters.
- `POST /key-shares/{shareId}/nonce` without both session headers issues a nonce for a `ruhnu/pk/` share
  (`404` if the share does not exist or has expired, `400` for other recipients). Requests with a session
  header are handled as before.
- `GET /key-shares/{shareId}` with an auth token whose `iss` starts with `ruhnu/pk/` is verified with the
  public key in `iss` (JWS `ES256`). No session token, certificate, Smart-ID parameters or RP countersignature
  are needed. The audience, shareId and nonce checks are the same as for Smart-ID/Mobile-ID, and the share is
  released only if `iss` equals the share recipient. Other tokens take the Smart-ID/Mobile-ID path unchanged.
- `ruhnu/pk/` shares get the `cdoc2.ruhnu.pk.*` lifetimes. A client may request a shorter one with
  `x-expiry-time`; a longer one is cut to the maximum. If the default is
  configured longer than the maximum, the maximum is used as the default and the server logs a warning at
  startup. Other recipients keep `key-share.*-expiration-duration`.
- Every successful share release, for all recipient types, is logged at `INFO` to logger
  `ee.cyber.cdoc2.server.audit`: `Key share released: shareId=..., recipient=..., time=...`.
  For `ruhnu/pk/` recipients `recipient` is the key's OpenSSH fingerprint (`ruhnu/pk:SHA256:...`, as shown
  by `ssh-keygen -l` and `ssh-add -l`). Other recipients are logged as `redacted`, so personal identification
  codes of `etsi/` recipients are not written to the log.

Access to a `ruhnu/pk/` share ends when it expires. To revoke earlier, delete the recipient's rows from
`key_material_share` on at least one shares server. Nonces in `key_material_share_nonce` reference their share
(no cascade), so delete those first; otherwise the delete fails while a recent nonce exists:

```sql
-- :r is the recipient, ruhnu/pk/<base64 OpenSSH public key blob>
delete from key_material_share_nonce
 where share_id in (select share_id from key_material_share where recipient = :'r');
delete from key_material_share where recipient = :'r';
```

## DID recipients (ruhnu fork, `cdoc2.ruhnu.did.*`)

A DID recipient is `ruhnu/did/<did:web DID>/hash/<fingerprint>`, for example
`ruhnu/did/did:web:example.org:p:alice/hash/NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs`. The fingerprint is
the SHA-256 of the ECDSA P-256 OpenSSH public key blob in unpadded base64url: the `ssh-keygen -l` value after
`SHA256:` with `+/` replaced by `-_`. A share is released only if the caller signs with that key **and** the
DID document, fetched at that moment, still lists the key. The fingerprint pins the key in the container, so a
compromised DID host can withdraw access but cannot grant it.

DID recipients work only while `cdoc2.ruhnu.enabled=true` and only for DID hosts the operator allows:

`application.properties`:
```
# DID hosts this server stores DID recipient shares for and fetches DID documents from.
# Comma separated, each "host" or "host:port" (port 443 when omitted). Default empty: no DID recipients.
cdoc2.ruhnu.did.allowed-hosts=did.example.org
# Timeouts for fetching a DID document: connect, and overall deadline for connect, headers and body.
# Keep the deadline below the clients' read timeout (cdoc2-cli default 5 s), so that a hanging DID host
# reaches the user as 503 rather than as a client timeout.
cdoc2.ruhnu.did.connect-timeout=PT2S
cdoc2.ruhnu.did.request-timeout=PT3S
```

**Outbound HTTPS.** The server fetches `https://<host>[:<port>]/<path>/did.json` (or `/.well-known/did.json`
for a DID without a path) on every share download, from each allowed host, without a cache and without
following redirects. TLS is validated against the JVM's default trusted CAs; a DID host with a private CA
needs it in the JVM trust store (`-Djavax.net.ssl.trustStore=...`). Standard proxy settings
(`https.proxyHost`, `http.nonProxyHosts`) apply. Documents larger than 64 KiB are refused.

**The allowlist is required against SSRF.** `POST /key-shares` needs no authentication, so without an
allowlist anyone could make the server fetch URLs of their choice. It is checked when a share is created
(`400` for a host not in the list) and again before every fetch (`404`), so removing a host takes effect for
existing shares. IP addresses are never accepted as DID hosts.

**With the flag on and the host allowed:**
- Create checks the identifier (did:web DID, 43 character base64url fingerprint, at most 255 characters) and
  the host, otherwise `400`. Nothing is fetched on create.
- `POST /key-shares/{shareId}/nonce` without session headers issues a nonce for a `ruhnu/did/` share, as for
  `ruhnu/pk/`. The DID is not resolved.
- `GET /key-shares/{shareId}` with an auth token whose `iss` starts with `ruhnu/did/`:
  1. the token is verified without network access: the public key in the JWS `jwk` header must have the
     fingerprint in `iss` and verify the `ES256` signature; audience, shareId and nonce as for other tokens
     (`401`, or `404` for an unknown or expired nonce);
  2. the share must exist, be unexpired and have `iss` as its recipient (`404`);
  3. the DID host must still be allowed (`404`);
  4. the DID document is fetched: `503` if the DID host cannot be reached, times out, fails TLS or answers
     `5xx`/`429`; `404` if the document is missing (any other status, including redirects), is for another
     DID, or does not list the key under `authentication`.
  Only then is the share released and the release logged.
- `503` means "try again": nonces are not consumed, so a client can repeat the same request until the nonce
  expires (`cdoc2.nonce.expiration-seconds`, default 300).
- The audit log line for a `ruhnu/did/` release has the full `ruhnu/did/` identifier as `recipient`. It names
  the DID; review that against your privacy rules if your DIDs contain personal identification codes.
- `ruhnu/did/` shares use the global `key-share.*-expiration-duration` lifetimes (3 years by default, at most
  5 years), not the `cdoc2.ruhnu.pk.*` ones.

**Revoking access.** Remove the key from the DID document's `authentication`, or remove the DID document.
The next share download on every shares server is refused. Deleting rows as for `ruhnu/pk/` also works.

**Long lifetimes and key rotation.** Because DID shares live for years, access ends when someone removes the
key from the DID document, not when the share expires; keep that process in place. A key that is rotated away
must stay listed until the containers encrypted to it have been re-encrypted, or they can no longer be opened:
the container pins the old key's fingerprint.

## Logging

`cdoc2-shares-server` uses following lines to configure logging from `application.properties`:
```
logging.level.root=info
logging.level.ee.cyber.cdoc2=trace
 ```

When running in Docker, then logs can be viewed `docker logs <containerID>` command or 
from file `/var/lib/docker/containers/<container-id>/<container-id>-json.log`.

Internally Spring Boot uses [logback](https://logback.qos.ch/). More advanced logging can be set up
by configuring logback through configuration file. Logback configuration location can be configured
by setting `LOGGING_CONFIG` environment variable or passing `logging.config` as Java system property:

```bash
docker run -v /path/to/config/logback.xml:/app/config/logback.xml \
    -v /path/to/config/application.properties:/app/config/application.properties \
    -e SPRING_CONFIG_ADDITIONAL_LOCATION=optional:file:/app/config/application.properties \
    -e LOGGING_CONFIG=/app/config/logback.xml \
    ghcr.io/open-eid/cdoc2-shares-server:latest
```

Example [logback.xml](src/test/resources/logback.xml)

Example OpenTelemetry-compatible Logback configuration [otel-logback.xml](config/otel-logback.xml)

More info on setting up Spring Boot logging: <https://docs.spring.io/spring-boot/reference/features/logging.html>

## Monitoring and metrics

By default `cdoc2-shares-server` exposes `info`, `health`, `startup` and `prometheus` monitoring endpoints.

NB! Currently, the monitoring endpoints require no authentication. As these endpoints are
running on a separate HTTPS port, the access to the monitoring endpoints must be implemented by network access rules (e.g firewall).
Only `/prometheus` endpoint is authenticated.


### Info endpoint
`curl -k -X GET https://<management_host>:<management_port>/actuator/info`

```json
{
  "build": {
    "artifact": "cdoc2-shares-server",
    "name": "cdoc2-shares-server",
    "time": "2025-02-12T13:54:45.711Z",
    "version": "0.4.1-SNAPSHOT",
    "group": "ee.cyber.cdoc2"
  },
  "system.time": "2025-02-14T09:46:03Z"
}
```

### Health endpoint
`curl -k -X GET https://<management_host>:<management_port>/actuator/health`

```json
{
  "status": "UP",
  "components": {
    "db": {
      "status": "UP",
      "details": {
        "database": "PostgreSQL",
        "validationQuery": "isValid()"
      }
    },
    "livenessState": {
      "status": "UP"
    },
    "readinessState": {
      "status": "UP"
    }
  }
}
```

### Startup endpoint
`curl -k -X GET https://<management_host>:<management_port>/actuator/startup`

```json
{
  "timeline": {
    "startTime": "2025-02-14T09:48:09.832145831Z",
    "events": []
  },
  "springBootVersion": "3.4.1"
}
```

### Metrics - Prometheus endpoint (authentication required)
`curl -k -u <username>:<password> https://<management_host>:<management_port>/actuator/prometheus -X GET`

(username and password are defined in application.properties as `username` and `password` under `management.endpoints.metrics`)

```
# HELP executor_pool_core_threads The core number of threads for the pool
# TYPE executor_pool_core_threads gauge
executor_pool_core_threads{application="shares-server",applications="transfer-service",name="applicationTaskExecutor",} 8.0
# HELP jvm_memory_usage_after_gc_percent The percentage of long-lived heap pool used after the last GC event, in the range [0..1]
# TYPE jvm_memory_usage_after_gc_percent gauge
jvm_memory_usage_after_gc_percent{application="shares-server",applications="transfer-service",area="heap",pool="long-lived",} 0.00239985994123664
# HELP jvm_memory_used_bytes The amount of used memory
# TYPE jvm_memory_used_bytes gauge
jvm_memory_used_bytes{application="shares-server",applications="transfer-service",area="nonheap",id="Compressed Class Space",} 1.0815688E7
...........
# HELP jdbc_connections_active Current number of active connections that have been allocated from the data source.
# TYPE jdbc_connections_active gauge
...........
```

Prometheus endpoint just provides monitoring data, usually its visualized with some other tool, like [Grafana](https://grafana.com/grafana/)

### Tracing

`cdoc2-shares-server` supports distributed tracing using OpenTelemetry Protocol (OTLP) through Spring Boot's
Micrometer integration. To visualize traces, you need to run a compatible trace backend.

#### Configuration
To enable tracing, add the following configuration parameters to `application.properties`:
```
# Tracing configuration
# Probability of requests to sample (1.0 = 100%, 0.1 = 10%)
management.tracing.sampling.probability=1.0

# OTLP endpoint for trace export
# Default endpoint for OpenTelemetry Collector or compatible backends
management.opentelemetry.tracing.export.otlp.endpoint=http://localhost:4318/v1/traces
```

#### Trace Propagation
`cdoc2-shares-server` supports W3C Trace Context propagation, allowing distributed traces to span across
multiple services and components.

To propagate traces, include the `traceparent` header in your HTTP requests:
```
traceparent: 00-<trace-id>-<span-id>-01
```
Format breakdown:
* `00` - Version (currently always "00")
* `<trace-id>` - 32-character hexadecimal trace identifier (16 bytes)
* `<span-id>` - 16-character hexadecimal span identifier (8 bytes)
* `01` - Trace flags (01 = sampled, 00 = not sampled)


### Monitoring/metrics configuration

Configuring metrics is out of scope for this document, official Spring Boot Documentation:
<https://docs.spring.io/spring-boot/reference/actuator/metrics.html#actuator.metrics.supported>

Sample `application.properties`:
```
# https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html#actuator.monitoring
# run management on separate https port
management.server.port=18443
management.server.ssl.enabled=true
management.server.ssl.key-store-type=PKCS12
# The path to the keystore containing the certificate
# See copy-keys-and-certificates in pom.xml
management.server.ssl.key-store=../keys/cdoc2server.p12
# The password used to generate the certificate
management.server.ssl.key-store-password=passwd
# The alias mapped to the certificate
management.server.ssl.key-alias=cdoc2-server

# configure monitoring endpoints
management.endpoints.enabled-by-default=false
management.endpoints.web.discovery.enabled=false
# key values can be hidden when change value to "never" or "when_authorized"
management.endpoint.env.show-values=always
management.endpoint.configprops.show-values=always

# explicitly enable endpoints
management.endpoint.info.enabled=true
management.endpoint.health.enabled=true
management.endpoint.startup.enabled=true
management.endpoint.prometheus.enabled=true
management.endpoint.health.show-details=always
management.endpoint.env.enabled=false

# expose only liveness, readiness and database indicators for /actuator/health endpoint
management.health.defaults.enabled=false
management.health.livenessState.enabled=true
management.health.readinessState.enabled=true
management.health.db.enabled=true

# expose endpoints
management.endpoints.web.exposure.include=info,health,startup,prometheus,env

# Supported metrics
# https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html#actuator.metrics.supported

#enable tomcat.* metrics
server.tomcat.mbeanregistry.enabled=true

# Spring Data Repository Metrics
# https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html#actuator.metrics.supported.spring-data-repository
# spring.data.repository.* metrics
management.metrics.data.repository.autotime.enabled=true

# https://docs.spring.io/spring-boot/docs/2.1.5.RELEASE/reference/htmlsingle/#production-ready-metrics-spring-mvc
# http.server.requests metrics
management.metrics.web.server.auto-time-requests=true

# access security must be implemented at network access rules (firewall)
management.security.enabled=false
endpoints.health.sensitive=false

# credentials for /actuator/prometheus api basic authentication
management.endpoints.metrics.username=username
management.endpoints.metrics.password=password

# Tracing configuration
management.tracing.sampling.probability=1.0
management.opentelemetry.tracing.export.otlp.endpoint=http://localhost:4318/v1/traces
```

[^1]: https://docs.oracle.com/cd/E54932_01/doc.705/e54936/cssg_create_ssl_cert.htm#CSVSG182