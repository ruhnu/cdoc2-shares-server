# Changelog

## [Unreleased]

### Features
* SSH public key recipients (`ruhnu/pk/<base64 OpenSSH public key blob>`, ECDSA P-256) behind feature
  flag `cdoc2.ruhnu.enabled` (default `false`, upstream behaviour). With the flag on: nonce without
  session token for `ruhnu/pk/` shares, auth tokens verified with the public key in `iss`, per
  recipient type expiry (`cdoc2.ruhnu.pk.*`, default 14 days, the default never exceeds the maximum)
  and a share release audit log.
  See admin-guide.md.
* DID recipients (`ruhnu/did/<did:web DID>/hash/<fingerprint>`, ECDSA P-256 key pinned by its SHA-256
  fingerprint) behind feature flag `cdoc2.ruhnu.enabled`, only for DID hosts in
  `cdoc2.ruhnu.did.allowed-hosts` (default none; `host`, `host:port` or wildcard `*.domain`, matching one
  DNS label; checked on create, `400`, and before every fetch, `404`).
  Get-share verifies the auth token against the key in its `jwk` header, then fetches the DID document on
  every request (`cdoc2.ruhnu.did.connect-timeout`, overall deadline `cdoc2.ruhnu.did.request-timeout`,
  default PT3S): `503` if the DID host is unavailable, `404` if the document no longer lists the key. The
  release audit log names the `ruhnu/did/` recipient. DID shares use the global `key-share.*` lifetimes.
  Key-shares API 1.5.0-draft, cdoc2-auth-token 0.9.0-SNAPSHOT. See admin-guide.md.
* `spring.jpa.open-in-view` now defaults to `false`, so that no database connection is held for the whole
  request (for example while a DID document is fetched).
* `key_material_share.recipient` widened to 255 characters; key-shares API 1.4.0-draft makes the
  session and auth certificate headers optional in the API document, the server still requires them
  for Smart-ID/Mobile-ID requests.

### Bug fixes
* Expired key shares are no longer served. The nonce (`POST /key-shares/{shareId}/nonce`) and
  get-share (`GET /key-shares/{shareId}`) endpoints now respond 404 Not Found as soon as a share's
  expiry time has passed, instead of serving it until the scheduled clean-up job deletes it.
  Authentication is still checked first, so the response is the same as for a deleted share.

## [0.8.4]

### Improvements
* Fixed issue with certain configuration keys always binding to default values. The affected keys:
  * `cdoc2.auth-x5c.revocation-checks-enabled`
  * `cdoc2.auth-x5c.sign-cert-forbidden`
  * `cdoc2.rp-server.rp-name`
  * `cdoc2.rp-server.scheme-name`
  * `key-share.default-expiration-duration`
  * `key-share.max-expiration-duration`
  * `cdoc2.nonce.expiration-seconds`

## [0.8.3]

### Improvements
* Upgrade to Java 21

## [0.8.2]

### Improvements
* TLS_1.3 no longer forced for infrastructure connections
* logging and tracing improvements

## [0.8.1]

### Improvements
* added `logstash-logback-encoder` dependency to enable JSON logging
* Added logging for previously unlogged exception handling paths (failed auth/session token
  validation, JWK fetch failures) and a catch-all exception handler for unexpected errors
* Add support for tracing (`micrometer-tracing-bridge-otel`, `opentelemetry-exporter-otlp`,
  `spring-boot-micrometer-tracing`, `spring-boot-micrometer-tracing-opentelemetry`)
* Dependency updates

## [0.8.0]

### Improvements
* Updated cdoc2-client version
* Updated cdoc2-auth-token version
* Code refinements and test coverage

## [0.7.3]

### Improvements
* Updated dependencies to latest stable versions
* Migrated code for breaking API changes in Spring Boot `AntPathRequestMatcher` -> `PathPatternRequestMatcher`

## [0.7.2]

### Improvements
* Additional unit tests

## [0.7.1]

### Improvements
* Use CycloneDX Maven plugin for SBOM creation

## [0.7.0]

### Features:

* Added optional `x-expiry-time` header to `POST` `/key-shares` request. If omitted, key share 
  expiry will be determined by a server-configured default value.
* Added optional `x-expiry-time`, `x-expiry-time-adjusted` headers to `POST` `/key-shares` 
  response. `x-expiry-time` in response is the actual applied expiry time, which may differ from 
  the requested time if the requested time exceeds the servers configured maximum allowable key 
  share expiration time. If the server adjusted the expiry time, `x-expiry-time-adjusted` will 
  be set to `true`.
* Added `x-expiry-time` header to `GET` `/key-shares/{shareId}` response.
* Added `/info` endpoint.

## [0.6.0]  SID/MID authentication/security improvements

### Features:
* Create job for expired session nonce removal
* RFC9421 HTTP signature validation for /key-share/{shareId} endpoint

### Improvements
* Upgraded Spring Boot 4.0.3 -> 4.0.6

## [0.5.0]  SID/MID authentication/security improvements

### Features:
* Create new `/session_nonce` endpoint
* Use [cdoc2-auth-token:0.5.0-SNAPSHOT]
* Auth token verification accepts SID RPv3 token signatures
* header `x-cdoc2-auth-ticket` renamed to `x-cdoc2-auth-token`
* header `x-cdoc2-auth-x5c` changed to expect a Base64Url-encoded DER certificate
* new headers `x-cdoc2-session-token`, `x-cdoc2-session-x5c` applied to endpoints 
 `GET /key-shares/{shareId}`, `POST /key-shares/{shareId}/nonce`
* new header `x-cdoc2-sid-rpv3-signature-parameters` applied to endpoint `/key-shares/{shareId}`.
  Used when `x-cdoc2-auth-token` is signed with SID RPv3

## [0.4.3]  Handle empty "" GET /key-shares header parameters better. (2025-03-26)

### Improvements:
* Handle empty ("") "x-cdoc2-auth-x5c" and "x-cdoc2-auth-ticket" header parameters better (no long stacktrace in log), return HTTP 400
* Spring Boot 3.4.1 -> 3.4.3 + other dependency updates
* Upgrade dependency `ee.cyber.cdoc2.openapi:cdoc2-key-shares-openapi` `1.0.1-draft` -> `1.0.1` (no changes besides version)

### Maven package versions:
```
cdoc2-shares-server 0.4.3
cdoc2-shares-server-pom 0.2.1
cdoc2-css-db 0.1.3
cdoc2-css-openapi 0.1.2
```

## [0.4.2] Bug fix for config property initialization (2025-02-27)

### Internal

* Bug fix for config property initialization inside `KeyShareApiService` and unit tests.

### Maven package versions:
```
cdoc2-shares-server-pom 0.2.0
cdoc2-shares-server 0.4.2
cdoc2-css-db 0.1.2
cdoc2-css-openapi 0.1.1
```

## [0.4.2-SNAPSHOT] Added index on `key_material_share_nonce` table

### Improvements:
* Added index on `key_material_share_nonce` table columns to increase query performance

## [0.4.1-SNAPSHOT] Support for JWT tokens signed with Mobile-ID (ES256)

### Features:
* Use [cdoc2-auth-token:0.3.3-SNAPSHOT](https://github.com/open-eid/cdoc2-auth) that adds support 
  for ES256 (Mobile-ID)

### Improvements:
* Certificates updates + added script that downloads and creates truststore
* Spring Boot 3.3.3 -> 3.4.1 + other dependency updates
* Tag `cdoc2-shares-server-liquibase` with `latest` when built using `build-image.sh` script  

## [0.3.0-SNAPSHOT] First public release 

* use [auth-token:0.2.0-SNAPSHOT](https://github.com/open-eid/cdoc2-auth) (SDJWT.body: `"aud":"https://server:port/key-shares/{shareID}?nonce={nonce}"`)
  - Fix Disclosure decoding (previously Disclosure were incorrectly decoded even when digest didn't match )
  - Use `"aud"` list of `{server}/key-shares/{shareID}?nonce={nonce}` URLs instead of custom `shareAccessData` json object.
  - remove `"kid"` from JWT header (duplicate of "iss" in JWT body)
  - remove `"iat"` and `"exp"` claims. Nonce creation time is checked by `cdoc2-shares-server`
  - Move x5c certificate issuer check into cdoc2-auth-token module (from `cdoc2-shares-server`) 
