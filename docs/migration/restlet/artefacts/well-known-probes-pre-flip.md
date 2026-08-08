<!--
  D2 oracle capture for /.well-known, phase 5d-2a-i (checklist step 2, criterion 5).
  Recorded 2026-08-06. This measurement cannot be re-derived: 5d-2a-ii deletes the endpoint it measures.
  Per INDEX.md "the oracle record": never delete a measured value from this file.
-->

# `/.well-known` oracle capture — pre-flip (Restlet incumbent)

**Recorded** 2026-08-06 against the running `openam-idp` container, image `openam-e2e:soakfix`.

**Provenance.** The image was built from the soak-fix tree; `git diff --name-only 83f465452b..HEAD` is
docs-only, and the deployed jar was checksummed against the local build:

```
9caa6801bd211079351bc3d95ad43a97  openam-idp:/usr/local/tomcat/webapps/openam/WEB-INF/lib/openam-oauth2-16.2.0-SNAPSHOT.jar
9caa6801bd211079351bc3d95ad43a97  openam-oauth2/target/openam-oauth2-16.2.0-SNAPSHOT.jar
```

CI run `31105613611` on `83f465452b` was green (all 10 jobs) when this was taken.

---

## ⚠ What this measurement refutes

**[D2](../phase-5d-2.md#d2)'s central correction is wrong. The endpoint *is* wholly broken, and
`webfinger-test.spec.mjs`'s header comment was right.**

D2 predicted that only the success path 500s, and that a missing `resource`, a missing/wrong `rel` and an
unknown user each return "a live, working" 400/404 — four **parity targets** that criterion 8 would require
byte-identical after the flip. The measurement shows **all four return the same generic 500 as the success
path**, byte for byte (md5 `dd82fa5d59a42118454371b094ddfa6a`, 149 bytes).

The reason D2's reasoning failed is one line of ordering in `OpenIDConnectDiscovery:79-83`:

```java
final String deploymentUrl =
        baseUrlProviderFactory.get(realm).getRootURL(ServletUtils.getRequest(getRequest()));   // NPEs here
final Map<String, Object> response = providerDiscovery.discover(resource, rel, deploymentUrl, request);
```

`getRootURL(null)` throws **before** `discover(...)` is ever called, so the `BadRequestException` /
`NotFoundException` that `discover(...)` would have raised are unreachable. D2's `doCatch` analysis is
correct as far as it goes — the two-arg `ExceptionHandler.handle` overload does render the exception's own
`asMap()` — but the exception that arrives is a **`NullPointerException`**, not an `OAuth2Exception`, so it
renders as the generic 500. The validation contract D2 wanted to preserve has never once executed in this
deployment.

**Consequences** (carried into the spec):

1. **There are no parity targets.** Criterion 8's premise is void — nothing under `/.well-known/*` currently
   returns a value worth reproducing.
2. **Divergence row 33 widens** from "success path only" to *every routed request*.
3. **Row 34's incumbent is a 500, not `OAuth2StatusService`'s 404** — except for the two bare-segment
   spellings below, which do reach the status service.
4. **R-5d2.4 is discharged by measurement.** Nothing but 500s is served from the segment; in particular
   `/.well-known/openid-configuration` at the **context root** 500s (probe 15) — the real discovery document
   is `/oauth2/.well-known/openid-configuration` (probe 16, 200, already CHF-served).

## The whole segment in five bodies

| Answer | Probes | Meaning |
|---|---|---|
| **500** JSON, 149 B, md5 `dd82fa5d…` | 01–07, 09, 11, 12, 14, 15, 18, 19 | every path under `/.well-known/` that carries at least one path element, GET or POST, any parameters — the NPE |
| **500** `text/html`, 717 B | 13 (`HEAD`) | Restlet's HTML status page, **not** the JSON one — a third shape, reached only by `HEAD` |
| **404** JSON, 102 B, md5 `1b2c72cf…` | 10, 17 | `/.well-known` and `/.well-known/` — the only paths that reach `OAuth2StatusService` |
| **404** JSON, 70 B, md5 `2c54883f…` | 08 | `?realm=` that does not resolve — `RestletRealmRouter` rejects before dispatch |
| **200** JSON, 1515 B, md5 `74c2c745…` | 16 | control, `/oauth2/.well-known/openid-configuration`, unaffected by this phase |

⚠ **Routing note.** `/.well-known/nonsense`, `/.well-known/a/b/c` and `/.well-known/webfinger/extra` all
reach `OpenIDConnectDiscovery` rather than 404-ing (probes 09, 18, 19). The single `attach("/webfinger", …)`
on `WebFinger:71` matches far more than its literal path. After the port, `EQUALS "webfinger"` under
`STARTS_WITH ".well-known"` is strict, so all three become `OAuth2NotFoundHandler` 404s — a **narrowing**,
and one more reason row 34 needs rewriting.

## Post-flip expectations set by this capture

| Probe | Incumbent | Expected after 5d-2a-ii | Classification |
|---|---|---|---|
| 01, 02 | 500 | 200 JRD | row 33 (the fix) |
| 03, 04, 05, 07 | 500 | 400 `{"error":"bad_request",…}` from `discover(...)` | row 33 — **not** a parity target |
| 06 | 500 | 404 `{"error":"not_found",…}` | row 33 — **not** a parity target |
| 08 | 404 `Realm "/bogus" not found` | 400 `{"error":…}` via `RealmContextFilter` + `OAuth2ErrorFilter` | **new row** — status moves 404→400 |
| 09, 12, 18, 19 | 500 | 404 `{"error":"not_found","error_description":"Not Found"}` | row 34, widened |
| 11 | 500 | ⚠ **prediction corrected 2026-08-08 — 200 JRD**, see the note below | **row 33**, not row 34 |
| 10, 17 | 404 `OAuth2StatusService` | 404 `OAuth2NotFoundHandler` | row 34 as written |
| 13 (`HEAD`) | 500 `text/html`, 717 B | as row 01 (`Endpoints:70-72` maps HEAD→GET), no body | row 33 |
| 14 (`POST`) | 500 | 405 with `Allow` | **new row** — no `@Post` on the handler |
| 15 | 500 | 404 `OAuth2NotFoundHandler` | row 34 |
| 16 | 200 | 200, unchanged | control — must not move |

⚠ **One row of this table was a wrong prediction, and the flip corrected it — 2026-08-08, per
[the oracle rule](../INDEX.md#the-oracle-record).** Probe 11,
`/.well-known/realms/root/webfinger`, was grouped with the no-match probes on the assumption that the
`/realms/{realm}` spelling would not resolve under the ported route. It does: the flip measured **200 with the
same JRD as probes 01 and 02** (152 B, md5 `2df598686034f3c5ecae01102e6a3c39`) — which is what
`WellKnownRouterIT.theRealmsPathStyleReachesTheEndpoint` and
[research §10](../phase-5d-2-research.md#10) had said all along, and what
[D1](../phase-5d-2.md#d1) predicted when it noted the `/realms/{realm}` form comes "for free". So probe 11 is
**row 33**, not row 34.

**Only the expectation changed.** Every *measured* value in this file — statuses, headers, byte counts, md5s,
including probe 11's own 500 above and below — is the Restlet oracle, is not re-derivable, and is untouched.
The post-flip measurement is
[`well-known-probes-post-flip.md`](well-known-probes-post-flip.md#11--realmsrealm-path-spelling); the
classification is recorded in
[phase-5d-2-asbuilt.md](../phase-5d-2-asbuilt.md#criterion-8--where-the-nineteen-probes-landed).

---

## Raw probes


### 01 — success: issuer lookup, explicit realm=/ (the e2e spec's row)

```
GET /.well-known/webfinger?resource=acct%3ademo%40example.com&rel=http%3a%2f%2fopenid.net%2fspecs%2fconnect%2f1.0%2fissuer&realm=%2f
```

**Status + headers**

```http
HTTP/1.1 500 
X-Frame-Options: SAMEORIGIN
Date: Thu, 06 Aug 2026 15:19:44 GMT
Server: Restlet-Framework/2.4.4
Content-Type: application/json;charset=UTF-8
Transfer-Encoding: chunked
Connection: close

```

**Body** — 149 bytes, md5 `dd82fa5d59a42118454371b094ddfa6a`

```
{"error":"Internal Server Error","error_description":"The server encountered an unexpected condition which prevented it from fulfilling the request"}
```

### 02 — success: issuer lookup, no realm parameter

```
GET /.well-known/webfinger?resource=acct%3ademo%40example.com&rel=http%3a%2f%2fopenid.net%2fspecs%2fconnect%2f1.0%2fissuer
```

**Status + headers**

```http
HTTP/1.1 500 
X-Frame-Options: SAMEORIGIN
Date: Thu, 06 Aug 2026 15:19:44 GMT
Server: Restlet-Framework/2.4.4
Content-Type: application/json;charset=UTF-8
Transfer-Encoding: chunked
Connection: close

```

**Body** — 149 bytes, md5 `dd82fa5d59a42118454371b094ddfa6a`

```
{"error":"Internal Server Error","error_description":"The server encountered an unexpected condition which prevented it from fulfilling the request"}
```

### 03 — missing resource (rel only)

```
GET /.well-known/webfinger?rel=http%3a%2f%2fopenid.net%2fspecs%2fconnect%2f1.0%2fissuer
```

**Status + headers**

```http
HTTP/1.1 500 
X-Frame-Options: SAMEORIGIN
Date: Thu, 06 Aug 2026 15:19:44 GMT
Server: Restlet-Framework/2.4.4
Content-Type: application/json;charset=UTF-8
Transfer-Encoding: chunked
Connection: close

```

**Body** — 149 bytes, md5 `dd82fa5d59a42118454371b094ddfa6a`

```
{"error":"Internal Server Error","error_description":"The server encountered an unexpected condition which prevented it from fulfilling the request"}
```

### 04 — missing rel (resource only)

```
GET /.well-known/webfinger?resource=acct%3ademo%40example.com
```

**Status + headers**

```http
HTTP/1.1 500 
X-Frame-Options: SAMEORIGIN
Date: Thu, 06 Aug 2026 15:19:44 GMT
Server: Restlet-Framework/2.4.4
Content-Type: application/json;charset=UTF-8
Transfer-Encoding: chunked
Connection: close

```

**Body** — 149 bytes, md5 `dd82fa5d59a42118454371b094ddfa6a`

```
{"error":"Internal Server Error","error_description":"The server encountered an unexpected condition which prevented it from fulfilling the request"}
```

### 05 — wrong rel

```
GET /.well-known/webfinger?resource=acct%3ademo%40example.com&rel=http%3a%2f%2fexample.com%2fnot-the-issuer-rel
```

**Status + headers**

```http
HTTP/1.1 500 
X-Frame-Options: SAMEORIGIN
Date: Thu, 06 Aug 2026 15:19:44 GMT
Server: Restlet-Framework/2.4.4
Content-Type: application/json;charset=UTF-8
Transfer-Encoding: chunked
Connection: close

```

**Body** — 149 bytes, md5 `dd82fa5d59a42118454371b094ddfa6a`

```
{"error":"Internal Server Error","error_description":"The server encountered an unexpected condition which prevented it from fulfilling the request"}
```

### 06 — unknown user

```
GET /.well-known/webfinger?resource=acct%3anobody%40example.com&rel=http%3a%2f%2fopenid.net%2fspecs%2fconnect%2f1.0%2fissuer
```

**Status + headers**

```http
HTTP/1.1 500 
X-Frame-Options: SAMEORIGIN
Date: Thu, 06 Aug 2026 15:19:44 GMT
Server: Restlet-Framework/2.4.4
Content-Type: application/json;charset=UTF-8
Transfer-Encoding: chunked
Connection: close

```

**Body** — 149 bytes, md5 `dd82fa5d59a42118454371b094ddfa6a`

```
{"error":"Internal Server Error","error_description":"The server encountered an unexpected condition which prevented it from fulfilling the request"}
```

### 07 — no parameters at all

```
GET /.well-known/webfinger
```

**Status + headers**

```http
HTTP/1.1 500 
X-Frame-Options: SAMEORIGIN
Date: Thu, 06 Aug 2026 15:19:44 GMT
Server: Restlet-Framework/2.4.4
Content-Type: application/json;charset=UTF-8
Transfer-Encoding: chunked
Connection: close

```

**Body** — 149 bytes, md5 `dd82fa5d59a42118454371b094ddfa6a`

```
{"error":"Internal Server Error","error_description":"The server encountered an unexpected condition which prevented it from fulfilling the request"}
```

### 08 — bad realm via ?realm=

```
GET /.well-known/webfinger?resource=acct%3ademo%40example.com&rel=http%3a%2f%2fopenid.net%2fspecs%2fconnect%2f1.0%2fissuer&realm=%2fbogus
```

**Status + headers**

```http
HTTP/1.1 404 
X-Frame-Options: SAMEORIGIN
Date: Thu, 06 Aug 2026 15:19:44 GMT
Server: Restlet-Framework/2.4.4
Content-Type: application/json;charset=UTF-8
Transfer-Encoding: chunked

```

**Body** — 70 bytes, md5 `2c54883f2d648b11fa2c17d7ad640f48`

```
{"error":"Not Found","error_description":"Realm \"/bogus\" not found"}
```

### 09 — unrouted child

```
GET /.well-known/nonsense
```

**Status + headers**

```http
HTTP/1.1 500 
X-Frame-Options: SAMEORIGIN
Date: Thu, 06 Aug 2026 15:19:44 GMT
Server: Restlet-Framework/2.4.4
Content-Type: application/json;charset=UTF-8
Transfer-Encoding: chunked
Connection: close

```

**Body** — 149 bytes, md5 `dd82fa5d59a42118454371b094ddfa6a`

```
{"error":"Internal Server Error","error_description":"The server encountered an unexpected condition which prevented it from fulfilling the request"}
```

### 10 — bare /.well-known/

```
GET /.well-known/
```

**Status + headers**

```http
HTTP/1.1 404 
X-Frame-Options: SAMEORIGIN
Date: Thu, 06 Aug 2026 15:19:44 GMT
Accept-Ranges: bytes
Server: Restlet-Framework/2.4.4
Content-Type: application/json;charset=UTF-8
Transfer-Encoding: chunked

```

**Body** — 102 bytes, md5 `1b2c72cf6c481841700579cec2730fd2`

```
{"error":"Not Found","error_description":"The server has not found anything matching the request URI"}
```

### 11 — realms/{realm} path spelling

```
GET /.well-known/realms/root/webfinger?resource=acct%3ademo%40example.com&rel=http%3a%2f%2fopenid.net%2fspecs%2fconnect%2f1.0%2fissuer
```

**Status + headers**

```http
HTTP/1.1 500 
X-Frame-Options: SAMEORIGIN
Date: Thu, 06 Aug 2026 15:19:44 GMT
Server: Restlet-Framework/2.4.4
Content-Type: application/json;charset=UTF-8
Transfer-Encoding: chunked
Connection: close

```

**Body** — 149 bytes, md5 `dd82fa5d59a42118454371b094ddfa6a`

```
{"error":"Internal Server Error","error_description":"The server encountered an unexpected condition which prevented it from fulfilling the request"}
```

### 12 — legacy subrealm path spelling, unresolvable realm

```
GET /.well-known/bogusrealm/webfinger?resource=acct%3ademo%40example.com&rel=http%3a%2f%2fopenid.net%2fspecs%2fconnect%2f1.0%2fissuer
```

**Status + headers**

```http
HTTP/1.1 500 
X-Frame-Options: SAMEORIGIN
Date: Thu, 06 Aug 2026 15:19:44 GMT
Server: Restlet-Framework/2.4.4
Content-Type: application/json;charset=UTF-8
Transfer-Encoding: chunked
Connection: close

```

**Body** — 149 bytes, md5 `dd82fa5d59a42118454371b094ddfa6a`

```
{"error":"Internal Server Error","error_description":"The server encountered an unexpected condition which prevented it from fulfilling the request"}
```

### 13 — HEAD on the success URL

```
HEAD /.well-known/webfinger?resource=acct%3ademo%40example.com&rel=http%3a%2f%2fopenid.net%2fspecs%2fconnect%2f1.0%2fissuer&realm=%2f
```

**Status + headers**

```http
HTTP/1.1 500 
X-Frame-Options: SAMEORIGIN
Date: Thu, 06 Aug 2026 15:19:44 GMT
Server: Restlet-Framework/2.4.4
Content-Type: text/html;charset=utf-8
Content-Language: en
Content-Length: 717
Connection: close

```

**Body** — 0 bytes, md5 `d41d8cd98f00b204e9800998ecf8427e`

_(empty)_

### 14 — POST on the success URL

```
POST /.well-known/webfinger?resource=acct%3ademo%40example.com&rel=http%3a%2f%2fopenid.net%2fspecs%2fconnect%2f1.0%2fissuer&realm=%2f
```

**Status + headers**

```http
HTTP/1.1 500 
X-Frame-Options: SAMEORIGIN
Date: Thu, 06 Aug 2026 15:19:44 GMT
Server: Restlet-Framework/2.4.4
Content-Type: application/json;charset=UTF-8
Transfer-Encoding: chunked
Connection: close

```

**Body** — 149 bytes, md5 `dd82fa5d59a42118454371b094ddfa6a`

```
{"error":"Internal Server Error","error_description":"The server encountered an unexpected condition which prevented it from fulfilling the request"}
```

### 15 — R-5d2.4: does /.well-known serve openid-configuration at the context root?

```
GET /.well-known/openid-configuration
```

**Status + headers**

```http
HTTP/1.1 500 
X-Frame-Options: SAMEORIGIN
Date: Thu, 06 Aug 2026 15:19:44 GMT
Server: Restlet-Framework/2.4.4
Content-Type: application/json;charset=UTF-8
Transfer-Encoding: chunked
Connection: close

```

**Body** — 149 bytes, md5 `dd82fa5d59a42118454371b094ddfa6a`

```
{"error":"Internal Server Error","error_description":"The server encountered an unexpected condition which prevented it from fulfilling the request"}
```

### 16 — control: the same document under /oauth2 (already CHF-served)

```
GET /oauth2/.well-known/openid-configuration
```

**Status + headers**

```http
HTTP/1.1 200 
X-Frame-Options: SAMEORIGIN
Content-Type: application/json;charset=UTF-8
Content-Length: 1515
Date: Thu, 06 Aug 2026 15:19:44 GMT

```

**Body** — 1515 bytes, md5 `74c2c745fbbdc2c4bdd52cbe748d83ed`

```
{"response_types_supported":["code","code token","token"],"claims_parameter_supported":false,"end_session_endpoint":"http://openam.example.org:8080/openam/oauth2/connect/endSession","revocation_endpoint":"http://openam.example.org:8080/openam/oauth2/revoke","version":"3.0","check_session_iframe":"http://openam.example.org:8080/openam/oauth2/connect/checkSession","scopes_supported":["openid","profile","uma_protection","uma_authorization"],"issuer":"http://openam.example.org:8080/openam/oauth2","id_token_encryption_enc_values_supported":["A256GCM","A192GCM","A128GCM","A128CBC-HS256","A192CBC-HS384","A256CBC-HS512"],"acr_values_supported":[],"authorization_endpoint":"http://openam.example.org:8080/openam/oauth2/authorize","userinfo_endpoint":"http://openam.example.org:8080/openam/oauth2/userinfo","device_authorization_endpoint":"http://openam.example.org:8080/openam/oauth2/device/code","claims_supported":[],"id_token_encryption_alg_values_supported":["RSA-OAEP","RSA-OAEP-256","A128KW","RSA1_5","A256KW","dir","A192KW"],"jwks_uri":"http://openam.example.org:8080/openam/oauth2/connect/jwk_uri","subject_types_supported":["public"],"id_token_signing_alg_values_supported":["ES384","HS256","HS512","ES256","RS256","HS384","ES512"],"registration_endpoint":"http://openam.example.org:8080/openam/oauth2/connect/register","token_endpoint_auth_methods_supported":["client_secret_post","private_key_jwt","none","client_secret_basic"],"token_endpoint":"http://openam.example.org:8080/openam/oauth2/access_token"}
```

### 17 — /.well-known with no trailing slash

```
GET /.well-known
```

**Status + headers**

```http
HTTP/1.1 404 
X-Frame-Options: SAMEORIGIN
Date: Thu, 06 Aug 2026 15:19:44 GMT
Accept-Ranges: bytes
Server: Restlet-Framework/2.4.4
Content-Type: application/json;charset=UTF-8
Transfer-Encoding: chunked

```

**Body** — 102 bytes, md5 `1b2c72cf6c481841700579cec2730fd2`

```
{"error":"Not Found","error_description":"The server has not found anything matching the request URI"}
```

### 18 — extra path element after webfinger

```
GET /.well-known/webfinger/extra?resource=acct%3ademo%40example.com&rel=http%3a%2f%2fopenid.net%2fspecs%2fconnect%2f1.0%2fissuer
```

**Status + headers**

```http
HTTP/1.1 500 
X-Frame-Options: SAMEORIGIN
Date: Thu, 06 Aug 2026 15:19:45 GMT
Server: Restlet-Framework/2.4.4
Content-Type: application/json;charset=UTF-8
Transfer-Encoding: chunked
Connection: close

```

**Body** — 149 bytes, md5 `dd82fa5d59a42118454371b094ddfa6a`

```
{"error":"Internal Server Error","error_description":"The server encountered an unexpected condition which prevented it from fulfilling the request"}
```

### 19 — deep unrouted child

```
GET /.well-known/a/b/c
```

**Status + headers**

```http
HTTP/1.1 500 
X-Frame-Options: SAMEORIGIN
Date: Thu, 06 Aug 2026 15:19:45 GMT
Server: Restlet-Framework/2.4.4
Content-Type: application/json;charset=UTF-8
Transfer-Encoding: chunked
Connection: close

```

**Body** — 149 bytes, md5 `dd82fa5d59a42118454371b094ddfa6a`

```
{"error":"Internal Server Error","error_description":"The server encountered an unexpected condition which prevented it from fulfilling the request"}
```

