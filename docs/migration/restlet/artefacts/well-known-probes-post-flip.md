# `/.well-known` oracle capture — post-flip

Driven against `http://openam.example.org:8080/openam`.

### 01 — success: issuer lookup, explicit realm=/ (the e2e spec's row)

```
GET /.well-known/webfinger?resource=acct%3ademo%40example.com&rel=http%3a%2f%2fopenid.net%2fspecs%2fconnect%2f1.0%2fissuer&realm=%2f
```

**Status + headers**

```http
HTTP/1.1 200 
X-Frame-Options: SAMEORIGIN
Content-Type: application/json;charset=UTF-8
Content-Length: 152
Date: Sat, 08 Aug 2026 08:12:11 GMT

```

**Body** — 152 bytes, md5 `2df598686034f3c5ecae01102e6a3c39`

```
{"subject":"acct:demo@example.com","links":[{"rel":"http://openid.net/specs/connect/1.0/issuer","href":"http://openam.example.org:8080/openam/oauth2"}]}
```

### 02 — success: issuer lookup, no realm parameter

```
GET /.well-known/webfinger?resource=acct%3ademo%40example.com&rel=http%3a%2f%2fopenid.net%2fspecs%2fconnect%2f1.0%2fissuer
```

**Status + headers**

```http
HTTP/1.1 200 
X-Frame-Options: SAMEORIGIN
Content-Type: application/json;charset=UTF-8
Content-Length: 152
Date: Sat, 08 Aug 2026 08:12:11 GMT

```

**Body** — 152 bytes, md5 `2df598686034f3c5ecae01102e6a3c39`

```
{"subject":"acct:demo@example.com","links":[{"rel":"http://openid.net/specs/connect/1.0/issuer","href":"http://openam.example.org:8080/openam/oauth2"}]}
```

### 03 — missing resource (rel only)

```
GET /.well-known/webfinger?rel=http%3a%2f%2fopenid.net%2fspecs%2fconnect%2f1.0%2fissuer
```

**Status + headers**

```http
HTTP/1.1 400 
X-Frame-Options: SAMEORIGIN
Content-Type: application/json;charset=UTF-8
Content-Length: 80
Date: Sat, 08 Aug 2026 08:12:11 GMT
Connection: close

```

**Body** — 80 bytes, md5 `16b0e18092c50b4ad565a76350346372`

```
{"error":"bad_request","error_description":"No resource provided in discovery."}
```

### 04 — missing rel (resource only)

```
GET /.well-known/webfinger?resource=acct%3ademo%40example.com
```

**Status + headers**

```http
HTTP/1.1 400 
X-Frame-Options: SAMEORIGIN
Content-Type: application/json;charset=UTF-8
Content-Length: 86
Date: Sat, 08 Aug 2026 08:12:11 GMT
Connection: close

```

**Body** — 86 bytes, md5 `08e8fec4a79efd233fe1fefd26dc38d1`

```
{"error":"bad_request","error_description":"No or invalid rel provided in discovery."}
```

### 05 — wrong rel

```
GET /.well-known/webfinger?resource=acct%3ademo%40example.com&rel=http%3a%2f%2fexample.com%2fnot-the-issuer-rel
```

**Status + headers**

```http
HTTP/1.1 400 
X-Frame-Options: SAMEORIGIN
Content-Type: application/json;charset=UTF-8
Content-Length: 86
Date: Sat, 08 Aug 2026 08:12:11 GMT
Connection: close

```

**Body** — 86 bytes, md5 `08e8fec4a79efd233fe1fefd26dc38d1`

```
{"error":"bad_request","error_description":"No or invalid rel provided in discovery."}
```

### 06 — unknown user

```
GET /.well-known/webfinger?resource=acct%3anobody%40example.com&rel=http%3a%2f%2fopenid.net%2fspecs%2fconnect%2f1.0%2fissuer
```

**Status + headers**

```http
HTTP/1.1 404 
X-Frame-Options: SAMEORIGIN
Content-Type: application/json;charset=UTF-8
Content-Length: 63
Date: Sat, 08 Aug 2026 08:12:11 GMT

```

**Body** — 63 bytes, md5 `e9e7a36eb75f9e8899a980e8085697a5`

```
{"error":"not_found","error_description":"Invalid parameters."}
```

### 07 — no parameters at all

```
GET /.well-known/webfinger
```

**Status + headers**

```http
HTTP/1.1 400 
X-Frame-Options: SAMEORIGIN
Content-Type: application/json;charset=UTF-8
Content-Length: 80
Date: Sat, 08 Aug 2026 08:12:11 GMT
Connection: close

```

**Body** — 80 bytes, md5 `16b0e18092c50b4ad565a76350346372`

```
{"error":"bad_request","error_description":"No resource provided in discovery."}
```

### 08 — bad realm via ?realm=

```
GET /.well-known/webfinger?resource=acct%3ademo%40example.com&rel=http%3a%2f%2fopenid.net%2fspecs%2fconnect%2f1.0%2fissuer&realm=%2fbogus
```

**Status + headers**

```http
HTTP/1.1 400 
X-Frame-Options: SAMEORIGIN
Content-Type: application/json;charset=UTF-8
Content-Length: 71
Date: Sat, 08 Aug 2026 08:12:11 GMT
Connection: close

```

**Body** — 71 bytes, md5 `68c64a4ffebaee87bf293484fbcdcf06`

```
{"error":"invalid_request","error_description":"Invalid realm, /bogus"}
```

### 09 — unrouted child

```
GET /.well-known/nonsense
```

**Status + headers**

```http
HTTP/1.1 404 
X-Frame-Options: SAMEORIGIN
Content-Type: application/json;charset=UTF-8
Content-Length: 53
Date: Sat, 08 Aug 2026 08:12:11 GMT

```

**Body** — 53 bytes, md5 `6995583eaf3206e9093f2f4dfc469b72`

```
{"error":"not_found","error_description":"Not Found"}
```

### 10 — bare /.well-known/

```
GET /.well-known/
```

**Status + headers**

```http
HTTP/1.1 500 
X-Frame-Options: SAMEORIGIN
Content-Length: 0
Date: Sat, 08 Aug 2026 08:12:11 GMT
Connection: close

```

**Body** — 0 bytes, md5 `d41d8cd98f00b204e9800998ecf8427e`

_(empty)_

### 11 — realms/{realm} path spelling

```
GET /.well-known/realms/root/webfinger?resource=acct%3ademo%40example.com&rel=http%3a%2f%2fopenid.net%2fspecs%2fconnect%2f1.0%2fissuer
```

**Status + headers**

```http
HTTP/1.1 200 
X-Frame-Options: SAMEORIGIN
Content-Type: application/json;charset=UTF-8
Content-Length: 152
Date: Sat, 08 Aug 2026 08:12:11 GMT

```

**Body** — 152 bytes, md5 `2df598686034f3c5ecae01102e6a3c39`

```
{"subject":"acct:demo@example.com","links":[{"rel":"http://openid.net/specs/connect/1.0/issuer","href":"http://openam.example.org:8080/openam/oauth2"}]}
```

### 12 — legacy subrealm path spelling, unresolvable realm

```
GET /.well-known/bogusrealm/webfinger?resource=acct%3ademo%40example.com&rel=http%3a%2f%2fopenid.net%2fspecs%2fconnect%2f1.0%2fissuer
```

**Status + headers**

```http
HTTP/1.1 404 
X-Frame-Options: SAMEORIGIN
Content-Type: application/json;charset=UTF-8
Content-Length: 53
Date: Sat, 08 Aug 2026 08:12:11 GMT

```

**Body** — 53 bytes, md5 `6995583eaf3206e9093f2f4dfc469b72`

```
{"error":"not_found","error_description":"Not Found"}
```

### 13 — HEAD on the success URL

```
HEAD /.well-known/webfinger?resource=acct%3ademo%40example.com&rel=http%3a%2f%2fopenid.net%2fspecs%2fconnect%2f1.0%2fissuer&realm=%2f
```

**Status + headers**

```http
HTTP/1.1 200 
X-Frame-Options: SAMEORIGIN
Content-Type: application/json;charset=UTF-8
Content-Length: 152
Date: Sat, 08 Aug 2026 08:12:11 GMT

```

**Body** — 0 bytes, md5 `d41d8cd98f00b204e9800998ecf8427e`

_(empty)_

### 14 — POST on the success URL

```
POST /.well-known/webfinger?resource=acct%3ademo%40example.com&rel=http%3a%2f%2fopenid.net%2fspecs%2fconnect%2f1.0%2fissuer&realm=%2f
```

**Status + headers**

```http
HTTP/1.1 405 
X-Frame-Options: SAMEORIGIN
Allow: GET
Content-Type: application/json;charset=UTF-8
Content-Length: 71
Date: Sat, 08 Aug 2026 08:12:11 GMT

```

**Body** — 71 bytes, md5 `3ffb126e2da396a161e9cbb88c3a3487`

```
{"error":"method_not_allowed","error_description":"Method Not Allowed"}
```

### 15 — R-5d2.4: does /.well-known serve openid-configuration at the context root?

```
GET /.well-known/openid-configuration
```

**Status + headers**

```http
HTTP/1.1 404 
X-Frame-Options: SAMEORIGIN
Content-Type: application/json;charset=UTF-8
Content-Length: 53
Date: Sat, 08 Aug 2026 08:12:11 GMT

```

**Body** — 53 bytes, md5 `6995583eaf3206e9093f2f4dfc469b72`

```
{"error":"not_found","error_description":"Not Found"}
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
Date: Sat, 08 Aug 2026 08:12:12 GMT

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
Content-Type: application/json;charset=UTF-8
Content-Length: 53
Date: Sat, 08 Aug 2026 08:12:12 GMT

```

**Body** — 53 bytes, md5 `6995583eaf3206e9093f2f4dfc469b72`

```
{"error":"not_found","error_description":"Not Found"}
```

### 18 — extra path element after webfinger

```
GET /.well-known/webfinger/extra?resource=acct%3ademo%40example.com&rel=http%3a%2f%2fopenid.net%2fspecs%2fconnect%2f1.0%2fissuer
```

**Status + headers**

```http
HTTP/1.1 404 
X-Frame-Options: SAMEORIGIN
Content-Type: application/json;charset=UTF-8
Content-Length: 53
Date: Sat, 08 Aug 2026 08:12:12 GMT

```

**Body** — 53 bytes, md5 `6995583eaf3206e9093f2f4dfc469b72`

```
{"error":"not_found","error_description":"Not Found"}
```

### 19 — deep unrouted child

```
GET /.well-known/a/b/c
```

**Status + headers**

```http
HTTP/1.1 404 
X-Frame-Options: SAMEORIGIN
Content-Type: application/json;charset=UTF-8
Content-Length: 53
Date: Sat, 08 Aug 2026 08:12:12 GMT

```

**Body** — 53 bytes, md5 `6995583eaf3206e9093f2f4dfc469b72`

```
{"error":"not_found","error_description":"Not Found"}
```

