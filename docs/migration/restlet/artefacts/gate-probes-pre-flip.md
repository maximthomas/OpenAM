# Checklist-13 gate probes — live Restlet, recorded 2026-08-05

The last-chance measurements taken immediately before the 5d-1c flip, per
[phase-5d-1.md](../phase-5d-1.md) checklist step 13 and
[risk #20](../plan.md#risk-register-behavioral-compatibility). Everything here answers a question the
[spec](../phase-5d-1.md) left open and that **only live Restlet could answer**; after the flip none of it is
reproducible.

Container `openam-idp`, image `openam-e2e:5d1b`, git `ad28c31fc3`, `/oauth2/*` served by `ForgeRockRest`.
Companion artefacts: [`e2e-oracle-pre-flip.txt`](e2e-oracle-pre-flip.txt) (210 normalised rows) and
[`e2e-transcript-pre-flip.txt`](e2e-transcript-pre-flip.txt) (the raw run).

**Verdict: FLIP MAY PROCEED.** No open question still required the live oracle.

## `?_api` / `?_crestapi` — 5-E5 row 8, bytes never recorded

The spec notes CHF's `ApiDescriptorFilter` / `OpenApiRequestFilter` see these parameters on `/oauth2` for the
first time after the flip, but drafted no divergence row and recorded no Restlet bytes to compare against.

```
GET /oauth2/connect/jwk_uri            -> 200 application/json;charset=UTF-8, 447 B
GET /oauth2/connect/jwk_uri?_api       -> 200, header set and body BYTE-IDENTICAL to the plain GET
GET /oauth2/connect/jwk_uri?_crestapi  -> 200, byte-identical
GET /oauth2/tokeninfo (Bearer)         -> 200 application/json, Cache-Control: no-cache, no-store
GET /oauth2/tokeninfo?_api             -> 200, byte-identical incl. Cache-Control
GET /oauth2/tokeninfo?_crestapi        -> 200, byte-identical      (never sent by 5-E5)
GET /oauth2/tokeninfo?_api=true        -> 200, byte-identical
GET /oauth2/tokeninfo?_crestapi=true   -> 200, byte-identical
```

⇒ **Restlet ignores both parameters completely**, on a public lookup and on a token-protected endpoint alike.

## `Allow` on the two filter-produced 405s — confirms 5-E5 row 6

```
PROPFIND /oauth2/authorize     -> 405  {"error_description":"Required Method: GET or POST found: PROPFIND","error":"method_not_allowed"}
PROPFIND /oauth2/access_token  -> 405  {"error_description":"Required Method: POST found: PROPFIND","error":"method_not_allowed"}
GET      /oauth2/access_token  -> 405  {"error_description":"Required Method: POST found: GET","error":"method_not_allowed"}
PUT      /oauth2/authorize     -> 405  {"error_description":"Required Method: GET or POST found: PUT","error":"method_not_allowed"}
OPTIONS  /oauth2/authorize     -> 405  {"error_description":"Required Method: GET or POST found: OPTIONS","error":"method_not_allowed"}
```

Header set: `X-Frame-Options: SAMEORIGIN`, `Cache-Control: no-store`, `Date`, `Accept-Ranges: bytes`,
`Server`, `Pragma: no-cache`, `Content-Type: application/json`, `Transfer-Encoding: chunked`.
**No `Allow` on any of them.** Contrast the resource producer: `PROPFIND /oauth2/tokeninfo` → 405 **+
`Allow: GET`** + a CREST body + no cache headers.

⚠ 5d-1a makes CHF stamp `Allow` on both producers, so the flip *adds* a header here that Restlet never sent.
That change had no divergence row — it becomes **row 21**.

## `HEAD` `Content-Length` per endpoint shape — finding 7, the Restlet half

```
success  HEAD /oauth2/tokeninfo (token)                -> 200 application/json,                no Content-Length, no Transfer-Encoding
         HEAD /oauth2/.well-known/openid-configuration -> 200 application/json;charset=UTF-8,  no Content-Length
         HEAD /oauth2/connect/jwk_uri                  -> 200 application/json;charset=UTF-8,  no Content-Length
         HEAD /oauth2/resource_set  and  /resource_set/ -> 200 application/json,               no Content-Length

error    HEAD /oauth2/tokeninfo (no token)   -> 401 text/html;charset=utf-8 + Content-Language: en + Content-Length: 721
         HEAD /oauth2/userinfo  (no token)   -> 401 ... Content-Length: 721   (its GET is application/json)
         HEAD /oauth2/nosuchendpoint         -> 404 ... Content-Length: 714
         HEAD /oauth2/connect/nosuch         -> 404 ... Content-Length: 714
         HEAD /oauth2/realms/bogus/tokeninfo -> 404 ... Content-Length: 714
         HEAD /oauth2/access_token           -> 405 ... Content-Length: 726  (+ Cache-Control: no-store, Pragma: no-cache)
         HEAD /oauth2/authorize              -> 405 ... Content-Length: 726  (+ same cache headers)
         HEAD /oauth2/idtokeninfo            -> 405 ... Content-Length: 726
         HEAD /oauth2/connect/register       -> 400 ... Content-Length: 796  (its GET is 400 application/json, 170 B)
```

⇒ Restlet sends **no** `Content-Length` on a successful `HEAD` and **does** send one on its own error pages:
401/404/405/400 = **721 / 714 / 726 / 796**.

## `PATCH /oauth2/resource_set/{rsid}` — divergence row 14's unmeasured "+ new ETag"

Row 14 asserted a new `ETag` from the source; it had never been measured. Confirmed on a throwaway resource
set:

```
POST  /oauth2/resource_set                  -> 201 ETag: W/"979061353"
PATCH /oauth2/resource_set/{id} If-Match:*  -> 200 ETag: W/"-2033111829"   <-- NEW tag, confirmed
      body: {"_id":"…","user_access_policy_uri":"…"}   (the create shape, not the description)
GET   after                                 -> 200 ETag: W/"-2033111829", name+scopes fully replaced
PATCH with NO If-Match                      -> 400 {"error_description":"precondition_failed (512) - Require If-Match header to update Resource Set","error":"server_error"}
```

## Realm and unrouted 404s, verbatim — ⚠ this corrects divergence row 15

```
GET /oauth2/realms/bogus/tokeninfo -> 404 application/json
    {"code":404,"reason":"Not Found","message":"No mapping organization found for organization identifier: /bogus"}
GET /oauth2/tokeninfo?realm=bogus  -> 404
    {"code":404,"reason":"Not Found","message":"No mapping organization found for organization identifier: bogus"}
GET /oauth2/resource_set/a/b       -> 404
    {"code":404,"reason":"Not Found","message":"No mapping organization found for organization identifier: /resource_set"}
GET /oauth2/nosuchendpoint         -> 404
    {"code":404,"reason":"Not Found","message":"The server has not found anything matching the request URI"}
```

The realm 404s carry **no** `Accept-Ranges`; the router 404 does.

⚠ **[Divergence row 15](../phase-5d-1.md) as drafted is wrong.** It states Restlet answers
`{"code":404,…,"message":"Realm \"bogus\" not found"}` and cites *"confirmed by 5-E5 row 4"*. 5-E5 row 4
measured `"No mapping organization found for organization identifier: /bogus"` — the cited measurement
contradicts the claim. Consequently D5's *"for the realm case even the `error_description` is byte-identical
to Restlet's `message`"* cannot hold either. Corrected in 5d-1c's commit.

## JSP mappings that out-rank `/oauth2/*` — baseline so a post-flip regression is attributable

Exact `<url-pattern>`s beat the `/oauth2/*` prefix per the servlet spec, so these must be **unchanged** after
the flip. `/oauth2/registerClient.jsp` had no e2e coverage at all.

```
GET  /oauth2/registerClient.jsp   -> 302 Location: ../UI/Login, Content-Length: 0,
                                        Set-Cookie: JSESSIONID=…; Path=/openam; HttpOnly
                                        NO Server header => Jasper, not Restlet
GET  /oauth2/connect/checkSession -> 200 text/html;charset=UTF-8, Content-Length: 1254, no Server header (JSP)
POST /oauth2/connect/checkSession -> 200 same 1254 B
PUT  /oauth2/connect/checkSession -> 405 Tomcat/Jasper page, Allow: GET, HEAD, POST, OPTIONS,
                                        text/html;charset=utf-8, Content-Length: 771
HEAD /oauth2/connect/checkSession -> 200 Content-Length: 1254  (Jasper sends it; Restlet does not)
GET  /oauth2/realms/root/connect/checkSession -> 200 text/html;charset=UTF-8, Server: Restlet-Framework/2.4.4 (FTL)
GET  /oauth2/checkSession.jsp     -> 404 Restlet router 404, application/json, 104 B  <-- flips to D5's body
```

## Negative results — recorded so nobody re-asks

```
Accept: application/xml | text/html | text/plain | application/json | */*  on /oauth2/connect/jwk_uri
  -> 200 application/json;charset=UTF-8, 447 B, identical every time.  No conneg, no 406.
Accept: text/html on /oauth2/tokeninfo -> 200 application/json.  No conneg.
Accept-Encoding: gzip -> no Content-Encoding.  Restlet does not compress /oauth2.
```

`Vary: Accept-*` and `Accept-Ranges: bytes` are pure Restlet-connector artefacts and vanish at the flip; no
e2e row asserts either.

## Incidental — not asserted by any e2e row

A resource set registered with a **client_credentials** PAT cannot be deleted:

```
DELETE /oauth2/resource_set/{id} If-Match:* (or the concrete tag) -> 400
    {"error_description":"Internal Server Error (500) - The server encountered an unexpected condition which prevented it from fulfilling the request","error":"server_error"}
```

The same lifecycle with a **password**-grant PAT (owner `demo`) deletes cleanly (204). Pre-existing product
behaviour, unrelated to the migration; noted so a post-flip sighting is not misread as a regression.
