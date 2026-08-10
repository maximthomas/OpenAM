## Purpose

Defines the observable contract of an OAuth2 error: the fields the body carries, the relationship
between the failure that occurred and the HTTP status reported for it, and when an error is
delivered by redirecting the user agent rather than by rendering a response directly.

## ADDED Requirements

### Requirement: An error reports the status of the failure it describes

An OAuth2 error response SHALL report the HTTP status belonging to the failure that occurred. A
failure raised deep in the provider SHALL NOT have its status replaced by a generic one merely
because it crossed a handler boundary on the way out.

A resource that cannot be found SHALL be reported as not found. A failure that carries no status
of its own SHALL be reported as a server failure.

This requirement governs which status is reported, not what the status for a given failure is.
The status and error code already defined for each failure — including the existing status for a
server failure — are unchanged.

#### Scenario: A missing resource is reported as not found
- **WHEN** an operation fails because the token, code or grant it names does not exist
- **THEN** the response status is `404`
- **AND** the body reports error `not_found`

#### Scenario: A server failure is reported as a server failure
- **WHEN** an operation fails because a backing store or configuration service is unavailable
- **THEN** the body reports error `server_error`

#### Scenario: A specific failure is not widened into a generic one
- **WHEN** a failure that identifies itself as not found reaches the boundary that renders errors
- **THEN** the response reports not found
- **AND** the response does not report `server_error`

#### Scenario: A failure carrying no status of its own
- **WHEN** an unexpected exception with no OAuth2 status reaches the boundary that renders errors
- **THEN** the response reports error `server_error`

### Requirement: An error body carries the RFC 6749 error fields

An error response from an OAuth2 protocol endpoint SHALL carry an `error` field naming the error
code. It SHALL carry `error_description` when a human-readable reason is available, `error_uri`
when one is configured, and `state` when the request that failed carried a `state` parameter.

This requirement governs the OAuth2 protocol endpoints only. JSON administrative endpoints render
their own family's error format; the status they report is constrained separately, below.

Fields with no value SHALL be omitted rather than emitted empty or null, so that a client
distinguishing "absent" from "empty" reads the same thing either way.

#### Scenario: Error code is always present
- **WHEN** an OAuth2 protocol endpoint produces any error response
- **THEN** the body carries an `error` field naming the error code

#### Scenario: Description present
- **WHEN** the failure carries a human-readable reason
- **THEN** the body carries `error_description` holding that reason

#### Scenario: Description absent
- **WHEN** the failure carries no human-readable reason
- **THEN** the body carries no `error_description` field at all

#### Scenario: State is echoed
- **WHEN** the request that failed carried a `state` parameter
- **THEN** the body carries `state` holding that value

#### Scenario: State absent from the request
- **WHEN** the request that failed carried no `state` parameter
- **THEN** the body carries no `state` field

### Requirement: An error is redirected only to a validated redirect URI

When a failed request has an associated redirect URI that the provider has validated against the
client's registration, the error SHALL be delivered by redirecting the user agent to that URI
with the error fields attached. The fields SHALL be attached to the query component or the
fragment component according to the response type of the original request.

When the failure is that the redirect URI is missing, invalid, or does not match a registered
value, the provider SHALL NOT redirect. The error is rendered to the resource owner directly, so
that a mis-registered or attacker-supplied URI never receives the error. This follows RFC 6749
§3.1.2.4.

#### Scenario: Validated redirect URI, query parameters
- **WHEN** an authorization request that requested a query-delivered response fails with a validated redirect URI
- **THEN** the user agent is redirected to that URI
- **AND** the error fields appear in the query component

#### Scenario: Validated redirect URI, fragment parameters
- **WHEN** an authorization request that requested a fragment-delivered response fails with a validated redirect URI
- **THEN** the user agent is redirected to that URI
- **AND** the error fields appear in the fragment component

#### Scenario: Redirect URI does not match the registration
- **WHEN** an authorization request fails because its redirect URI does not match a registered value
- **THEN** the user agent is not redirected
- **AND** the error is rendered directly to the resource owner

#### Scenario: No redirect URI at all
- **WHEN** a request fails and has no associated redirect URI
- **THEN** the error is rendered directly

### Requirement: The same failure reports the same status on every endpoint that observes it

A failure condition raised by shared provider code SHALL report the same HTTP status whichever
endpoint family observed it. The body *shape* may differ between endpoint families — an OAuth2
endpoint renders the RFC 6749 fields above, a JSON administrative endpoint renders that family's
error format — but the status SHALL agree.

Before this change the two paths disagreed. A missing authorization code raised by the token
store was reported as `400` with `server_error` by the OAuth2 endpoints, because the error type
was opaque to their handler and was flattened into a server failure, and as `500` by the JSON
administrative endpoints, because their handler mapped every provider failure to an internal
server error. Neither reported that the resource was missing.

#### Scenario: Missing resource observed by an OAuth2 endpoint
- **WHEN** an OAuth2 endpoint invokes provider code that fails because a token or code does not exist
- **THEN** the response status is `404`

#### Scenario: Missing resource observed by a JSON administrative endpoint
- **WHEN** a JSON administrative endpoint invokes the same provider code and it fails the same way
- **THEN** the response status is `404`
- **AND** the response is not reported as an internal server error

#### Scenario: The two agree
- **WHEN** the two preceding scenarios are compared
- **THEN** both report the same HTTP status
