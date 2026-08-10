## Purpose

Defines how the OAuth2 provider reads the inputs of a request: where a named parameter is looked
for and in what order, how a repeated parameter is treated, how a client may present its
credentials and a caller its access token, and what a request carries besides its parameters.

## ADDED Requirements

### Requirement: A named parameter resolves from one source, in a fixed order

The provider SHALL resolve a named request parameter by consulting, in order: a value already
established for that name earlier in the same request; the query component of the request URI;
and the request body. The first source holding the name SHALL supply the value, and later sources
SHALL NOT be consulted.

Only a POST request's body SHALL be consulted. A body sent with any other method SHALL be ignored
for parameter resolution.

Both form-encoded and JSON request bodies SHALL be readable as parameters.

#### Scenario: Present only in the query
- **WHEN** a parameter appears in the query component and nowhere else
- **THEN** the provider resolves it to the query value

#### Scenario: Present in both the query and the body
- **WHEN** a POST request carries the same parameter name in the query component and in its body
- **THEN** the provider resolves it to the query value
- **AND** the body value is not used

#### Scenario: Established earlier in the request
- **WHEN** the provider has already established a value for a name while handling this request
- **AND** the query component also carries that name
- **THEN** the provider resolves it to the value already established

#### Scenario: Form-encoded body
- **WHEN** a POST request carries a form-encoded body holding a parameter absent from the query
- **THEN** the provider resolves it to the body value

#### Scenario: JSON body
- **WHEN** a POST request carries a JSON body holding a parameter absent from the query
- **THEN** the provider resolves it to the body value

#### Scenario: Body of a non-POST request
- **WHEN** a GET request carries a body holding a parameter absent from the query
- **THEN** the provider does not resolve that parameter
- **AND** treats it as absent

#### Scenario: Absent everywhere
- **WHEN** a parameter appears in none of the three sources
- **THEN** the provider treats it as absent rather than empty

### Requirement: Reading the request body does not consume it

Resolving a parameter from the request body SHALL leave the body readable. A later read of the
same parameter, of a different parameter, or of the whole body SHALL return what the client sent.

This holds however many times the body is read, and whichever order the reads occur in.

#### Scenario: The same body parameter read twice
- **WHEN** a parameter is resolved from a form-encoded body and then resolved again
- **THEN** both reads return the same value

#### Scenario: A parameter read, then the whole body
- **WHEN** a parameter is resolved from the body and the endpoint then reads the entire body
- **THEN** the endpoint receives the complete body as the client sent it

#### Scenario: A JSON body read twice
- **WHEN** the JSON body of a request is read and then read again
- **THEN** both reads return the same content

### Requirement: A repeated request parameter is rejected

A request that carries the same parameter more than once SHALL be rejected, whether the repeats
appear in the query component or within the request body. This follows RFC 6749 §3.1, which
forbids a request parameter from being included more than once and permits POST to the
authorization endpoint.

A parameter appearing once in the query component and once in the body is not a repeat. That case
is resolved by the precedence rule above, which exists to settle it.

#### Scenario: Repeated in the query
- **WHEN** an authorization request carries the same parameter twice in the query component
- **THEN** the request is rejected
- **AND** the response reports error `invalid_request`

#### Scenario: Repeated in a form body
- **WHEN** a POST authorization request carries the same parameter twice in its form-encoded body
- **THEN** the request is rejected
- **AND** the response reports error `invalid_request`

#### Scenario: Once in the query, once in the body
- **WHEN** a POST authorization request carries a parameter once in the query component and once in its body
- **THEN** the request is not rejected as a repeat
- **AND** the query value is the one used

#### Scenario: Distinct parameters
- **WHEN** a request carries several different parameters, none of them more than once
- **THEN** the request is not rejected on these grounds

### Requirement: A client presents its credentials by exactly one mechanism

A client SHALL present its credentials by HTTP Basic authentication, by `client_id` and
`client_secret` request parameters, or by a private-key JWT client assertion. A request that uses
more than one of these mechanisms SHALL be rejected, and the error reported SHALL be
`invalid_request` — RFC 6749 §5.2 assigns that code to a request which "utilizes more than one
mechanism for authenticating the client", whichever two mechanisms were combined.

The provider SHALL record which mechanism was used and SHALL check it against the authentication
method the client registered for the token endpoint.

#### Scenario: HTTP Basic only
- **WHEN** a request authenticates with an `Authorization: Basic` header and carries no `client_id` parameter
- **THEN** the client identifier and secret are taken from the header
- **AND** the mechanism is recorded as client secret basic

#### Scenario: Request parameters only
- **WHEN** a request carries `client_id` and `client_secret` parameters and no `Authorization: Basic` header
- **THEN** the credentials are taken from those parameters
- **AND** the mechanism is recorded as client secret post

#### Scenario: Client assertion only
- **WHEN** a request carries a client assertion of the JWT bearer assertion type and no other credentials
- **THEN** the credentials are taken from the assertion
- **AND** the mechanism is recorded as private key JWT

#### Scenario: Basic combined with a client_id parameter
- **WHEN** a request carries an `Authorization: Basic` header and a `client_id` parameter
- **THEN** the request is rejected
- **AND** the response reports error `invalid_request`

#### Scenario: Basic combined with a client assertion
- **WHEN** a request carries an `Authorization: Basic` header and a JWT bearer client assertion
- **THEN** the request is rejected
- **AND** the response reports error `invalid_request`

#### Scenario: Basic header carrying an identifier and no secret
- **WHEN** a request authenticates with an `Authorization: Basic` header whose credentials hold an identifier and an empty secret
- **THEN** the client identifier is taken from the header
- **AND** the secret is treated as empty rather than absent

#### Scenario: No client identifier anywhere
- **WHEN** a request carries no client identifier by any mechanism
- **THEN** client authentication fails

### Requirement: An access token may be presented in the header, the query or the body

The provider SHALL be able to read a bearer access token from an `Authorization: Bearer` header,
from an `access_token` query parameter, and from an `access_token` form-body parameter, per
RFC 6750 §2. Which of the three a given endpoint accepts is that endpoint's concern; the provider
SHALL be able to read all three.

#### Scenario: Authorization header
- **WHEN** a request carries an `Authorization: Bearer` header holding a valid access token
- **THEN** the provider reads that token and treats the request as bearing it

#### Scenario: Query parameter
- **WHEN** a request carries a valid access token as an `access_token` query parameter
- **THEN** the provider reads that token and treats the request as bearing it

#### Scenario: Form body parameter
- **WHEN** a POST request carries a valid access token as an `access_token` parameter in a form-encoded body
- **THEN** the provider reads that token and treats the request as bearing it

#### Scenario: No token presented
- **WHEN** a request carries no access token in any of the three locations
- **THEN** the provider does not treat the request as bearing an access token

### Requirement: A request carries its locale and the state derived while handling it

The provider SHALL determine a request's locale from the request itself when the request does not
name one, and SHALL use the named locale when it does.

A value the provider derives while handling a request SHALL remain readable for the remainder of
that request. Stages of a single request that run after the value was derived SHALL observe it.

#### Scenario: Locale named by the request
- **WHEN** an authorization request that requires consent carries a `ui_locales` parameter
- **THEN** the consent page is rendered in the named locale

#### Scenario: Locale not named by the request
- **WHEN** an authorization request that requires consent carries neither `locale` nor `ui_locales`
- **THEN** the consent page is rendered in the locale the request itself indicates

#### Scenario: A matched authentication context reaches the issued token
- **WHEN** an authorization request names `acr_values` and the resource owner authenticates by a method mapped to one of them
- **THEN** the ID token issued for that request carries that value as its `acr` claim

#### Scenario: No authentication context matched
- **WHEN** an authorization request names `acr_values` and the resource owner authenticates by a method mapped to none of them
- **THEN** the ID token issued for that request carries `0` as its `acr` claim
