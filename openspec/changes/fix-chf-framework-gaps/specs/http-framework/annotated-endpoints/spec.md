## Purpose

Defines the HTTP method contract for endpoints declared as annotated handler classes: which
methods an endpoint serves, how `HEAD` is answered, and the status line, `Allow` header and
body of a `405 Method Not Allowed` response.

## ADDED Requirements

### Requirement: An endpoint serves the methods it declares

An annotated endpoint SHALL serve each HTTP method for which it declares a handler: `GET`,
`POST`, `PUT` and `DELETE`. A request whose method has no declared handler SHALL receive
`405 Method Not Allowed`.

A `POST` request carrying an `X-HTTP-Method-Override` header SHALL be dispatched as though its
method were the value of that header.

#### Scenario: Declared method
- **WHEN** a `POST` request reaches an endpoint that declares a `POST` handler
- **THEN** that handler is invoked

#### Scenario: Undeclared method
- **WHEN** a `DELETE` request reaches an endpoint that declares only `POST`
- **THEN** the response status is `405`

#### Scenario: Method override
- **WHEN** a `POST` request carrying `X-HTTP-Method-Override: DELETE` reaches an endpoint that declares a `DELETE` handler
- **THEN** the `DELETE` handler is invoked

### Requirement: HEAD is served by the GET handler

An endpoint that declares a `GET` handler SHALL serve `HEAD` by invoking that handler and
returning the resulting status and headers with no message body. An endpoint that declares no
`GET` handler SHALL respond `405` to `HEAD`.

The `Content-Length` of a `HEAD` response SHALL NOT be required to equal the length of the body
the corresponding `GET` would return. RFC 9110 §9.3.2 permits a server to omit header fields
whose values are determined only while generating content, and the response is written without
the body being produced. This is a deliberate and accepted divergence from the Restlet
behaviour it replaces, which reported the true length; no conformance test may assert a
particular `Content-Length` on a `HEAD` response.

#### Scenario: HEAD on an endpoint declaring GET
- **WHEN** a `HEAD` request reaches an endpoint whose `GET` handler returns `200` with a JSON body
- **THEN** the response status is `200`
- **AND** the headers set by the handler are present
- **AND** the response carries no message body

#### Scenario: HEAD on an endpoint not declaring GET
- **WHEN** a `HEAD` request reaches an endpoint that declares only `POST`
- **THEN** the response status is `405`

#### Scenario: Content-Length on a HEAD response is unconstrained
- **WHEN** a `HEAD` request is served by an endpoint whose `GET` returns a body of non-zero length
- **THEN** the response is conformant whether it carries `Content-Length` equal to that length, `Content-Length: 0`, or no `Content-Length` header at all

#### Scenario: A failing GET handler is reported identically under HEAD
- **WHEN** a `HEAD` request reaches an endpoint whose `GET` handler fails with `500`
- **THEN** the response status is `500`
- **AND** the response carries no message body

### Requirement: Every 405 response advertises the methods that are allowed

A `405` response from an annotated endpoint SHALL include an `Allow` header naming the methods
that endpoint serves, as required by RFC 9110 §15.5.6.

The advertised set SHALL comprise the endpoint's declared handler methods, plus `HEAD` whenever
a `GET` handler is declared. An annotated endpoint SHALL NOT advertise `OPTIONS`, because it
does not serve it.

Where a filter ahead of the endpoint answers `OPTIONS` on its behalf, that filter is responsible
for the `Allow` header of its own response; this requirement governs only the `405` responses
the endpoint itself produces.

#### Scenario: Endpoint declaring only POST
- **WHEN** a `GET` request reaches an endpoint that declares only `POST`
- **THEN** the response status is `405`
- **AND** the response carries `Allow: POST`

#### Scenario: Endpoint declaring only GET
- **WHEN** a `POST` request reaches an endpoint that declares only `GET`
- **THEN** the response status is `405`
- **AND** the advertised methods are `GET` and `HEAD`

#### Scenario: Endpoint declaring GET and POST
- **WHEN** a `PATCH` request reaches an endpoint that declares `GET` and `POST`
- **THEN** the response status is `405`
- **AND** the advertised methods are `GET`, `HEAD` and `POST`

### Requirement: Every 405 response body reports status 405

A `405` response SHALL carry a body whose reported status code is `405`, and that body SHALL
have the same shape whether the requested method is one the endpoint could have declared or one
outside the declarable set.

Before this change the two cases diverged: a method outside the declarable set produced a `405`
status line above a body reporting `501`, contradicting itself, while a declarable but
undeclared method produced a correct `405` body.

#### Scenario: Method outside the declarable set
- **WHEN** a `PATCH` request reaches an endpoint that declares only `POST`
- **THEN** the response status is `405`
- **AND** the body reports status code `405`

#### Scenario: Declarable but undeclared method
- **WHEN** a `GET` request reaches an endpoint that declares only `POST`
- **THEN** the response status is `405`
- **AND** the body reports status code `405`

#### Scenario: Both cases agree
- **WHEN** the two preceding scenarios are compared
- **THEN** the two response bodies have the same shape and the same reported status code
