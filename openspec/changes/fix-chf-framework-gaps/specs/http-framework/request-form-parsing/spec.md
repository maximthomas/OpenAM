## Purpose

Defines how a request's form parameters are obtained from the query string and from an
`application/x-www-form-urlencoded` entity: which entities qualify for parsing, how the two
sources stay distinguishable, and what happens when an entity cannot be read.

## ADDED Requirements

### Requirement: Entity form parsing is selected by media type alone

When deciding whether a request entity holds form parameters, the system SHALL consider only
the media type of the `Content-Type` header. Parameters carried by that header — `charset`
above all — SHALL NOT affect the decision, and the comparison SHALL be case-insensitive.

Any request whose `Content-Type` media type is `application/x-www-form-urlencoded` SHALL have
its entity parsed for form parameters.

#### Scenario: Media type with no parameters
- **WHEN** a request carries `Content-Type: application/x-www-form-urlencoded` and a body of `grant_type=authorization_code&code=abc`
- **THEN** the entity is parsed
- **AND** `grant_type` resolves to `authorization_code` and `code` resolves to `abc`

#### Scenario: Media type with a charset parameter
- **WHEN** a request carries `Content-Type: application/x-www-form-urlencoded; charset=UTF-8` and a body of `grant_type=authorization_code&code=abc`
- **THEN** the entity is parsed
- **AND** `grant_type` resolves to `authorization_code` and `code` resolves to `abc`

#### Scenario: Media type differing in case
- **WHEN** a request carries `Content-Type: APPLICATION/X-WWW-FORM-URLENCODED`
- **THEN** the entity is parsed

#### Scenario: Media type with an unrecognised parameter
- **WHEN** a request carries `Content-Type: application/x-www-form-urlencoded; boundary=xyz`
- **THEN** the entity is parsed

#### Scenario: Non-form media type
- **WHEN** a request carries `Content-Type: application/json` and a JSON body
- **THEN** the entity is not parsed as form parameters
- **AND** no form parameter is derived from the body

#### Scenario: Absent Content-Type
- **WHEN** a request carries a body but no `Content-Type` header
- **THEN** the entity is not parsed as form parameters

### Requirement: Query and entity parameters remain separately obtainable

The system SHALL offer three views of a request's form parameters: those from the query string
alone, those from the request entity alone, and the two combined.

A consumer that must know where a parameter came from SHALL be able to obtain that from these
views without parsing the request itself. This distinction is load-bearing for OAuth2 client
authentication, where RFC 6749 §2.3.1 forbids credentials in the query string, and for
parameter precedence, where a query value outranks an entity value of the same name.

#### Scenario: Same parameter present in both query and entity
- **WHEN** a request has query string `state=fromQuery` and a form entity containing `state=fromEntity`
- **THEN** the query-only view yields `fromQuery` and nothing else for `state`
- **AND** the entity-only view yields `fromEntity` and nothing else for `state`
- **AND** the combined view yields both values, with the query value ordered first

#### Scenario: Parameter present only in the entity
- **WHEN** a request has an empty query string and a form entity containing `client_secret=s3cret`
- **THEN** the query-only view yields no value for `client_secret`
- **AND** the entity-only view yields `s3cret`

### Requirement: An unreadable entity fails loudly only where detection is required

The combined query-and-entity view SHALL NOT fail when the request entity cannot be read. It
SHALL return the parameters obtained from the query string, so that existing consumers of the
combined view keep their present behaviour.

The entity-only view SHALL propagate the failure, so that a consumer which must distinguish
"no parameters in the body" from "the body could not be read" is able to do so and reject the
request rather than proceeding on partial input.

#### Scenario: Combined view over an unreadable entity
- **WHEN** a request has query string `realm=/alpha` and an entity that cannot be read
- **THEN** the combined view yields `realm` as `/alpha`
- **AND** no error is raised to the caller

#### Scenario: Entity-only view over an unreadable entity
- **WHEN** a request has an entity that cannot be read
- **AND** a consumer requests the entity-only view
- **THEN** the failure is propagated to that consumer

#### Scenario: Entity-only view over a well-formed empty entity
- **WHEN** a request declares the form media type and carries a zero-length body
- **THEN** the entity-only view yields no parameters
- **AND** no error is raised, because the body was read successfully
