## Purpose

Defines how HTTP authentication credentials are read from an `Authorization` header and how
`WWW-Authenticate` challenges are emitted, both of which are wire-visible protocol contract for
OAuth2 clients rather than internal detail.

## ADDED Requirements

### Requirement: Basic credentials are parsed from the Authorization header

The system SHALL parse an `Authorization` header using the `Basic` scheme into a client
identifier and a secret, per RFC 7617. The identifier is the portion of the decoded value
before the first colon and the secret is everything after it; either may be empty.

The secret SHALL be exposed in a form the caller can overwrite in place after use, so a client
password need not persist in memory beyond the request that carried it.

A malformed header SHALL yield no credentials rather than partial or guessed ones. A decoded
value containing no colon and a payload that is not valid base64 SHALL both be treated as
malformed.

A header naming a scheme other than `Basic` is not malformed; it simply carries no Basic
credentials, and SHALL yield none without being reported as an error.

#### Scenario: Well-formed Basic credentials
- **WHEN** a request carries `Authorization: Basic` followed by the base64 encoding of `myclient:s3cret`
- **THEN** the identifier is `myclient`
- **AND** the secret is `s3cret`

#### Scenario: Secret containing a colon
- **WHEN** a request carries Basic credentials whose decoded value is `myclient:pass:word`
- **THEN** the identifier is `myclient`
- **AND** the secret is `pass:word`

#### Scenario: Empty secret
- **WHEN** a request carries Basic credentials whose decoded value is `myclient:`
- **THEN** the identifier is `myclient`
- **AND** the secret is present and empty, not absent

#### Scenario: Empty identifier
- **WHEN** a request carries Basic credentials whose decoded value is `:s3cret`
- **THEN** the identifier is present and empty
- **AND** the secret is `s3cret`

#### Scenario: Decoded value with no colon
- **WHEN** a request carries Basic credentials whose decoded value is `myclient`
- **THEN** no credentials are yielded

#### Scenario: Payload that is not valid base64
- **WHEN** a request carries `Authorization: Basic !!!not-base64!!!`
- **THEN** no credentials are yielded

#### Scenario: A different authentication scheme
- **WHEN** a request carries `Authorization: Bearer abc123`
- **THEN** no Basic credentials are yielded

#### Scenario: No Authorization header
- **WHEN** a request carries no `Authorization` header
- **THEN** no credentials are yielded

### Requirement: WWW-Authenticate challenges are emitted in RFC 7235 form

The system SHALL emit a `WWW-Authenticate` challenge as an authentication scheme token followed,
when parameters are present, by a single space and then the parameters as comma-separated
`name="value"` pairs, per RFC 7235 §4.1.

Parameter values SHALL be quoted strings, with `"` and `\` escaped by a preceding backslash.
Parameter order SHALL be preserved as supplied, because OAuth2 clients and conformance suites
compare the emitted header against an expected wire form.

A challenge with no parameters SHALL emit the scheme alone, with no trailing space, comma or
separator.

#### Scenario: Bearer challenge carrying an error
- **WHEN** a `Bearer` challenge is emitted with `realm` of `example`, `error` of `invalid_token` and `error_description` of `The access token expired`
- **THEN** the header value is `Bearer realm="example", error="invalid_token", error_description="The access token expired"`

#### Scenario: Parameter order is preserved
- **WHEN** the same three parameters are supplied in the order `error`, `error_description`, `realm`
- **THEN** they appear in the header value in that order

#### Scenario: Value requiring escaping
- **WHEN** a challenge parameter value contains a double quote or a backslash
- **THEN** that character is emitted escaped by a preceding backslash within the quoted string

#### Scenario: Challenge with no parameters
- **WHEN** a `Basic` challenge is emitted with no parameters
- **THEN** the header value is exactly `Basic`
