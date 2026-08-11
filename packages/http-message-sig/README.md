# http-message-sig

![License](https://img.shields.io/npm/l/http-message-sig.svg)
[![crates.io](https://img.shields.io/npm/v/http-message-sig.svg)][npm]

[npm]: https://www.npmjs.com/package/http-message-sig

HTTP Message Signatures defined by [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html).

Forked from [ltonetwork/http-message-signatures](https://github.com/ltonetwork/http-message-signatures).

## Tables of Content

- [Features](#features)
- [Usage](#usage)
- [Security Considerations](#security-considerations)
- [License](#license)

## Features

- RFC 9421 request, response, trailer, and request-bound response signatures
- Occurrence-preserving fields and all derived/component parameters
- Multiple `Signature`, `Signature-Input`, and `Accept-Signature` members
- RFC 9651 Structured Fields parser and serializer
- Provider API for all registered algorithms and optional WebCrypto provider
- Legacy `Signer`, `SignerSync`, and `Verify<T>` compatibility

## Usage

The vNext API uses ordered discriminated unions (`HttpMessage`,
`CoveredComponent`, `SfParameter`, and `BareItem`). `buildSignatureBase`,
`signMessage`, `verifyMessageSignatures`, `appendSignature`, and the field
parsers operate on these values. Strict RFC 9421 is the default. Pass
`signatureInputProfile: "rfc9651-extension"` only for an explicitly negotiated
Signature-Input extension profile.

`alg` is optional. Providers supply the effective algorithm; a present `alg`
parameter must match it. `webCryptoSigningProvider` and
`webCryptoVerificationProvider` accept operation-specific private/secret and
public/secret keys. Parsing and base construction apply conservative limits by
default; override individual values with `limits` when a deployment needs a
larger bounded envelope. `maxFieldOccurrences` and `maxFieldBytes` are
aggregate message-construction limits, not per-component limits; all covered
field occurrences share them.

`HttpRequest.requestTarget` preserves the raw request-target independently from
`targetUri`; its origin, absolute, authority, or asterisk form must match the
HTTP method. For `bs`, each field occurrence is unfolded and stripped of outer
OWS before Base64 encoding. `FieldOccurrence.bytes` supplies the original HTTP
bytes directly; the same CRLF+OWS unfolding and byte-level OWS stripping apply.

`Accept-Signature` has separate validation: bare `created` and `expires`
parameters request generated values, while `Signature-Input` requires integer
timestamps.

Legacy `signatureHeaders`, `signatureHeadersSync`, and `verify` remain exported.

## Security Considerations

Messages are snapshotted once before asynchronous provider or policy callbacks,
closing mutation/TOCTOU windows without repeated full copies. Applications must
still enforce key lookup, freshness, nonce/replay, required-component, and
algorithm policy through verification callbacks. This software has not been
audited.

## License

This project is under the Apache-2.0 license.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you shall be Apache-2.0 licensed as above, without any additional terms or conditions.

### Forks

This project is forked from [ltonetwork/http-message-signatures](https://github.com/ltonetwork/http-message-signatures).
It has been forked to allow for customization and extension of the library's functionality.
It is may be rewritten from scratch down the line, as the original project is not fully implementing the RFC.
