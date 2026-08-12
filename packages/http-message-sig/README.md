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

- RFC 9421 request, response, and descriptor operations
- RFC 9651 Structured Field values
- Synchronous and asynchronous signing
- Multiple signature parsing and label selection
- TypeScript types

## Usage

The package root provides signing, signature enumeration, and algorithm- and
key-bound verification without exposing the underlying RFC engine's types.
It defaults to the strict RFC 9421 Signature-Input profile. Date and
Display String signature parameters require the explicit
`signatureInputProfile: "rfc9651-extension"` option. Covered Structured Fields
use RFC 9651.

```typescript
import { createSignature } from "http-message-sig";

const fields = await createSignature(request, {
  signer,
  components: [
    "@method",
    { name: "@query-param", parameters: [["name", "page"]] },
    { name: "example-dictionary", parameters: [["key", "member"]] },
  ],
  parameters: [["created", 1_735_689_600]],
});
```

`fetch-message-signatures@0.1.0` provides the RFC parser and canonicalization
engine.

## Security Considerations

This software has not been audited. Please use at your sole discretion.

## License

This project is under the Apache-2.0 license.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you shall be Apache-2.0 licensed as above, without any additional terms or conditions.

### Forks

This project is forked from [ltonetwork/http-message-signatures](https://github.com/ltonetwork/http-message-signatures).
It has been forked to allow for customization and extension of the library's functionality.
It is may be rewritten from scratch down the line, as the original project is not fully implementing the RFC.
