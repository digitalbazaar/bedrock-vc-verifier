# Bedrock VC Verifier API module _(@bedrock/vc-verifier)_

[![Build Status](https://img.shields.io/github/actions/workflow/status/digitalbazaar/bedrock-vc-verifier/main.yaml)](https://github.com/digitalbazaar/bedrock-vc-verifier/actions/workflows/main.yaml)
[![NPM Version](https://img.shields.io/npm/v/@bedrock/vc-verifier.svg)](https://npm.im/@bedrock/vc-verifier)

> A VC Verifier API library for use with Bedrock applications.

## Table of Contents

- [Background](#background)
- [Security](#security)
- [Install](#install)
- [Usage](#usage)
- [Contribute](#contribute)
- [Commercial Support](#commercial-support)
- [License](#license)

## Background

* [Verifiable Credentials HTTP API v0.3](https://w3c-ccg.github.io/vc-api/) specification.

## Security

TBD

## Install

This software requires and supports maintained recent versions of Node.js.
Updates may remove support for older unmaintained platform versions. Please use
dependency version lock files and testing to ensure compatibility with this
software.

### NPM

To install via NPM:

```
npm install --save @bedrock/vc-verifier
```

### Development

To install locally (for development):

```
git clone https://github.com/digitalbazaar/bedrock-vc-verifier.git
cd bedrock-vc-verifier
npm install
```

## Usage

In `lib/index.js`:

```js
import '@bedrock/vc-verifier';
```

### Verifier HTTP API

This module exposes the following API endpoints.

#### Verify Presentation - `POST /vc/verify`

Example request:

```json
{
  "presentation": {},
  "challenge": "...",
  "domain": "issuer.example.com"
}
```

#### Verify Credentials - `POST /verifier/credentials`

Alias: `/instances/:instanceId/credentials/verify`

Optionally performs status checks using the `@digitalbazaar/vc-revocation-list`
or `@digitalbazaar/vc-status-list` library.

Example request:

```json
{
  "verifiableCredential": {},
  "options": {
    "checks": ["proof", "credentialStatus"]
  }
}
```

#### Verify Presentations - `POST /verifier/presentations`

Alias: `/instances/:instanceId/presentations/verify`

Optionally performs status checks using the `vc-revocation-list` or
`vc-status-list` library.

Example request:

```json
{
  "verifiablePresentation": {},
  "options": {
    "challenge": "...",
    "checks": ["proof", "credentialStatus"],
    "domain": "issuer.exmaple.com"
  }
}
```

Add `"holderBinding"` to `checks` to require that the presentation was
signed by the party each credential was issued to. Every credential must
name the presentation's verified signer as a `credentialSubject.id` (for a
VC-JWT, the `sub` claim). The signer is taken from signature verification:
the `iss` claim of a VC-JWT presentation, or the controller of the proof's
verification method for a Data Integrity presentation. A self-asserted
`holder` property is not used. DIDs are compared without fragments, and two
`did:jwk` DIDs for the same key match even if their JSON member order
differs. A credential with no subject identifier fails the check, including
a selectively disclosed credential that does not disclose
`/credentialSubject/id`. Request `"proof"` as well: without a verified
presentation signer, the check fails. mDL presentations are not affected,
because mdoc device authentication already binds the holder.

## Contribute

See [the contribute file](https://github.com/digitalbazaar/bedrock/blob/master/CONTRIBUTING.md)!

PRs accepted.

If editing the Readme, please conform to the
[standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## Commercial Support

Commercial support for this library is available upon request from
Digital Bazaar: support@digitalbazaar.com

## License

[Bedrock Non-Commercial License v1.0](LICENSE.md) © Digital Bazaar
