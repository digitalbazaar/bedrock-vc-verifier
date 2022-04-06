# Bedrock VC Verifier API module _(bedrock-vc-verifier)_

[![Build Status](https://img.shields.io/github/workflow/status/digitalbazaar/bedrock-vc-verifier/Bedrock%20Node.js%20CI)](https://github.com/digitalbazaar/bedrock-vc-verifier/actions?query=workflow%3A%22Bedrock+Node.js+CI%22)
[![NPM Version](https://img.shields.io/npm/v/bedrock-vc-verifier.svg)](https://npm.im/bedrock-vc-verifier)

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

* [Verifiable Credentials HTTP API v0.3](https://w3c-ccg.github.io/vc-http-api/) specification.

## Security

TBD

## Install

- Node.js 14+ is required.

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

Optionally performs status checks using the `vc-revocation-list` or
`vc-status-list` library.

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
