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

### Return hints

A verify request with `"responseFormat": "vcalm-v1"` and `returnCredential`
or `returnPresentation` set to `true` can name a return hint in
`options.returnHint`. A verifier instance can set a default in
`verifyOptions.returnHint`; the request option overrides it. The hint names a
mapping that is applied to the returned credential or presentation. If the
hint is unknown or the mapping fails, the payload is returned unchanged and
`problemDetails` says why.

#### `mdl2vdl`

Maps a verified mdoc mDL, sent as an `application/mdoc` or
`application/mdl-vp-token` envelope, to an unsigned vDL
(`Iso18013DriversLicenseCredential`). For a presentation, the result is a
`VerifiablePresentation` whose `verifiableCredential` holds the vDL. The vDL
is a JSON-LD view of data the verifier has already verified; it carries no
proof of its own.

- `@context`: VCDM 2.0, `https://w3id.org/vdl/v1` and
  `https://w3id.org/vdl/aamva/v1`.
- `issuer.id` is a `did:jwk` for the issuer certificate's public key, and
  `issuer.name` is the certificate's common name (or `issuing_authority`).
- `validFrom` and `validUntil` come from the mdoc's validity information.
- `credentialSubject.driversLicense` holds the `org.iso.18013.5.1` data
  elements under their own names. Elements the vDL context does not define,
  such as `biometric_template_*`, are left out.
- `org.iso.18013.5.1.aamva` data elements are renamed to the AAMVA context
  terms: `aamva_` followed by the lowercase name, with `.` replaced by `_`
  (for example, `DHS_compliance` becomes `aamva_dhs_compliance` and
  `aka_family_name.v2` becomes `aamva_aka_family_name_v2`). Elements the
  context does not define are left out.
- Dates: the context types `birth_date`, `issue_date`, `expiry_date`,
  `portrait_capture_date` and `aamva_hazmat_endorsement_expiration_date` as
  `xsd:dateTime`, but the mdoc holds most of them as dates without a time. A
  date without a time is given as midnight UTC, for example
  `1990-01-01T00:00:00Z`; the time and zone are not part of the mdoc data.
  Dates inside `driving_privileges` and
  `aamva_domestic_driving_privileges`, which are JSON values, keep the
  `YYYY-MM-DD` form.
- `portrait` and `signature_usual_mark` are `data:` URLs, with the media type
  taken from the image data (`image/jpeg` or `image/jp2`).

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
