# bedrock-vc-verifier ChangeLog

## 22.1.2 - 2025-04-14

### Fixed
- Fix processing of unprotected VPs that contain enveloped verifiable
  credentials.

## 22.1.1 - 2025-04-14

### Fixed
- Fix processing of base64-encoded `qr_code` VCBs.

## 22.1.0 - 2025-04-10

### Added
- Add support for `ecdsa-xi-2023` cryptosuite.
- Add support for verifying VCBs:
  - VCB must be expressed as an `EnvelopedVerifiableCredential`.
  - Vanilla QR VCBs can be verified; no support yet for QR VCBs with extra
    information.
  - PDF417 VCBs that include an AAMVA DL or ID card can be verified,
    including with extra information.
    - Only PDF417s issued using either the test vector/invalid issuer
      identifier number `000000` or the by the US state of CA `636014`.

## 22.0.0 - 2025-03-18

### Changed
- Update dependencies.
  - `@digitalbazaar/data-integrity@2.5.0`.
  - `@digitalbazaar/ecdsa-multikey@1.8.0`.
  - `@digitalbazaar/ecdsa-rdfc-2019-cryptosuite@1.2.0`.
  - `@digitalbazaar/ed25519-multikey@1.3.1`.
  - `@digitalbazaar/ed25519-signature-2018@4.1.0`.
  - `@digitalbazaar/eddsa-rdfc-2022-cryptosuite@1.2.0`.
  - `@digitalbazaar/vc@7.1.2`.
  - `@digitalbazaar/vc-bitstring-status-list@2.0.1`.
  - `@digitalbazaar/vc-status-list@8.0.1`.
  - `body-parser@1.20.3`.
  - `jose@6.0.10`.
  - `serialize-error@12.0.0`.
- Update peer dependencies.
  - `@bedrock/core@6.3.0`.
  - `@bedrock/credentials-context@5.0.3`.
  - `@bedrock/did-io@10.4.0`.
  - `@bedrock/jsonld-document-loader@5.2.0`.
  - **BREAKING**: `@bedrock/mongodb@11`.
    - Use MongoDB driver 6.x and update error names and details.
    - See changelog for details.
  - **BREAKING**: `@bedrock/service-agent@10`.
    - Updated for `@bedrock/mongodb@11`.
  - **BREAKING**: `@bedrock/service-context-store@13`.
    - Updated for `@bedrock/mongodb@11`.
  - **BREAKING**: `@bedrock/service-core@11`.
    - Updated for `@bedrock/mongodb@11`.
  - `@bedrock/validation@7.1.1`.
- Update dev dependencies.
- Update test dependencies.

## 21.2.3 - 2025-03-04

### Fixed
- Do not pass `writeOptions` in database calls.
- Pass `includeResultMetadata: true` to `findOneAndUpdate` to ensure meta data
  is always returned.

## 21.2.2 - 2025-03-04

### Fixed
- Remove unused `background` option from mongodb index creation.

## 21.2.1 - 2025-03-03

### Fixed
- Return passed `record` instead of resulting record from mongodb calls to
  enable using newer mongodb driver.

## 21.2.0 - 2024-11-08

### Added
- Add support for verifying vcs with `ecdsa-jcs-2019` and `eddsa-jcs-2022`
  signatures.

## 21.1.0 - 2024-11-07

### Added
- Support checking `BitstringStatusList` credential status checks.

## 21.0.3 - 2024-08-26

### Fixed
- Use latest cryptosuite dependencies to get bug fixes.

## 21.0.2 - 2024-08-26

### Fixed
- Use `@digitalbazaar/ecdsa-rdfc-2019@1.1.1` to get P-384 proof fix.

## 21.0.1 - 2024-08-24

### Fixed
- Throw better error if JWT verification method cannot be retrieved
  from `kid` URL.
- Improve verification method controller check error.

## 21.0.0 - 2024-08-19

### Changed
- **BREAKING**: Use `@digitalbazaar/bbs-2023-cryptosuite@2` to get
  interoperability with the latest IETF BBS draft 6. Previous BBS proofs are
  no longer compatible and should be considered obsolete.

## 20.1.2 - 2024-08-08

### Fixed
- Fix in-place modification (creates a clone instead) of VC/VP properties
  when decoding VC-JWTs.

## 20.1.1 - 2024-08-08

### Fixed
- Ensure a DI-protected VP that contains at least one enveloped VC can be
  verified.

## 20.1.0 - 2024-08-07

### Added
- Add feature to verify VC-JWT-enveloped credentials and presentations. These
  credentials and presentations must be sent using an VC 2.x
  `EnvelopedVerifiableCredential` or `EnvelopedVerifiablePresentation` to the
  appropriate VC API endpoint. For presentations, any VCs inside the
  presentation can be provided using `EnvelopedVerifiableCredential` or, if a
  the `EnvelopedVerifiablePresentation` envelopes a 1.1 VP, the VCs can
  be expressed directly as strings to allow for interoperability with
  VC-JWT 1.1.

## 20.0.0 - 2024-08-02

### Added
- Add support for using a configured external DID resolver.
- Add support for `did:web` DIDs via `@bedrock/did-io@10.3`.
- Add support for `documentLoader` options when configuring a
  verifier instance, with an option for disabling remote context loading.

### Changed
- **BREAKING**: Update peer dependencies.
  - `@bedrock/core@6.1.3`
  - `@bedrock/credentials-context@5.0.2`
  - `@bedrock/data-integrity-context@4.0.3`
  - `@bedrock/did-context@6.0.0`
  - `@bedrock/express@8.3.1`
  - `@bedrock/https-agent@4.1.0`
  - `@bedrock/jsonld-document-loader@5.1.0`
  - `@bedrock/mongodb@10.2.0`
  - `@bedrock/multikey-context@3.0.0`
  - `@bedrock/security-context@9.0.0`
  - `@bedrock/service-agent@9.0.2`
  - `@bedrock/service-context-store@12.0.0`
  - `@bedrock/service-core@10.0.0`
  - `@bedrock/validation@7.1.0`
  - `@bedrock/vc-revocation-list-context@5.0.0`
  - `@bedrock/vc-status-list-context@6.0.2`
  - `@bedrock/veres-one-context@16.0.0`
- Update to `@digitalbazaar/vc@7`.
  - Adds VC 2.0 support.
- Update minor, test, and dev dependencies.

## 19.1.0 - 2024-01-25

### Changed
- Use `@bedrock/did-io@10.2` to enable resolution of BBS-based `did:key` DIDs.

## 19.0.0 - 2023-11-14

### Added
- Add support for verifying vcs with `ecdsa-sd-2023`, `ecdsa-rdfc-2019` and
  `eddsa-rdfc-2022` signatures.
- Add missing peer dep `@bedrock/app-identity` v4.0.

### Changed
- **BREAKING**: Update `@bedrock/data-integrity-context` peer dep to v3.0 that
  uses `@digitalbazaar/data-integrity@2.0`.
- Use `@digitalbazaar/data-integrity@2.0`. Adds `legacyContext` flag to allow
  use of legacy context and updates default context URL to
  `https://w3id.org/security/data-integrity/v2`.

## 18.1.0 - 2023-11-06

### Added
- Add support for verifying signatures that use the `ECDSA P-384` key type.

## 18.0.0 - 2023-09-21

### Changed
- Use `@digitalbazaar/vc@6`.
- **BREAKING**: Update peer deps:
  - Use `@bedrock/credentials-context@4`. This version requires Node.js 18+.
  - Use `@bedrock/data-integrity-context@2`. This version requires Node.js 18+.
  - Use `@bedrock/did-context@5`. This version requires Node.js 18+.
  - Use `@bedrock/jsonld-document-loader@4`. This version requires Node.js 18+.
  - Use `@bedrock/multikey-context@2`. This version requires Node.js 18+.
  - Use `@bedrock/security-context@8`. This version requires Node.js 18+.
  - Use `@bedrock/service-agent@8`. This version requires Node.js 18+.
  - Use `@bedrock/service-context-store@11`. This version requires Node.js 18+.
  - Use `@bedrock/service-core@9`. This version requires Node.js 18+.
  - Use `@bedrock/vc-revocation-list-context@4`. This version requires
    Node.js 18+.
  - Use `@bedrock/vc-status-list-context@5`. This version requires Node.js 18+.
  - Use `@bedrock/veres-one-context@15`. This version requires Node.js 18+.
- Update test deps.

## 17.0.0 - 2023-08-16

### Changed
- **BREAKING**: Drop support for Node.js 16.

## 16.0.1 - 2023-04-18

### Fixed
- Fixed mismatched/incompatible peerdeps. Updated to:
  - Update `@bedrock/service-agent` to v7.0.
  - Update `@bedrock/service-context-store` to v10.0.
  - Update `@bedrock/service-core` to v8.0.

## 16.0.0 - 2023-04-14

### Added
- Add `ecdsa-2019` to supported suites.

### Changed
- **BREAKING**: Update peerdep `@bedrock/did-io` to v10.0.

## 15.0.0 - 2023-01-08

### Changed
- **BREAKING**: Use little-endian bit order for all bitstrings with revocation
  and status lists. This change is incompatible with previous deployments.

## 14.1.0 - 2022-12-17

### Added
- Ensure verification errors, such as expired credential errors, are
  serializable.

## 14.0.0 - 2022-11-03

### Changed
- **BREAKING**: Only check challenge reuse (using verifier-based challenge
  management) when `challenge` is set in `checks`.

## 13.0.1 - 2022-10-25

### Fixed
- Update `@digitalbazaar/ed25519-signature-*` and `@digitalbazaar/vc*`
  dependencies.

## 13.0.0 - 2022-10-23

### Changed
- **BREAKING**: Update peer deps:
  - `@bedrock/service-context-store@9`
  - `@bedrock/service-core@7`.
- **BREAKING**: See `@bedrock/service-core@7` for important config changes
  and new peer dependency `@bedrock/oauth2-verifier@1`.

## 12.3.0 - 2022-10-10

### Changed
- Allow json `req.body` to be more than just objects or arrays.

## 12.2.0 - 2022-09-21

### Added
- Add support for eddsa-2022 cryptosuite.
- Add support for DataIntegrityProof.

## 12.1.0 - 2022-07-17

### Added
- Add support for oauth2-authorized verifier instances.

## 12.0.0 - 2022-06-30

### Changed
- **BREAKING**: Require Node.js >=16.
- **BREAKING**: Update dependenices.
  - `@digitalbazaar/vc@4`: `expirationDate` now checked.
- **BREAKING**: Update peer dependencies.
  - `@bedrock/did-io@9`
  - `@bedrock/service-agent@6`
  - `@bedrock/service-context-store@8`
  - `@bedrock/service-core@6`
- Use `package.json` `files` field.
- Lint module.

## 11.0.0 - 2022-06-05

### Changed
- **BREAKING** Use `@digitalbazaar/vc-status-list` v4.0.  If `statusPurpose`
  in credential does not match the `statusPurpose` of status list credential,
  an error will be thrown.

## 10.0.0 - 2022-05-17

### Changed
- **BREAKING**: Use `@bedrock-service-context-store@7` to cause migration of
  old EDV context documents to the new EDV attribute version.

## 9.0.0 - 2022-05-05

### Changed
- **BREAKING**: Update peer deps:
  - `@bedrock/service-agent@5`
  - `@bedrock/service-context-store@6`.
- **BREAKING**: The updated peer dependencies use a new EDV client with a
  new blind attribute version. This version is incompatible with previous
  versions and a manual migration must be performed to update all
  EDV documents to use the new blind attribute version -- or a new
  deployment is required.

## 8.0.0 - 2022-04-29

### Changed
- **BREAKING**: Update peer deps:
  - `@bedrock/core@6`
  - `@bedrock/credentials-context@3`
  - `@bedrock/did-context@4`
  - `@bedrock/did-io@8`
  - `@bedrock/express@8`
  - `@bedrock/https-agent@4`
  - `@bedrock/jsonld-document-loader@3`
  - `@bedrock/mongodb@10`
  - `@bedrock/security-context@7`
  - `@bedrock/service-agent@4`
  - `@bedrock/service-context-store@5`
  - `@bedrock/service-core@5`
  - `@bedrock/validation@7`
  - `@bedrock/vc-status-list-context@3`
  - `@bedrock/vc-revocation-list-context@3`
  - `@bedrock/veres-one-context@14`.

## 7.0.0 - 2022-04-23

### Changed
- **BREAKING**: Update `@digitalbazaar/vc-status-list` and
  `@bedrock/vc-status-list-context` to v3.0.

## 6.0.0 - 2022-04-06

### Changed
- **BREAKING**: Rename package to `@bedrock/vc-verifier`.
- **BREAKING**: Convert to module (ESM).
- **BREAKING**: Remove default export.
- **BREAKING**: Require node 14.x.

## 5.2.0 - 2022-03-14

### Added
- Add missing dependencies `@digitalbazaar/webkms-client@10.0` and
  `@digitalbazaar/edv-client@13.0` in test.
- Add coverage action in github workflows.

### Removed
- Remove unused dependency `crypto-ld@6.0`.
- Remove unused dependencies `veres-one-context`, `did-veres-one`, `crypto-ld`,
  `did-context` and `bedrock-views` from test.

## 5.1.0 - 2022-03-12

### Changed
- Update dependencies:
  - `@digitalbazaar/vc-status-list@2.1`.

## 5.0.0 - 2022-03-11

### Changed
- **BREAKING**: Update peer dependencies:
  - `bedrock-service-core@3`
  - `bedrock-service-context-store@3`
  - `bedrock-did-io@6.1`.

## 4.0.0 - 2022-03-01

### Changed
- **BREAKING**: Move zcap revocations to `/zcaps/revocations` to better
  future proof.
- **BREAKING**: Require `bedrock-service-core@2`, `bedrock-service-agent@2`,
  and `bedrock-service-context-store@2` peer dependencies.

## 3.1.0 - 2022-02-23

### Added
- Add default (dev mode) `app-identity` entry for `vc-verifier` service.

## 3.0.1 - 2022-02-21

### Changed
- Use `@digitalbazaar/vc-status-list-context` and updated bedrock-vc-status-list-context.
  These dependencies have no changes other than moved package locations.

## 3.0.0 - 2022-02-20

### Changed
- **BREAKING**: Complete refactor to run on top of `bedrock-service*` modules. While
  this version has similar functionality, its APIs and implementation are a clean
  break from previous versions.

## 2.3.0 - 2022-02-15

### Changed
- Refactor documentLoader.

## 2.2.0 - 2022-02-09

### Added
- Add support for "StatusList2021Credential" status checks using
  `vc-status-list@1.0`
- Add tests.

## 2.1.0 - 2021-09-14

### Added
- Add support for unsigned VPs.

## 2.0.2 - 2021-08-23

### Changed
- Update deps to fix multicodec bugs and set `verificationSuite` for `v1` to
  `Ed25519VerificationKey2020` in config.

## 2.0.1 - 2021-05-28

### Fixed
- Fix bedrock peer dependencies.

## 2.0.0 - 2021-05-28

### Changed
- **BREAKING**: Remove `axios` and use `@digitalbazaar/http-client@1.1.0`.
  Errors surfaced from `http-client` do not have the same signature as `axios`.
- **BREAKING**: Remove `cfg.ledgerHostname` and `cfg.mode` from `config.js`.
- **BREAKING**: Use [vc-revocation-list@3](https://github.com/digitalbazaar/vc-revocation-list/blob/main/CHANGELOG.md).
  Revocation list credentials must have the same issuer value as the credential
  to be revoked.
- **BREAKING**: Use [bedrock-did-io@3.0](https://github.com/digitalbazaar/bedrock-did-io/blob/main/CHANGELOG.md).
- Replace `vc-js` with `@digitalbazaar/vc`.
- Update to support ed25519 2020 signature suite.
- Update peerDeps and testDeps.

## 1.2.0 - 2021-03-03

### Fixed

- Only verify based on `options.checks`.

## 1.1.0 - 2020-05-18

### Added

- Implement W3C CCG VC Verification HTTP API.

## 1.0.0 - 2020-02-27

### Added
  - API endpoint /vc/verify which can verify a presentation.
  - Mock API endpoint /verifiers/:verifierId/verifications/:referenceId
  - Positive tests for both endpoints.
  - Utils to serialize errors in verification reports.
