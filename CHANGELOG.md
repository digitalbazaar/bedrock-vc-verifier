# bedrock-vc-verifier ChangeLog

## 6.0.0 - 2022-04-xx

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
