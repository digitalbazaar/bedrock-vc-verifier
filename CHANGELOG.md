# bedrock-vc-verifier ChangeLog

## 2.0.0 - 2021-03-TBD

### Changed
- **BREAKING**: Remove `axios` and use `@digitalbazaar/http-client@1.1.0`.
- Rename `vc-js` to `@digitalbazaar/vc`.
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
