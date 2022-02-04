# bedrock-vc-verifier ChangeLog

## 2.2.0 - 2022-TBD

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
