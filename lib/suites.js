/*!
 * Copyright (c) 2018-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import {Ed25519Signature2018} from '@digitalbazaar/ed25519-signature-2018';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {
  cryptosuite as eddsa2022CryptoSuite
} from '@digitalbazaar/eddsa-2022-cryptosuite';

// DataIntegriyProof should work for multiple cryptosuites
const SUPPORTED_CRYPTOSUITES = new Map([
  ['eddsa-2022', eddsa2022CryptoSuite]
]);

const SUPPORTED_LEGACY_SUITES = new Map([
  ['Ed25519Signature2018', Ed25519Signature2018],
  ['Ed25519Signature2020', Ed25519Signature2020]
]);

export function createSuites() {
  const cfg = bedrock.config['vc-verifier'];
  const {supportedSuites} = cfg;
  const suite = supportedSuites.map(supportedSuite => {
    const LegacySuite = SUPPORTED_LEGACY_SUITES.get(supportedSuite);
    if(LegacySuite) {
      return new LegacySuite();
    }
    const cryptosuite = SUPPORTED_CRYPTOSUITES.get(supportedSuite);
    if(cryptosuite) {
      return new DataIntegrityProof({cryptosuite});
    }
    throw new Error(`Unsupported suite ${supportedSuite}`);
  });
  return suite;
}
