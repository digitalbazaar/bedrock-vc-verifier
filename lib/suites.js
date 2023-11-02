/*!
 * Copyright (c) 2018-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import {
  cryptosuite as ecdsa2019CryptoSuite
} from '@digitalbazaar/ecdsa-2019-cryptosuite';
import {Ed25519Signature2018} from '@digitalbazaar/ed25519-signature-2018';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {
  cryptosuite as eddsa2022CryptoSuite
} from '@digitalbazaar/eddsa-2022-cryptosuite';

// DataIntegrityProof should work for multiple cryptosuites
const SUPPORTED_CRYPTOSUITES = new Map([
  ['ecdsa-2019', ecdsa2019CryptoSuite],
  ['eddsa-2022', eddsa2022CryptoSuite]
]);

const SUPPORTED_LEGACY_SUITES = new Map([
  ['Ed25519Signature2018', Ed25519Signature2018],
  ['Ed25519Signature2020', Ed25519Signature2020]
]);

export function createSuites({algorithm} = {}) {
  const cfg = bedrock.config['vc-verifier'];
  const {supportedSuites} = cfg;
  const suites = [];
  for(const supportedSuite of supportedSuites) {
    const LegacySuite = SUPPORTED_LEGACY_SUITES.get(supportedSuite);
    if(LegacySuite) {
      suites.push(new LegacySuite());
      continue;
    }
    const cryptosuite = SUPPORTED_CRYPTOSUITES.get(supportedSuite);
    if(cryptosuite) {
      if(supportedSuite === 'ecdsa-2019') {
        const suiteConfig = {...cryptosuite};
        if(algorithm) {
          suiteConfig.requiredAlgorithm = algorithm;
        }
        suites.push(new DataIntegrityProof({cryptosuite: suiteConfig}));
      } else {
        suites.push(new DataIntegrityProof({cryptosuite}));
      }
    } else {
      throw new Error(`Unsupported suite ${supportedSuite}`);
    }
  }
  return suites;
}
