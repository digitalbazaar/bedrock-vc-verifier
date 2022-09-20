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
const cryptosuites = [
  eddsa2022CryptoSuite
];

export function addSuites() {
  const suite = [];
  const cfg = bedrock.config['vc-verifier'];
  const {supportedSuites} = cfg;
  if(supportedSuites.includes('Ed25519Signature2018')) {
    suite.push(new Ed25519Signature2018());
  }
  if(supportedSuites.includes('Ed25519Signature2020')) {
    suite.push(new Ed25519Signature2020());
  }
  if(supportedSuites.includes('eddsa-2022')) {
    for(const cryptosuite of cryptosuites) {
      suite.push(new DataIntegrityProof({cryptosuite}));
    }
  }
  return suite;
}
