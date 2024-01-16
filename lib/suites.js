/*!
 * Copyright (c) 2018-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {
  createVerifyCryptosuite as createBbs2023VerifyCryptosuite
} from '@digitalbazaar/bbs-2023-cryptosuite';
import {
  createVerifyCryptosuite as createEcdsaSd2023VerifyCryptosuite
} from '@digitalbazaar/ecdsa-sd-2023-cryptosuite';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import {
  cryptosuite as ecdsa2019CryptoSuite
} from '@digitalbazaar/ecdsa-2019-cryptosuite';
import {
  cryptosuite as ecdsaRdfc2019CryptoSuite
} from '@digitalbazaar/ecdsa-rdfc-2019-cryptosuite';
import {Ed25519Signature2018} from '@digitalbazaar/ed25519-signature-2018';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {
  cryptosuite as eddsa2022CryptoSuite
} from '@digitalbazaar/eddsa-2022-cryptosuite';
import {
  cryptosuite as eddsaRdfc2022CryptoSuite
} from '@digitalbazaar/eddsa-rdfc-2022-cryptosuite';

// DataIntegrityProof should work for multiple cryptosuites
const SUPPORTED_CRYPTOSUITES = new Map([
  ['bbs-2023', createBbs2023VerifyCryptosuite()],
  ['ecdsa-rdfc-2019', ecdsaRdfc2019CryptoSuite],
  ['eddsa-rdfc-2022', eddsaRdfc2022CryptoSuite],
  ['ecdsa-sd-2023', createEcdsaSd2023VerifyCryptosuite()]
]);

const SUPPORTED_LEGACY_CRYPTOSUITES = new Map([
  ['ecdsa-2019', ecdsa2019CryptoSuite],
  ['eddsa-2022', eddsa2022CryptoSuite],
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
    const LegacyCryptosuite = SUPPORTED_LEGACY_CRYPTOSUITES.get(supportedSuite);
    if(LegacyCryptosuite) {
      return new DataIntegrityProof({
        cryptosuite: LegacyCryptosuite, legacyContext: true
      });
    }
    const cryptosuite = SUPPORTED_CRYPTOSUITES.get(supportedSuite);
    if(cryptosuite) {
      return new DataIntegrityProof({cryptosuite});
    }
    throw new Error(`Unsupported suite ${supportedSuite}`);
  });
  return suite;
}
