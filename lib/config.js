/*!
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {Ed25519VerificationKey2018} =
  require('@digitalbazaar/ed25519-verification-key-2018');

const {config} = require('bedrock');

// bedrock-did-io configuration
// This will cause the did-method-key did-io driver to resolve DID Documents
// and keys using the 2018/2019 suites (for backwards compatibility)
config['did-io'].methods.key.verificationSuite = Ed25519VerificationKey2018;

const cfg = config['vc-verifier'] = {};

// document loader configuration for the verifier
cfg.documentLoader = {};

// document loading mode options:
//   local - do not fetch documents from the network
//   web - fetch documents from the global Web
cfg.documentLoader.mode = 'web';

cfg.supportedSuites = ['Ed25519Signature2018', 'Ed25519Signature2020'];

cfg.routes = {
  verify: '/vc/verify',
  context: '/verifiers/:verifierId/contexts',
  challenges: '/verifiers/:verifierId/challenges',
  verification: '/verifiers/:verifierId/verifications/:referenceId'
};
