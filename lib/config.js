/*!
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {config} = require('bedrock');

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
