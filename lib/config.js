/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {config} = require('bedrock');

const cfg = config['vc-verifier'] = {};

// FIXME: if ledgerHostname is not defined, no effort will be made to load
// a DID from a ledger, only local document loaders will be used
// this needs further consideration wrt how to indicate support for various
// ledgers

// must be set explicitly e.g. `myledger.example.com`
cfg.ledgerHostname = null;

// dev || production
cfg.mode = 'dev';

// document loader configuration for the verifier
cfg.documentLoader = {};

// document loading mode options:
//   local - do not fetch documents from the network
//   web - fetch documents from the global Web
cfg.documentLoader.mode = 'web';

cfg.routes = {
  verify: '/vc/verify',
  context: '/verifiers/:verifierId/contexts',
  challenges: '/verifiers/:verifierId/challenges',
  verification: '/verifiers/:verifierId/verifications/:referenceId'
};
