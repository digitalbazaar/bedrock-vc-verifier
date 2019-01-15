/*
 * Copyright (c) 2016-2019 Digital Bazaar, Inc. All rights reserved.
 */
const bedrock = require('bedrock');
const {config: {constants}} = bedrock;
require('bedrock-vc-verifier');
require('bedrock-veres-one-context');

constants.VC_CONTEXT_V1_URL = 'https://w3id.org/vc/v1';
constants.CONTEXTS[constants.VC_CONTEXT_V1_URL] =
  require('./contexts/vc-v1.jsonld.json');

require('bedrock-test');
bedrock.start();
