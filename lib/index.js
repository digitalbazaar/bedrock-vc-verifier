/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const brRest = require('bedrock-rest');
const jsigs = require('jsonld-signatures');
const {asyncHandler} = require('bedrock-express');
const {config, util: {BedrockError}} = bedrock;
const vc = require('vc-js');
require('bedrock-credentials-context');

const {
  suites: {Ed25519Signature2018},
} = jsigs;
// load module config
require('./config');
const {serializeReport} = require('./utils');

const {'vc-verifier': cfg} = config;

// must be loaded after the module config
const loader = require('./documentLoader');

const api = {loader};
module.exports = api;

// add routes
bedrock.events.on('bedrock-express.configure.routes', addRoutes);

function addRoutes(app) {
  app.post(cfg.routes.verify, brRest.when.prefers.ld,
    asyncHandler(async (req, res) => {
      const {challenge, domain, presentation} = req.body;
      let _report;
      try {
        _report = await vc.verify({
          documentLoader: loader.documentLoader,
          challenge,
          domain,
          suite: new Ed25519Signature2018(),
          presentation,
        });
      } catch(e) {
        console.log('VC.VERIFY ERROR', e);
        throw e;
      }
      const report = serializeReport(_report);
      if(report.error === true) {
        return res.status(400).json(report);
      }
      res.json(report);
    }));
  // FIXME this is mock route that needs to be implemented.
  app.post(cfg.routes.verification, asyncHandler(async (req, res) => {
    // FIXME use verifierId & referenceId
    const {verifierId, referenceId} = req.params;
    // FIXME use these to actually verify
    const {
      options = {},
      credential,
      presentation
    } = req.body;
    res.json({verified: true});
  }));

  app.post('/verifier/credentials', asyncHandler(async (req, res) => {
    const {
      options = {},
      verifiableCredential: credential,
    } = req.body;

    const {checks} = options;

    _validateChecks({checks});

    try {
      const result = await vc.verifyCredential({
        credential,
        documentLoader: loader.documentLoader,
        suite: new Ed25519Signature2018(),
      });
      result.checks = ['proof'];
      if(!result.verified) {
        console.log('RESULT:', result);
        throw new BedrockError(
          'Verification Error.',
          'NotAllowedError', {httpStatusCode: 400, public: true});
      }
      res.status(200).json(result);
    } catch(e) {
      console.error('ERROR:', e);
      res.status(400).json({error: e.name, checks: ['proof']});
    }
  }));

  app.post('/verifier/presentations', asyncHandler(async (req, res) => {
    const {
      verifiablePresentation,
      options = {}
    } = req.body;

    const {challenge, checks, domain} = options;
    if(!challenge) {
      throw new BedrockError(
        '"options.challenge" is required.', 'TypeError', {
          httpStatusCode: 400,
          public: true
        });
    }

    _validateChecks({checks});

    try {
      const options = {
        challenge,
        presentation: verifiablePresentation,
        documentLoader: loader.documentLoader,
        suite: new Ed25519Signature2018(),
      };
      if(verifiablePresentation.proof.domain) {
        options.domain = domain || 'issuer.example.com'
      }
      const result = await vc.verify(options);

      result.checks = ['proof'];
      if(!result.verified) {
        console.log('RESULT:', result);
        throw new BedrockError(
          'Verification Error.',
          'NotAllowedError', {httpStatusCode: 400, public: true, cause: result.error});
      }
      res.status(200).json(result);
    } catch(e) {
      console.error('ERROR:', e);
      res.status(400).json({error: e.name, checks: ['proof']});
    }
  }));
}

function _validateChecks({checks}) {
  if(!Array.isArray(checks)) {
    throw new BedrockError(
      '"options.checks" must be an array.', 'TypeError', {
        httpStatusCode: 400,
        public: true
      });
  }
  if(!checks.includes('proof')) {
    throw new BedrockError(
      '"options.checks" must include the string "proof".', 'TypeError', {
        httpStatusCode: 400,
        public: true
      });
  }
}
