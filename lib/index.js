/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const brRest = require('bedrock-rest');
const bodyParser = require('body-parser');
const cors = require('cors');
const jsigs = require('jsonld-signatures');
const {asyncHandler} = require('bedrock-express');
const {config, util: {BedrockError}} = bedrock;
const vc = require('vc-js');
require('bedrock-credentials-context');
require('bedrock-vc-revocation-list-context');
require('bedrock-did-context');
require('bedrock-veres-one-context');

const {
  suites: {Ed25519Signature2018},
} = jsigs;
// load module config
require('./config');
const {serializeReport} = require('./utils');

const {checkStatus} = require('./status');

const {'vc-verifier': cfg} = config;

// must be loaded after the module config
const loader = require('./documentLoader');

const api = {loader};
module.exports = api;

// FIXME: remove and apply at top-level application
bedrock.events.on('bedrock-express.configure.bodyParser', app => {
  app.use(bodyParser.json({limit: '32MB', type: ['json', '+json']}));
});

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
          checkStatus
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

  app.options('/verifier/credentials', cors());
  app.post('/verifier/credentials', cors(), asyncHandler(async (req, res) => {
    let response;
    try {
      const {
        options = {},
        verifiableCredential: credential,
      } = req.body;

      const {checks} = options;

      _validateChecks({checks});

      const result = await vc.verifyCredential({
        credential,
        documentLoader: loader.documentLoader,
        suite: new Ed25519Signature2018(),
        checkStatus
      });
      response = _createResponse({credential, result});
    } catch(e) {
      console.error('ERROR:', e);
      response = _createResponse({error: e});
    }

    if(response.verified) {
      res.status(200).json(response);
    } else {
      res.status(400).json(response).end();
    }
  }));

  app.options('/verifier/presentations', cors());
  app.post('/verifier/presentations', cors(), asyncHandler(async (req, res) => {
    let response;
    try {
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

      const verifyOptions = {
        challenge,
        presentation: verifiablePresentation,
        documentLoader: loader.documentLoader,
        suite: new Ed25519Signature2018(),
        checkStatus
      };
      if(verifiablePresentation.proof.domain) {
        verifyOptions.domain = domain || 'issuer.example.com';
      }
      const result = await vc.verify(verifyOptions);
      response = _createResponse({result});
    } catch(e) {
      console.error('ERROR:', e);
      response = _createResponse({error: e});
    }

    if(response.verified) {
      res.status(200).json(response);
    } else {
      res.status(400).json(response);
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

function _createResponse({credential, result, error}) {
  result = result || {verified: false, error};

  let response;
  if(result.verified) {
    result.checks = ['proof'];
    response = {...result, checks: ['proof']};
  } else {
    // debugging purposes
    console.log('RESULT:', result);

    // get verification method for presentation/credential
    let verificationMethod;
    const results = result.results ||
      (result.presentationResult && result.presentationResult.results);
    if(results && results.length > 0) {
      const [{proof}] = results;
      ({verificationMethod} = proof);
    }

    if(!result.error) {
      // try to get error from credential results
      const firstCredentialResult = (result.presentationResult &&
        result.credentialResults && result.credentialResults[0]) ||
        result;
      if(firstCredentialResult) {
        if(!firstCredentialResult.error &&
          firstCredentialResult.statusResult &&
          !firstCredentialResult.statusResult.verified) {
          error = {message: 'The credential has been revoked.'};
        } else {
          error = firstCredentialResult.error;
        }
      }
      error = error || {message: 'Verification error.'};
    } else {
      error = result.error;
      if(!error.message) {
        error.message = 'Verification error.';
      }
    }

    let message = error.message;
    if(error.errors && error.errors.length > 0) {
      message = error.errors[0].message;
    }
    response = {
      ...result,
      verified: false,
      error,
      checks: [{
        check: 'proof',
        id: credential && credential.id,
        error: message,
        verificationMethod
      }]
    };
  }
  return response;
}
