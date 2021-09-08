/*!
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const brRest = require('bedrock-rest');
const bodyParser = require('body-parser');
const cors = require('cors');
const {asyncHandler} = require('bedrock-express');
const {config, util: {BedrockError}} = bedrock;
const vc = require('@digitalbazaar/vc');
const {Ed25519Signature2020} = require('@digitalbazaar/ed25519-signature-2020');
const {Ed25519Signature2018} = require('@digitalbazaar/ed25519-signature-2018');
require('bedrock-credentials-context');
require('bedrock-vc-revocation-list-context');
require('bedrock-did-context');
require('bedrock-veres-one-context');
require('bedrock-security-context');
require('bedrock-did-io');

// load module config
require('./config');
const {serializeReport} = require('./utils');

const {checkStatus} = require('./status');

const {'vc-verifier': cfg} = config;
const {supportedSuites} = cfg;

const suite = [];
if(supportedSuites.includes('Ed25519Signature2018')) {
  suite.push(new Ed25519Signature2018());
}
if(supportedSuites.includes('Ed25519Signature2020')) {
  suite.push(new Ed25519Signature2020());
}
// must be loaded after the module config
const {documentLoader: _documentLoader} = require('./documentLoader');

// the _documentLoader is exported for use in the test suite
const api = {_documentLoader};
module.exports = api;

// FIXME: remove and apply at top-level application
bedrock.events.on('bedrock-express.configure.bodyParser', app => {
  app.use(bodyParser.json({limit: '32MB', type: ['json', '+json']}));
});

// add routes
bedrock.events.on('bedrock-express.configure.routes', addRoutes);

function addRoutes(app) {
  /**
   * /vc/verify
   */
  app.post(cfg.routes.verify, brRest.when.prefers.ld,
    asyncHandler(async (req, res) => {
      const {challenge, domain, presentation} = req.body;
      const _report = await vc.verify({
        documentLoader: _documentLoader,
        challenge,
        domain,
        suite,
        presentation,
        checkStatus
      });

      const report = serializeReport(_report);
      if(report.error === true) {
        return res.status(400).json(report);
      }
      res.json(report);
    }));

  // FIXME this is mock route that needs to be implemented.
  app.post(cfg.routes.verification, asyncHandler(async (req, res) => {
    // FIXME use verifierId & referenceId
    // eslint-disable-next-line no-unused-vars
    const {verifierId, referenceId} = req.params;
    // FIXME use these to actually verify
    const {
      // eslint-disable-next-line no-unused-vars
      options = {},
      // eslint-disable-next-line no-unused-vars
      credential,
      // eslint-disable-next-line no-unused-vars
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
        documentLoader: _documentLoader,
        suite,
        // only check credential status when option is set
        checkStatus: checks.includes('credentialStatus') ?
          checkStatus : () => ({verified: true})
      });
      response = _createResponse({credential, result, checks});
    } catch(e) {
      response = _createResponse({error: e});
    }

    if(response.verified) {
      res.status(200).json(response);
    } else {
      res.status(400).json(response).end();
    }
  }));

  app.options(
    ['/verifier/presentations', '/instances/:instanceId/presentations/verify'],
    cors()
  );
  /**
   * Verify Presentation
   *
   * @example
   * POST /instances/1234/presentations/verify
   * {
   *   "verifiablePresentation": {...},
   *   "options": {
   *     "challenge": "...",
   *     "checks": ["proof", "credentialStatus"],
   *     "domain": "issuer.example.com"
   *   }
   * }
   */
  app.post([
    '/verifier/presentations', '/instances/:instanceId/presentations/verify'
  ],
  cors(),
  asyncHandler(async (req, res) => {
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
      const unsignedPresentation = !checks.includes('proof');

      const verifyOptions = {
        challenge,
        presentation: verifiablePresentation,
        documentLoader: _documentLoader,
        suite,
        unsignedPresentation,
        checkStatus
      };
      if(verifiablePresentation.proof && verifiablePresentation.proof.domain) {
        verifyOptions.domain = domain || 'issuer.example.com';
      }
      const result = await vc.verify(verifyOptions);
      response = _createResponse({result, checks});
    } catch(e) {
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
}

function _createResponse({credential, result, error, checks}) {
  result = result || {verified: false, error};

  let response;
  if(result.verified) {
    result.checks = checks;
    response = {...result, checks};
  } else {
    // debugging purposes
    console.log('RESULT:', JSON.stringify(result, null, 2));

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
      if(!firstCredentialResult.error &&
        firstCredentialResult.statusResult &&
        !firstCredentialResult.statusResult.verified) {
        error = {message: 'The credential has been revoked.'};
      } else {
        error = firstCredentialResult.error;
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
