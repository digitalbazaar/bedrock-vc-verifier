/*!
 * Copyright (c) 2018-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as vc from '@digitalbazaar/vc';
import {createChallenge, verifyChallenge} from './challenges.js';
import {
  createChallengeBody,
  verifyCredentialBody,
  verifyPresentationBody
} from '../schemas/bedrock-vc-verifier.js';
import {metering, middleware} from '@bedrock/service-core';
import {addSuites} from './suites.js';
import {asyncHandler} from '@bedrock/express';
import bodyParser from 'body-parser';
import {checkStatus} from './status.js';
import cors from 'cors';
import {createDocumentLoader} from './documentLoader.js';
import {createValidateMiddleware as validate} from '@bedrock/validation';

const {util: {BedrockError}} = bedrock;

// FIXME: remove and apply at top-level application
bedrock.events.on('bedrock-express.configure.bodyParser', app => {
  app.use(bodyParser.json({limit: '10MB', type: ['json', '+json']}));
});

export async function addRoutes({app, service} = {}) {
  const {routePrefix} = service;
  const suite = addSuites();
  const cfg = bedrock.config['vc-verifier'];
  const baseUrl = `${routePrefix}/:localId`;
  const routes = {
    challenges: `${baseUrl}${cfg.routes.challenges}`,
    credentialsVerify: `${baseUrl}${cfg.routes.credentialsVerify}`,
    presentationsVerify: `${baseUrl}${cfg.routes.presentationsVerify}`
  };

  const getConfigMiddleware = middleware.createGetConfigMiddleware({service});

  /* Note: CORS is used on all endpoints. This is safe because authorization
  uses HTTP signatures + capabilities or OAuth2, not cookies; CSRF is not
  possible. */

  // create a challenge
  app.options(routes.challenges, cors());
  app.post(
    routes.challenges,
    cors(),
    validate({bodySchema: createChallengeBody}),
    getConfigMiddleware,
    middleware.authorizeServiceObjectRequest(),
    asyncHandler(async (req, res) => {
      const {config} = req.serviceObject;
      const challenge = await createChallenge({verifierId: config.id});
      res.json({challenge});

      // meter operation usage
      metering.reportOperationUsage({req});
    }));

  // verify a credential
  app.options(routes.credentialsVerify, cors());
  app.post(
    routes.credentialsVerify,
    cors(),
    validate({bodySchema: verifyCredentialBody}),
    getConfigMiddleware,
    middleware.authorizeServiceObjectRequest(),
    asyncHandler(async (req, res) => {
      const {config} = req.serviceObject;
      const documentLoader = await createDocumentLoader({config});

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
          documentLoader,
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

      // meter operation usage
      metering.reportOperationUsage({req});
    }));

  // verify a presentation
  app.options(routes.presentationsVerify, cors());
  /**
   * Verifies a Verifiable Presentation.
   *
   * POST /verifiers/z1234/presentations/verify
   * {
   *   "verifiablePresentation": {...},
   *   "options": {
   *     "challenge": "...",
   *     "checks": ["proof", "credentialStatus"],
   *     "domain": "issuer.example.com"
   *   }
   * }.
   */
  app.post(
    routes.presentationsVerify,
    cors(),
    validate({bodySchema: verifyPresentationBody}),
    getConfigMiddleware,
    middleware.authorizeServiceObjectRequest(),
    asyncHandler(async (req, res) => {
      const {config} = req.serviceObject;
      const documentLoader = await createDocumentLoader({config});

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

        // FIXME: allow for `checks` to request whether or not the challenge
        // should be checked; for now, default to checking it

        // first, check the challenge
        const {verified, uses: challengeUses, error} = await verifyChallenge(
          {challenge, verifierId: config.id});
        if(!verified) {
          throw error;
        }

        const verifyOptions = {
          challenge,
          presentation: verifiablePresentation,
          documentLoader,
          suite,
          unsignedPresentation,
          checkStatus
        };
        const {proof} = verifiablePresentation;
        if(proof && proof.domain) {
          // FIXME: do not set a default
          verifyOptions.domain = domain || 'issuer.example.com';
        }
        const result = await vc.verify(verifyOptions);
        response = _createResponse({result, challengeUses, checks});
      } catch(e) {
        response = _createResponse({error: e});
      }

      if(response.verified) {
        res.status(200).json(response);
      } else {
        res.status(400).json(response);
      }

      // meter operation usage
      metering.reportOperationUsage({req});
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

function _createResponse({credential, result, challengeUses, error, checks}) {
  result = result || {verified: false, error};

  let response;
  if(result.verified) {
    result.checks = checks;
    response = {...result, challengeUses, checks};
  } else {
    // debugging purposes
    // console.log('RESULT:', JSON.stringify(result, null, 2));

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
        if(firstCredentialResult.statusResult.error) {
          error = {
            message: 'The credential status could not be checked.',
            cause: firstCredentialResult.statusResult.error.message
          };
        } else {
          // FIXME: surface status type information so it can be included here
          error = {
            message: 'The credential failed a status check.'
          };
        }
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
        check: checks,
        id: credential && credential.id,
        error: message,
        verificationMethod
      }]
    };
  }
  return response;
}
