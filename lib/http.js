/*!
 * Copyright (c) 2018-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {createChallenge, verifyChallenge} from './challenges.js';
import {
  createChallengeBody,
  verifyCredentialBody,
  verifyPresentationBody
} from '../schemas/bedrock-vc-verifier.js';
import {metering, middleware} from '@bedrock/service-core';
import {verifyCredential, verifyPresentation} from './verify.js';
import {asyncHandler} from '@bedrock/express';
import bodyParser from 'body-parser';
import cors from 'cors';
import {serializeError} from 'serialize-error';
import {createValidateMiddleware as validate} from '@bedrock/validation';

const {util: {BedrockError}} = bedrock;

// FIXME: remove and apply at top-level application
bedrock.events.on('bedrock-express.configure.bodyParser', app => {
  app.use(bodyParser.json({
    // allow json that is not just arrays or objects
    strict: false,
    limit: '10MB',
    type: ['json', '+json']
  }));
});

export async function addRoutes({app, service} = {}) {
  const {routePrefix} = service;
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
    validate({bodySchema: verifyCredentialBody()}),
    getConfigMiddleware,
    middleware.authorizeServiceObjectRequest(),
    asyncHandler(async (req, res) => {
      const {config} = req.serviceObject;

      let response;
      try {
        const {
          options = {},
          verifiableCredential: credential,
        } = req.body;

        const {checks} = options;
        _validateChecks({checks});
        const result = await verifyCredential({config, credential, checks});
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
    validate({bodySchema: verifyPresentationBody()}),
    getConfigMiddleware,
    middleware.authorizeServiceObjectRequest(),
    asyncHandler(async (req, res) => {
      const {config} = req.serviceObject;

      let response;
      try {
        const {
          verifiablePresentation: presentation,
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

        // allow for `checks` to indicate whether or not the challenge
        // should be checked
        let challengeUses;
        if(checks.includes('challenge')) {
          // first, check the challenge
          const result = await verifyChallenge(
            {challenge, verifierId: config.id});
          const {verified, error} = result;
          if(!verified) {
            throw error;
          }
          ({uses: challengeUses} = result);
        }

        // FIXME: do not set a default domain
        const expectedDomain = domain ??
          (presentation?.proof?.domain && 'issuer.example.com');
        const result = await verifyPresentation({
          config, presentation, challenge, domain: expectedDomain, checks
        });
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
      for(const r of results) {
        // ensure error is serializable
        if(r.error) {
          r.error = _serializeError({error: r.error});
        }
      }
      const [{proof}] = results;
      if(proof) {
        ({verificationMethod} = proof);
      }
    }

    if(result.error) {
      // ensure error is serializable
      error = result.error = _serializeError({error: result.error});
    } else {
      // try to get error from credential results
      if(result.credentialResults) {
        for(const cr of result.credentialResults) {
          if(cr.error) {
            error = cr.error;
            break;
          }
          if(cr.statusResult?.verified === false) {
            if(cr.statusResult.error) {
              error = {
                message: 'A credential status could not be checked.',
                cause: cr.statusResult.error.message
              };
            } else {
              // FIXME: surface status type information so it can be included
              // here
              error = {
                message: 'A credential failed a status check.'
              };
            }
            break;
          }
        }
      }
      error = error || {message: 'Verification error.'};
      // ensure error is serializable
      error = _serializeError({error});
    }

    let message = error.message;
    if(error.errors?.length > 0) {
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

function _serializeError({error}) {
  // ensure error is serializable; do not include stack
  error = serializeError(error);
  if(!error.name || error.name === 'Error') {
    error.name = 'VerificationError';
  }
  if(!error.message) {
    error.message = 'Verification error.';
  }
  delete error.stack;
  return error;
}
