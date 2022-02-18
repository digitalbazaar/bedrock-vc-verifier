/*!
 * Copyright (c) 2018-2022 Digital Bazaar, Inc. All rights reserved.
 */
import {generateChallenge, verifyChallenge} from './challenges.js';
import bedrock from 'bedrock';
import {asyncHandler} from 'bedrock-express';
import cors from 'cors';
import {
  createChallengeBody,
  verifyCredentialBody,
  verifyPresentationBody
} from '../schemas/bedrock-vc-verifer.js';
import {createContextDocumentLoader} from 'bedrock-service-context-store';
import {createValidateMiddleware as validate} from 'bedrock-validation';
import {metering, middleware} from 'bedrock-service-core';

const {util: {BedrockError}} = bedrock;

export async function addRoutes({app, service} = {}) {
  const {routePrefix, serviceType} = service;

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
    // FIXME: add middleware to switch between oauth2 / zcap based on headers
    middleware.authorizeConfigZcapInvocation(),
    asyncHandler(async (req, res) => {
      const {config} = req.serviceObject;
      const challenge = await generateChallenge({config});
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
    // FIXME: add middleware to switch between oauth2 / zcap based on headers
    middleware.authorizeConfigZcapInvocation(),
    asyncHandler(async (req, res) => {
      const {config} = req.serviceObject;
      const documentLoader = await createContextDocumentLoader(
        {config, serviceType});

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
   * Verify Presentation
   *
   * @example
   * POST /verifiers/z1234/presentations/verify
   * {
   *   "verifiablePresentation": {...},
   *   "options": {
   *     "challenge": "...",
   *     "checks": ["proof", "credentialStatus"],
   *     "domain": "issuer.example.com"
   *   }
   * }
   */
  app.post(
    routes.presentationsVerify,
    cors(),
    validate({bodySchema: verifyPresentationBody}),
    getConfigMiddleware,
    // FIXME: add middleware to switch between oauth2 / zcap based on headers
    middleware.authorizeConfigZcapInvocation(),
    asyncHandler(async (req, res) => {
      const {config} = req.serviceObject;
      const documentLoader = await createContextDocumentLoader(
        {config, serviceType});

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
        const {verified, error} = await verifyChallenge({config, challenge});
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

function _createResponse({credential, result, error, checks}) {
  result = result || {verified: false, error};

  let response;
  if(result.verified) {
    result.checks = checks;
    response = {...result, checks};
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
        check: checks,
        id: credential && credential.id,
        error: message,
        verificationMethod
      }]
    };
  }
  return response;
}
