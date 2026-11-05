/*!
 * Copyright (c) 2018-2026 Digital Bazaar, Inc.
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
import cors from 'cors';
import {serializeError} from 'serialize-error';
import {createValidateMiddleware as validate} from '@bedrock/validation';

const {util: {BedrockError}} = bedrock;

// `options.responseFormat` selects the shape of a verify response:
// `vc-api` (default) keeps the existing response; `vcalm` returns the VCALM
// VerifyCredentialResponse.
const RESPONSE_FORMAT_VC_API = 'vc-api';
const RESPONSE_FORMAT_VCALM = 'vcalm';

// URL prefixes for the problem types defined by the W3C specs
const PROBLEM_TYPE_PREFIXES = {
  // VC Data Model 2.0
  PARSING_ERROR: 'https://www.w3.org/TR/vc-data-model#',
  MALFORMED_VALUE_ERROR: 'https://www.w3.org/TR/vc-data-model#',
  CRYPTOGRAPHIC_SECURITY_ERROR: 'https://www.w3.org/TR/vc-data-model#',
  RANGE_ERROR: 'https://www.w3.org/TR/vc-data-model#',
  // Data Integrity
  PROOF_VERIFICATION_ERROR: 'https://w3id.org/security#',
  INVALID_DOMAIN_ERROR: 'https://w3id.org/security#',
  INVALID_CHALLENGE_ERROR: 'https://w3id.org/security#',
  // Bitstring Status List
  STATUS_VERIFICATION_ERROR: 'https://www.w3.org/ns/credentials/status-list#',
  // DID Resolution
  NOT_FOUND: 'https://www.w3.org/ns/did#'
};

// Classify a verification error by its message. Errors are not tagged at their
// source yet, so this is a best-effort match on the message text.
function _problemName({detail = ''}) {
  if(/domain/i.test(detail)) {
    return 'INVALID_DOMAIN_ERROR';
  }
  if(/challenge/i.test(detail)) {
    return 'INVALID_CHALLENGE_ERROR';
  }
  if(/status/i.test(detail)) {
    return 'STATUS_VERIFICATION_ERROR';
  }
  if(/\bDID\b.*(not found|resolv)/i.test(detail)) {
    return 'NOT_FOUND';
  }
  if(/parse|JSON/i.test(detail)) {
    return 'PARSING_ERROR';
  }
  // proof and signature failures, and any other verification failure
  return 'PROOF_VERIFICATION_ERROR';
}

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
      let responseFormat = RESPONSE_FORMAT_VC_API;
      try {
        const {
          options = {},
          verifiableCredential: credential
        } = req.body;

        const {checks} = options;
        _validateChecks({checks});
        responseFormat = _getResponseFormat({options});
        const result = await verifyCredential({config, credential, checks});
        response = _createResponse({
          credential, result, checks, responseFormat
        });
      } catch(e) {
        response = _createResponse({error: e, responseFormat});
      }

      if(response.verified) {
        res.status(200).json(response);
      } else {
        res.status(400).json(response);
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
          config, presentation, challenge, domain: expectedDomain, checks,
          options
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

function _getResponseFormat({options}) {
  const {responseFormat = RESPONSE_FORMAT_VC_API} = options;
  if(responseFormat !== RESPONSE_FORMAT_VC_API &&
    responseFormat !== RESPONSE_FORMAT_VCALM) {
    throw new BedrockError(
      '"options.responseFormat" must be "vc-api" or "vcalm".', 'TypeError', {
        httpStatusCode: 400,
        public: true
      });
  }
  return responseFormat;
}

// Map a verify response to the VCALM VerifyCredentialResponse. `results` is an
// object keyed by credential property (here, `proof`), and `checks` is not
// part of the VCALM response.
function _toVcalmResponse({response}) {
  const {verified, credential, results = [], error} = response;
  const vcalm = {verified: verified === true};
  if(credential !== undefined) {
    vcalm.credential = credential;
  }
  if(results.length > 0) {
    vcalm.results = {
      proof: results.map(({verified, verificationMethod}) => ({
        verified: verified === true,
        ...(verificationMethod !== undefined && {verificationMethod})
      }))
    };
  }
  if(error) {
    // use the first check error when there is one, as `errors[0]` does in the
    // default response
    const detail = error.errors?.[0]?.message ?? error.message;
    const name = _problemName({detail});
    vcalm.problemDetails = [{
      type: `${PROBLEM_TYPE_PREFIXES[name]}${name}`,
      title: name,
      detail
    }];
  }
  return vcalm;
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

function _createResponse({
  credential, result, challengeUses, error, checks,
  responseFormat = RESPONSE_FORMAT_VC_API
}) {
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
      const credentialResults = result.credentialResults ?? [result];
      for(const cr of credentialResults) {
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
            // FIXME: include status type information here
            error = {
              message: 'A credential failed a status check.'
            };
          }
          break;
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
  if(responseFormat === RESPONSE_FORMAT_VCALM) {
    return _toVcalmResponse({response});
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
