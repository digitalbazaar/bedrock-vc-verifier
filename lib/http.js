/*!
 * Copyright (c) 2018-2026 Digital Bazaar, Inc.
 */
import * as bedrock from '@bedrock/core';
import {applyReturnHint, resolveReturnHint} from './returnHints.js';
import {createChallenge, verifyChallenge} from './challenges.js';
import {
  createChallengeBody,
  verifyCredentialBody,
  verifyPresentationBody
} from '../schemas/bedrock-vc-verifier.js';
import {metering, middleware} from '@bedrock/service-core';
import {
  problemDetails, tagProblemType
} from './problemDetails.js';
import {verifyCredential, verifyPresentation} from './verify.js';
import {asyncHandler} from '@bedrock/express';
import cors from 'cors';
import {serializeError} from 'serialize-error';
import {createValidateMiddleware as validate} from '@bedrock/validation';

const {util: {BedrockError}} = bedrock;

// `options.responseFormat` selects the shape of a verify response:
// `vcalm-v0` (default) returns `checks` and an array of `results`, as this
// service has always done; `vcalm-v1` returns the VCALM
// VerifyCredentialResponse or VerifyPresentationResponse.
const RESPONSE_FORMAT_V0 = 'vcalm-v0';
const RESPONSE_FORMAT_V1 = 'vcalm-v1';
const SUPPORTED_RESPONSE_FORMATS = [RESPONSE_FORMAT_V0, RESPONSE_FORMAT_V1];

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
      let responseFormat = RESPONSE_FORMAT_V0;
      let returnCredential = false;
      try {
        const {
          options = {},
          verifiableCredential: credential
        } = req.body;

        // checked first so that every error below is shaped by the requested
        // format
        responseFormat = _getResponseFormat({options});
        returnCredential = options.returnCredential === true;
        const {checks} = options;
        _validateChecks({checks});
        const result = await verifyCredential({config, credential, checks});
        const {
          payload: returnedPayload, problemDetails: returnHintProblem
        } = await _getReturnedPayload({
          config, options, responseFormat, returnPayload: returnCredential,
          result, payload: credential, kind: 'credential'
        });
        response = _createResponse({
          credential, result, checks, responseFormat, returnCredential,
          returnedPayload, returnHintProblem
        });
      } catch(e) {
        response = _createResponse({
          error: e, responseFormat, returnCredential
        });
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
      let responseFormat = RESPONSE_FORMAT_V0;
      let returnPresentation = false;
      try {
        const {
          verifiablePresentation: presentation,
          options = {}
        } = req.body;

        responseFormat = _getResponseFormat({options});
        returnPresentation = options.returnPresentation === true;

        const {challenge, checks, domain} = options;
        if(!challenge) {
          throw tagProblemType(new BedrockError(
            '"options.challenge" is required.', {
              name: 'TypeError',
              details: {httpStatusCode: 400, public: true}
            }), 'MALFORMED_VALUE_ERROR');
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
        const {
          payload: returnedPayload, problemDetails: returnHintProblem
        } = await _getReturnedPayload({
          config, options, responseFormat, returnPayload: returnPresentation,
          result, payload: presentation, kind: 'presentation'
        });
        response = _createResponse({
          result, challengeUses, checks, responseFormat, returnPresentation,
          kind: 'presentation', returnedPayload, returnHintProblem
        });
      } catch(e) {
        response = _createResponse({
          error: e, responseFormat, returnPresentation, kind: 'presentation'
        });
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
  const {responseFormat = RESPONSE_FORMAT_V0} = options;
  if(!SUPPORTED_RESPONSE_FORMATS.includes(responseFormat)) {
    throw new BedrockError(
      '"options.responseFormat" must be "vcalm-v0" or "vcalm-v1".', {
        name: 'TypeError',
        details: {httpStatusCode: 400, public: true}
      });
  }
  return responseFormat;
}

// Get the payload a `vcalm-v1` response returns as `credential` or
// `verifiablePresentation`. A credential is returned in the form it was
// verified in when verification produced one (e.g., the decoded credential
// from a JWT or VCB envelope), otherwise as sent in the request. A
// presentation is the decoded presentation from a verified JWT payload (this
// includes `holder` from `iss`), otherwise as sent in the request.
function _getVcalmPayload({result, payload, kind}) {
  if(kind === 'credential') {
    return result.credential ?? payload;
  }
  const decoded = result.format?.typeAndSubType === 'application/jwt' ?
    result.presentation : undefined;
  return decoded ?? payload;
}

// Get the payload to return, with the return hint applied when one is set.
// The return hint applies only to a `vcalm-v1` response that returns the
// payload; otherwise it is ignored. An unknown hint or a failed mapping
// returns the payload unmapped, with a `problemDetails` entry saying why.
async function _getReturnedPayload({
  config, options, responseFormat, returnPayload, result, payload, kind
}) {
  payload = _getVcalmPayload({result, payload, kind});
  if(!(responseFormat === RESPONSE_FORMAT_V1 && returnPayload)) {
    return {payload};
  }
  const hint = resolveReturnHint({config, options});
  if(hint === undefined) {
    return {payload};
  }
  // an enveloped payload has its envelope media type; otherwise use the
  // VCDM 2.0 media type for the payload kind
  const mediaType = result.format?.typeAndSubType ??
    (kind === 'presentation' ? 'application/vp' : 'application/vc');
  return applyReturnHint({hint, payload, kind, mediaType});
}

// Build the VCALM `problemDetails` entry for a verify error. The first check
// error is used when there is one, as `errors[0]` is in the default response.
function _problemDetailsFor({error}) {
  const source = error.errors?.[0] ?? error;
  return problemDetails({
    problemType: source.details?.problemType ?? error.details?.problemType,
    detail: source.message ?? error.message
  });
}

// Map a verify response to the VCALM VerifyCredentialResponse. `results` is an
// object keyed by credential property (here, `proof`), and `checks` is not
// part of the VCALM response. `credential` is included when `response` has
// one; the credential route sets it only when the request sets
// `returnCredential`.
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
    vcalm.problemDetails = [_problemDetailsFor({error})];
  }
  return vcalm;
}

// Map a presentation verify response to the VCALM VerifyPresentationResponse.
// `verifiablePresentation` is the request's presentation and is returned only
// when the request sets `returnPresentation`. Each credential result is mapped
// with `_toVcalmResponse`.
function _toVcalmPresentationResponse({
  response, returnPresentation, presentation
}) {
  const {
    verified, presentationResult = {}, credentialResults = [], error
  } = response;
  const vcalm = {verified: verified === true};
  if(returnPresentation && presentation !== undefined) {
    vcalm.verifiablePresentation = presentation;
  }
  const results = {};
  const proofs = presentationResult.results ?? [];
  if(proofs.length > 0) {
    results.presentation = {
      proof: proofs.map(({verified, verificationMethod}) => ({
        verified: verified === true,
        ...(verificationMethod !== undefined && {verificationMethod})
      }))
    };
  }
  if(credentialResults.length > 0) {
    results.credentials = credentialResults.map(
      credential => _toVcalmResponse({response: credential}));
  }
  if(Object.keys(results).length > 0) {
    vcalm.results = results;
  }
  if(error) {
    vcalm.problemDetails = [_problemDetailsFor({error})];
  }
  return vcalm;
}

function _validateChecks({checks}) {
  if(!Array.isArray(checks)) {
    throw tagProblemType(new BedrockError(
      '"options.checks" must be an array.', {
        name: 'TypeError',
        details: {httpStatusCode: 400, public: true}
      }), 'MALFORMED_VALUE_ERROR');
  }
}

function _createResponse({
  credential, result, challengeUses, error, checks,
  responseFormat = RESPONSE_FORMAT_V0, returnCredential = false,
  returnPresentation = false, kind = 'credential', returnedPayload,
  returnHintProblem
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
            error = tagProblemType({
              message: 'A credential status could not be checked.',
              cause: cr.statusResult.error.message
            }, 'STATUS_VERIFICATION_ERROR');
          } else {
            // FIXME: include status type information here
            error = tagProblemType({
              message: 'A credential failed a status check.'
            }, 'STATUS_VERIFICATION_ERROR');
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

  if(responseFormat === RESPONSE_FORMAT_V0) {
    return response;
  }
  // `vcalm-v1`; the response shape follows the route, not the result, so that
  // errors from a presentation route are shaped as presentation responses;
  // `returnedPayload` is the payload from `_getReturnedPayload` (unset when
  // verification threw)
  let vcalm;
  if(kind === 'presentation') {
    vcalm = _toVcalmPresentationResponse({
      response, returnPresentation, presentation: returnedPayload
    });
  } else {
    // `credential` is returned only when the request sets `returnCredential`
    const returned = returnCredential ? returnedPayload : undefined;
    vcalm = _toVcalmResponse({response: {...response, credential: returned}});
  }
  if(returnHintProblem) {
    vcalm.problemDetails = [...vcalm.problemDetails ?? [], returnHintProblem];
  }
  return vcalm;
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
