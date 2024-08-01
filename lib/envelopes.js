/*
 * Copyright (c) 2019-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey';
import * as Ed25519Multikey from '@digitalbazaar/ed25519-multikey';
import {importJWK, jwtVerify} from 'jose';
import {didIo} from '@bedrock/did-io';

const {util: {BedrockError}} = bedrock;

// supported JWT algs
const ECDSA_ALGS = ['ES256', 'ES384'];
const EDDSA_ALGS = ['Ed25519', 'EdDSA'];

export async function verifyEnvelopedCredential({envelopedCredential} = {}) {
  try {
    const {contents: jwt} = _parseEnvelope({
      envelope: envelopedCredential
    });
    const {
      verified, controller, verificationMethod, verifyResult
    } = await _verifyJwt({
      jwt, proofPurpose: 'assertionMethod'
    });
    // if verified, parse credential from payload...
    let credential;
    if(verified) {
      // FIXME: perform extra VC-JWT checks
      credential = verifyResult.payload.vc;
      // FIXME: validate credential
      //throw new BedrockError()...
    }
    const results = [{
      verified,
      verificationMethod,
      controller,
      verifyResult,
      credential
    }];
    return {verified, controller, results, credential};
  } catch(error) {
    return {verified: false, error};
  }
}

export async function verifyEnvelopedPresentation({
  envelopedPresentation
} = {}) {
  try {
    const {contents: jwt} = _parseEnvelope({
      envelope: envelopedPresentation
    });
    const {verified, controller, verifyResult} = await _verifyJwt({
      jwt, proofPurpose: 'authentication'
    });
    // if verified, parse presentation from payload...
    let presentation;
    if(verified) {
      // FIXME: perform extra VC-JWT checks
      presentation = verifyResult.payload.vp;
      // FIXME: validate presentation
      //throw new BedrockError()...
      // FIXME: verify each VC (which can be DI or enveloped)
    }
    return {verified, controller, verifyResult, presentation};
  } catch(error) {
    return {verified: false, error};
  }
}

function _parseEnvelope({envelope}) {
  const {id} = envelope;
  let format;
  const comma = id.indexOf(',');
  if(id.startsWith('data:') && comma !== -1) {
    format = id.slice('data:'.length, comma);
  }
  if(format !== 'application/jwt') {
    throw new BedrockError(
      `Unknown envelope format "${format}".`, {
        name: 'DataError',
        details: {
          httpStatusCode: 400,
          public: true
        },
      });
  }
  return {contents: id.slice(comma + 1), format};
}

async function _verifyJwt({jwt, proofPurpose} = {}) {
  let verificationMethod;
  let controller;
  // `resolveKey` is passed `protectedHeader`
  const resolveKey = async ({alg, kid}) => {
    const isEcdsa = ECDSA_ALGS.includes(alg);
    const isEddsa = !isEcdsa && EDDSA_ALGS.includes(alg);
    if(!(isEcdsa || isEddsa)) {
      throw new BedrockError(
        `Unsupported JWT "alg": "${alg}".`, {
          name: 'DataError',
          details: {
            httpStatusCode: 400,
            public: true
          }
        });
    }

    const vm = await didIo.get({url: kid});
    // `vm.controller` must be the issuer of the JWT; also ensure that
    // the specified controller authorized `vm` for the given proof purpose
    ({controller} = vm);
    verificationMethod = vm;
    const didDoc = await didIo.get({url: controller});
    let match = didDoc?.authentication?.find?.(
      e => e === vm.id || e.id === vm.id);
    if(typeof match === 'string') {
      match = didDoc?.verificationMethod?.find?.(e => e.id === vm.id);
    }
    if(!(match && Array.isArray(match.controller) ?
      match.controller.includes(vm.controller) :
      match.controller === vm.controller)) {
      throw new BedrockError(
        `Verification method controller "${controller}" did not authorize ` +
        `verification method "${vm.id}" for the purpose ` +
        `of "${proofPurpose}".`, {
          name: 'DataError',
          details: {
            httpStatusCode: 400,
            public: true
          }
        });
    }
    let jwk;
    if(isEcdsa) {
      const keyPair = await EcdsaMultikey.from(vm);
      jwk = await EcdsaMultikey.toJwk({keyPair});
      jwk.alg = alg;
    } else {
      const keyPair = await Ed25519Multikey.from(vm);
      jwk = await Ed25519Multikey.toJwk({keyPair});
      jwk.alg = 'EdDSA';
    }
    return importJWK(jwk);
  };

  // FIXME: enable allowed algorithms to be configurable per instance
  const allowedAlgorithms = ['EdDSA', 'Ed25519', 'ES256', 'ES256K', 'ES384'];
  // FIXME: enable `maxClockSkew` to be configurable per instance
  // default is 300 secs
  const maxClockSkew = 300;

  // use `jose` lib (for now) to verify JWT and return `payload`;
  // pass optional supported algorithms as allow list ... note
  // that `jose` *always* prohibits the `none` algorithm
  let verifyResult;
  try {
    // `jwtVerify` checks claims: `aud`, `exp`, `nbf`
    const {payload, protectedHeader} = await jwtVerify(jwt, resolveKey, {
      algorithms: allowedAlgorithms,
      clockTolerance: maxClockSkew
    });
    verifyResult = {payload, protectedHeader};
  } catch(e) {
    const details = {
      httpStatusCode: 403,
      public: true,
      code: e.code,
      reason: e.message
    };
    if(e.claim) {
      details.claim = e.claim;
    }
    throw new BedrockError('JWT validation failed.', {
      name: 'DataError',
      details
    });
  }

  // check `iss` claim
  if(!(controller && verifyResult?.payload?.iss === controller)) {
    throw new BedrockError('JWT validation failed.', {
      name: 'DataError',
      details: {
        httpStatusCode: 400,
        public: true,
        code: 'ERR_JWT_CLAIM_VALIDATION_FAILED',
        reason: 'unexpected "iss" claim value.',
        claim: 'iss'
      }
    });
  }

  return {verified: true, verificationMethod, controller, verifyResult};
}
