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

const VC_CONTEXT_1 = 'https://www.w3.org/2018/credentials/v1';
const VC_CONTEXT_2 = 'https://www.w3.org/ns/credentials/v2';

export async function verifyEnvelopedCredential({jwt} = {}) {
  try {
    const {
      verified, controller, verificationMethod, verifyResult
    } = await _verifyJwt({jwt, proofPurpose: 'assertionMethod'});
    // if verified, parse credential from payload...
    let credential;
    if(verified) {
      credential = _jwtPayloadToCredential({verifyResult});
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
  jwt, challenge, domain
} = {}) {
  try {
    const {
      verified, controller, verificationMethod, verifyResult
    } = await _verifyJwt({
      jwt, proofPurpose: 'authentication', audience: domain
    });
    // if verified, parse presentation from payload...
    let presentation;
    if(verified) {
      presentation = _jwtPayloadToPresentation({
        verifyResult, challenge
      });
    }
    const results = [{
      verified,
      verificationMethod,
      controller,
      verifyResult,
      presentation
    }];
    return {verified, controller, results, presentation};
  } catch(error) {
    return {verified: false, error};
  }
}

async function _verifyJwt({jwt, proofPurpose, audience} = {}) {
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
    if(!vm) {
      throw new BedrockError(
        `Verification method identified by "kid" (${kid}) could not be ` +
        'retrieved.', {
          name: 'DataError',
          details: {
            public: true,
            httpStatusCode: 400
          }
        });
    }

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
      clockTolerance: maxClockSkew,
      audience
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

function _jwtPayloadToCredential({verifyResult} = {}) {
  /* Example:
  {
    "alg": <signer.algorithm>,
    "kid": <signer.id>
  }.
  {
    "iss": <verifiableCredential.issuer>,
    "jti": <verifiableCredential.id>
    "sub": <verifiableCredential.credentialSubject>
    "nbf": <verifiableCredential.[issuanceDate | validFrom]>
    "exp": <verifiableCredential.[expirationDate | validUntil]>
    "vc": <verifiableCredential>
  }
  */
  const {vc} = verifyResult.payload;
  if(!(vc && typeof vc === 'object')) {
    throw new BedrockError('JWT validation failed.', {
      name: 'DataError',
      details: {
        httpStatusCode: 400,
        public: true,
        code: 'ERR_JWT_CLAIM_VALIDATION_FAILED',
        reason: 'missing or unexpected "vc" claim value.',
        claim: 'vc'
      }
    });
  }

  let {'@context': context = []} = vc;
  if(!Array.isArray(context)) {
    context = [context];
  }
  const isVersion1 = context.includes(VC_CONTEXT_1);
  const isVersion2 = context.includes(VC_CONTEXT_2);
  if(!(isVersion1 ^ isVersion2)) {
    throw new BedrockError(
      'Verifiable credential is neither version "1.x" nor "2.x".', {
        name: 'DataError',
        details: {
          httpStatusCode: 400,
          public: true
        }
      });
  }

  const credential = {...vc};
  const {iss, jti, sub, nbf, exp} = verifyResult.payload;

  // inject `issuer` value
  if(vc.issuer === undefined) {
    vc.issuer = iss;
  } else if(vc.issuer && typeof vc.issuer === 'object' &&
    vc.issuer.id === undefined) {
    vc.issuer.id = {id: iss, ...vc.issuer};
  } else if(iss !== vc.issuer && iss !== vc.issuer?.id) {
    throw new BedrockError(
      'VC-JWT "iss" claim does not equal nor does it exclusively ' +
      'provide verifiable credential "issuer" / "issuer.id".', {
        name: 'DataError',
        details: {
          httpStatusCode: 400,
          public: true
        }
      });
  }

  if(jti !== undefined && jti !== vc.id) {
    // inject `id` value
    if(vc.id === undefined) {
      vc.id = jti;
    } else {
      throw new BedrockError(
        'VC-JWT "jti" claim does not equal nor does it exclusively ' +
        'provide verifiable credential "id".', {
          name: 'DataError',
          details: {
            httpStatusCode: 400,
            public: true
          }
        });
    }
  }

  if(sub !== undefined && sub !== vc.credentialSubject?.id) {
    // inject `credentialSubject.id` value
    if(!vc.credentialSubject) {
      throw new BedrockError(
        'Verifiable credential has no "credentialSubject".', {
          name: 'DataError',
          details: {
            httpStatusCode: 400,
            public: true
          }
        });
    }
    if(Array.isArray(vc.credentialSubject)) {
      throw new BedrockError(
        'Verifiable credential has multiple credential subjects, which is ' +
        'not supported in VC-JWT.', {
          name: 'DataError',
          details: {
            httpStatusCode: 400,
            public: true
          }
        });
    }
    if(vc.credentialSubject?.id === undefined) {
      vc.credentialSubject = {id: sub, ...vc.credentialSubject};
    } else {
      throw new BedrockError(
        'VC-JWT "sub" claim does not equal nor does it exclusively ' +
        'provide verifiable credential "credentialSubject.id".', {
          name: 'DataError',
          details: {
            httpStatusCode: 400,
            public: true
          }
        });
    }
  }

  if(nbf === undefined && isVersion1) {
    throw new BedrockError('JWT validation failed.', {
      name: 'DataError',
      details: {
        httpStatusCode: 400,
        public: true,
        code: 'ERR_JWT_CLAIM_VALIDATION_FAILED',
        reason: 'missing "nbf" claim value.',
        claim: 'nbf'
      }
    });
  }

  if(nbf !== undefined) {
    // fuzzy convert `nbf` into `issuanceDate` / `validFrom`, only require
    // second-level precision
    const dateString = new Date(nbf * 1000).toISOString().slice(0, -5);
    const dateProperty = isVersion1 ? 'issuanceDate' : 'validFrom';
    // inject dateProperty value
    if(vc[dateProperty] === undefined) {
      vc[dateProperty] = dateString + 'Z';
    } else if(!(vc[dateProperty].startsWith(dateString) &&
      vc[dateProperty].endsWith('Z'))) {
      throw new BedrockError(
        'VC-JWT "nbf" claim does not equal nor does it exclusively provide ' +
        `verifiable credential "${dateProperty}".`, {
          name: 'DataError',
          details: {
            httpStatusCode: 400,
            public: true
          }
        });
    }
  }

  if(exp !== undefined) {
    // fuzzy convert `exp` into `expirationDate` / `validUntil`, only require
    // second-level precision
    const dateString = new Date(exp * 1000).toISOString().slice(0, -5);
    const dateProperty = isVersion1 ? 'expirationDate' : 'validUntil';
    // inject dateProperty value
    if(vc[dateProperty] === undefined) {
      vc[dateProperty] = dateString + 'Z';
    } else if(!(vc[dateProperty].startsWith(dateString) &&
      vc[dateProperty].endsWith('Z'))) {
      throw new BedrockError(
        'VC-JWT "exp" claim does not equal nor does it exclusively provide ' +
        `verifiable credential "${dateProperty}".`, {
          name: 'DataError',
          details: {
            httpStatusCode: 400,
            public: true
          }
        });
    }
  }

  return credential;
}

function _jwtPayloadToPresentation({verifyResult, challenge} = {}) {
  /* Example:
  {
    "alg": <signer.algorithm>,
    "kid": <signer.id>
  }.
  {
    "iss": <verifiablePresentation.holder>,
    "aud": <verifiablePresentation.domain>,
    "nonce": <verifiablePresentation.nonce>,
    "jti": <verifiablePresentation.id>
    "nbf": <verifiablePresentation.[validFrom]>
    "exp": <verifiablePresentation.[validUntil]>
    "vp": <verifiablePresentation>
  }
  */
  const {vp} = verifyResult.payload;
  if(!(vp && typeof vp === 'object')) {
    throw new BedrockError('JWT validation failed.', {
      name: 'DataError',
      details: {
        httpStatusCode: 400,
        public: true,
        code: 'ERR_JWT_CLAIM_VALIDATION_FAILED',
        reason: 'missing or unexpected "vp" claim value.',
        claim: 'vp'
      }
    });
  }

  let {'@context': context = []} = vp;
  if(!Array.isArray(context)) {
    context = [context];
  }
  const isVersion1 = context.includes(VC_CONTEXT_1);
  const isVersion2 = context.includes(VC_CONTEXT_2);
  if(!(isVersion1 ^ isVersion2)) {
    throw new BedrockError(
      'Verifiable presentation is not either version "1.x" or "2.x".', {
        name: 'DataError',
        details: {
          httpStatusCode: 400,
          public: true
        }
      });
  }

  const presentation = {...vp};
  const {iss, nonce, jti, nbf, exp} = verifyResult.payload;

  // inject `holder` value
  if(vp.holder === undefined) {
    vp.holder = iss;
  } else if(vp.holder && typeof vp.holder === 'object' &&
    vp.holder.id === undefined) {
    vp.holder.id = {id: iss, ...vp.holder};
  } else if(iss !== vp.holder && iss !== vp.holder?.id) {
    throw new BedrockError(
      'VC-JWT "iss" claim does not equal nor does it exclusively ' +
      'provide verifiable presentation "holder" / "holder.id".', {
        name: 'DataError',
        details: {
          httpStatusCode: 400,
          public: true
        }
      });
  }

  if(jti !== undefined && jti !== vp.id) {
    // inject `id` value
    if(vp.id === undefined) {
      vp.id = jti;
    } else {
      throw new BedrockError(
        'VC-JWT "jti" claim does not equal nor does it exclusively ' +
        'provide verifiable presentation "id".', {
          name: 'DataError',
          details: {
            httpStatusCode: 400,
            public: true
          }
        });
    }
  }

  // version 1.x VPs do not support `validFrom`/`validUntil`
  if(nbf !== undefined && isVersion2) {
    // fuzzy convert `nbf` into `validFrom`, only require
    // second-level precision
    const dateString = new Date(nbf * 1000).toISOString().slice(0, -5);

    // inject `validFrom` value
    if(vp.validFrom === undefined) {
      vp.validFrom = dateString + 'Z';
    } else if(!(vp.validFrom?.startsWith(dateString) &&
      vp.validFrom.endsWith('Z'))) {
      throw new BedrockError(
        'VC-JWT "nbf" claim does not equal nor does it exclusively provide ' +
        'verifiable presentation "validFrom".', {
          name: 'DataError',
          details: {
            httpStatusCode: 400,
            public: true
          }
        });
    }
  }
  if(exp !== undefined && isVersion2) {
    // fuzzy convert `exp` into `validUntil`, only require
    // second-level precision
    const dateString = new Date(exp * 1000).toISOString().slice(0, -5);

    // inject `validUntil` value
    if(vp.validUntil === undefined) {
      vp.validUntil = dateString + 'Z';
    } else if(!(vp.validUntil?.startsWith(dateString) &&
      vp.validUntil?.endsWith('Z'))) {
      throw new BedrockError(
        'VC-JWT "exp" claim does not equal nor does it exclusively provide ' +
        'verifiable presentation "validUntil".', {
          name: 'DataError',
          details: {
            httpStatusCode: 400,
            public: true
          }
        });
    }
  }

  if(challenge !== undefined && nonce !== challenge) {
    throw new BedrockError('JWT validation failed.', {
      name: 'DataError',
      details: {
        httpStatusCode: 400,
        public: true,
        code: 'ERR_JWT_CLAIM_VALIDATION_FAILED',
        reason: 'missing or unexpected "nonce" claim value.',
        claim: 'nonce'
      }
    });
  }

  // do some validation on `verifiableCredential`
  let {verifiableCredential = []} = presentation;
  if(!Array.isArray(verifiableCredential)) {
    verifiableCredential = [verifiableCredential];
  }

  // ensure version 2 VPs only have objects in `verifiableCredential`
  const hasVCJWTs = verifiableCredential.some(vc => typeof vc !== 'object');
  if(isVersion2 && hasVCJWTs) {
    throw new BedrockError(
      'Version 2.x verifiable presentations must only use objects in the ' +
      '"verifiableCredential" field.', {
        name: 'DataError',
        details: {
          httpStatusCode: 400,
          public: true
        }
      });
  }

  // transform any VC-JWT VCs to enveloped VCs
  if(presentation.verifiableCredential && hasVCJWTs) {
    presentation.verifiableCredential = verifiableCredential.map(vc => {
      if(typeof vc !== 'string') {
        return vc;
      }
      return {
        '@context': VC_CONTEXT_2,
        id: `data:application/jwt,${vc}`,
        type: 'EnvelopedVerifiableCredential',
      };
    });
  }

  return presentation;
}
