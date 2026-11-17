/*!
 * Copyright (c) 2018-2026 Digital Bazaar, Inc.
 */
import * as di from './di.js';
import {
  verifyEnvelopedCredential, verifyEnvelopedPresentation
} from './envelopes.js';
import {checkHolderBinding} from './holderBinding.js';

export async function verifyCredential({
  config, credential, checks, presentationOptions
} = {}) {
  if(credential?.type !== 'EnvelopedVerifiableCredential') {
    return di.verifyCredential({config, credential, checks});
  }

  const result = await verifyEnvelopedCredential({
    config, envelopedCredential: credential, checks, presentationOptions
  });

  // if credential envelope is verified, credential has a `proof` field, and
  // format is JWT, do DI verification
  let {verified} = result;
  if(verified && result.credential.proof &&
    result.format.typeAndSubType === 'application/jwt') {
    const proofResult = await di.verifyCredential({
      config, credential: result.credential, checks
    });
    result.proofResult = proofResult;
    verified = verified && proofResult.verified;
  }
  return {...result, verified};
}

async function _verifyPresentation({
  config, presentation, challenge, domain, checks, options
} = {}) {
  if(presentation?.type !== 'EnvelopedVerifiablePresentation') {
    const result = await di.verifyPresentation({
      config, presentation, challenge, domain, checks
    });
    // if the whole VP and all its VCs were verified or if the VP itself
    // was checked and it failed verification, there is no extra work to be
    // done and we can return early; it is important to note that the
    // presence of `presentationResult` must be confirmed here to ensure that
    // if an unprotected presentation was used and this was allowed, the VC
    // checks will continue below
    if(result.verified || result.presentationResult?.verified === false) {
      return result;
    }

    // note that the presentation itself verified, but the VCs therein might
    // not because some of them might be enveloped VCs and the underlying
    // `vc` library doesn't support this; therefore only use the presentation
    // result and let the code below check VCs to ensure any enveloped VCs
    // will also be checked
    let {verifiableCredential = []} = presentation;
    if(!Array.isArray(verifiableCredential)) {
      verifiableCredential = [verifiableCredential];
    }
    const hasEnvelopedCredential = verifiableCredential.some(
      vc => vc?.type === 'EnvelopedVerifiableCredential');
    if(!hasEnvelopedCredential) {
      // no enveloped VCs, return result
      return result;
    }

    // try to verify each VC in the VP again but with envelope support
    const presentationOptions = {presentation, challenge, domain, options};
    const credentialResults = await Promise.all(verifiableCredential.map(
      credential => verifyCredential({
        config, credential, checks, presentationOptions
      })));
    const verified = credentialResults.every(({verified}) => verified);
    if(verified) {
      result.verified = true;
    }
    result.credentialResults = credentialResults;
    return result;
  }

  const presentationResult = await verifyEnvelopedPresentation({
    config, envelopedPresentation: presentation, challenge, domain, checks,
    options
  });
  // verify each `verifiableCredential` in the resulting VP, unless the VP
  // format was mDL, which means there will always be one VC (an enveloped mDL)
  // and it will already have been verified
  let verified = presentationResult.verified;
  let credentialResults;
  if(!verified) {
    credentialResults = [];
  } else if(
    presentationResult.format.typeAndSubType === 'application/mdl-vp-token') {
    let {verifiableCredential} = presentationResult.presentation;
    if(Array.isArray(verifiableCredential)) {
      verifiableCredential = verifiableCredential[0];
    }
    credentialResults = [{
      verified: true,
      credential: verifiableCredential,
      format: {
        mediaType: 'application/mdl',
        typeAndSubType: 'application/mdl',
        type: 'application',
        subType: 'mdl',
        parameters: {}
      }
    }];
  } else if(presentationResult.presentation?.proof &&
    presentationResult.format.typeAndSubType === 'application/jwt') {
    // presentation in the envelope has a `proof` and envelope format is JWT,
    // so recurse to check `proof` field
    const proofResult = await _verifyPresentation({
      config, presentation: presentationResult.presentation,
      challenge, domain, checks, options
    });
    verified = !!(verified && proofResult.presentationResult?.verified);
    presentationResult.proofResult = proofResult;
    ({credentialResults} = proofResult);
  } else {
    // verify each VC in the VP
    let {verifiableCredential = []} = presentationResult.presentation;
    if(!Array.isArray(verifiableCredential)) {
      verifiableCredential = [verifiableCredential];
    }
    credentialResults = await Promise.all(verifiableCredential.map(
      credential => verifyCredential({config, credential, checks})));
    verified = verified && credentialResults.every(
      ({verified}) => verified);
  }
  return {
    ...presentationResult,
    verified,
    presentationResult,
    credentialResults
  };
}

export async function verifyPresentation({
  config, presentation, challenge, domain, checks, options
} = {}) {
  const result = await _verifyPresentation({
    config, presentation, challenge, domain, checks, options
  });
  if(!(result.verified && checks?.includes('holderBinding'))) {
    return result;
  }
  const inputs = _holderBindingInputs({presentation, result});
  if(inputs.skip) {
    return result;
  }
  const holderBindingResult = checkHolderBinding(inputs);
  if(!holderBindingResult.verified) {
    return {
      ...result,
      verified: false,
      error: holderBindingResult.error,
      holderBindingResult
    };
  }
  return {...result, holderBindingResult};
}

// Returns the verified presentation signer and the verified credentials. The
// holder is taken from signature verification, never from a self-asserted
// `holder` property: for an enveloped VP it is the `controller` of the key
// that signed the envelope (for a VP-JWT, checked to equal `iss`); for a DI
// VP it is the controller of the proof's verification method.
function _holderBindingInputs({presentation, result}) {
  // an mDL VP binds the holder via device authentication
  if(result.format?.typeAndSubType === 'application/mdl-vp-token') {
    return {skip: true};
  }
  let holder;
  let verifiableCredential;
  if(presentation?.type === 'EnvelopedVerifiablePresentation') {
    const presentationResult = result.presentationResult ?? result;
    holder = presentationResult.controller;
    ({verifiableCredential} = presentationResult.presentation ?? {});
  } else {
    const [proofResult] = result.presentationResult?.results ?? [];
    holder = proofResult?.purposeResult?.controller?.id ??
      proofResult?.verificationMethod?.controller ??
      proofResult?.proof?.verificationMethod?.split('#')[0];
    ({verifiableCredential} = presentation ?? {});
  }
  const credentials = [verifiableCredential ?? []].flat().map(
    (credential, index) =>
      result.credentialResults?.[index]?.credential ?? credential);
  return {holder, credentials};
}
