/*!
 * Copyright (c) 2018-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as di from './di.js';
import {
  verifyEnvelopedCredential, verifyEnvelopedPresentation
} from './envelopes.js';

export async function verifyCredential({config, credential, checks} = {}) {
  if(credential?.type !== 'EnvelopedVerifiableCredential') {
    return di.verifyCredential({config, credential, checks});
  }

  const result = await verifyEnvelopedCredential({
    config, envelopedCredential: credential, checks
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

export async function verifyPresentation({
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
    const credentialResults = await Promise.all(verifiableCredential.map(
      credential => verifyCredential({config, credential, checks})));
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
  if(!verified ||
    presentationResult.format.typeAndSubType === 'application/mdl-vp-token') {
    credentialResults = [];
  } else if(presentationResult.presentation?.proof &&
    presentationResult.format.typeAndSubType === 'application/jwt') {
    // presentation in the envelope has a `proof` and envelope format is JWT,
    // so recurse to check `proof` field
    const proofResult = await verifyPresentation({
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
