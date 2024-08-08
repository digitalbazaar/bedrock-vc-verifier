/*!
 * Copyright (c) 2018-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as di from './di.js';
import {
  verifyEnvelopedCredential, verifyEnvelopedPresentation
} from './envelopes.js';

export async function verifyCredential({config, credential, checks} = {}) {
  if(credential?.type === 'EnvelopedVerifiableCredential') {
    const result = await verifyEnvelopedCredential({
      config, envelopedCredential: credential, checks
    });
    // if the credential has a `proof` field, do DI verification
    let {verified} = result;
    if(verified && result.credential.proof) {
      const proofResult = await di.verifyCredential({
        config, credential: result.credential, checks
      });
      result.proofResult = proofResult;
      verified = verified && proofResult.verified;
      console.log('proof result', result.proofResult);
    }
    return {...result, verified};
  }
  return di.verifyCredential({config, credential, checks});
}

export async function verifyPresentation({
  config, presentation, challenge, domain, checks
} = {}) {
  if(presentation?.type === 'EnvelopedVerifiablePresentation') {
    const presentationResult = await verifyEnvelopedPresentation({
      config,
      envelopedPresentation: presentation,
      challenge, domain, checks
    });
    // verify each `verifiableCredential` in the resulting VP
    let verified = presentationResult.verified;
    let credentialResults;
    if(!verified) {
      credentialResults = [];
    } else {
      // if the presentation has a `proof` field, do DI verification, but
      // note that the presentation itself may verify but the VCs therein might
      // not because some of them might be enveloped VCs and the underlying
      // `vc` library doesn't support this; therefore only use the presentation
      // result and let the code below check VCs to ensure any enveloped VCs
      // will also be checked
      if(presentationResult.presentation.proof) {
        const proofResult = await di.verifyPresentation({
          config, presentation: presentationResult.presentation,
          challenge, domain, checks
        });
        presentationResult.proofResult = proofResult;
        verified = !!(verified && proofResult.presentationResult?.verified);
        if(proofResult.verified) {
          // the whole VP was verified, so include the credential results, no
          // need to repeat below to ensure enveloped credentials are checked
          // as there aren't any
          credentialResults = proofResult.credentialResults;
        }
      }

      if(!credentialResults) {
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
    }
    return {
      ...presentationResult,
      verified,
      presentationResult,
      credentialResults
    };
  }
  const result = await di.verifyPresentation({
    config, presentation, challenge, domain, checks
  });
  return result;
}
