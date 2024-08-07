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
    // FIXME: get `credential` from result and if it has any `proofs` use
    // `di.js`
    return result;
  }
  return di.verifyCredential({config, credential, checks});
}

export async function verifyPresentation({
  config, presentation, challenge, domain, checks
} = {}) {
  if(presentation?.type === 'EnvelopedVerifiablePresentation') {
    const result = await verifyEnvelopedPresentation({
      config,
      envelopedPresentation: presentation,
      challenge, domain, checks
    });
    // FIXME: get `presentation` from result and if it has any `proofs` use
    // `di.js`
    // FIXME: verify each `verifiableCredential` in the resulting VP by
    // calling `verifyCredential` above
    return result;
  }
  const result = await di.verifyPresentation({
    config, presentation, challenge, domain, checks
  });
  // FIXME: process enveloped credential in the resulting VP by calling
  // `verifyCredential` above
  return result;
}
