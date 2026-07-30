/*!
 * Copyright (c) 2018-2026 Digital Bazaar, Inc.
 */
import * as vc from '@digitalbazaar/vc';
import {createCheckStatus} from './status.js';
import {createDocumentLoader} from './documentLoader.js';
import {createSuites} from './suites.js';

export async function verifyCredential({
  config, credential, options, checks
} = {}) {
  const documentLoader = await createDocumentLoader({config});
  const suite = createSuites({options});

  // only check credential status when option is set
  const checkStatus = checks.includes('credentialStatus') ?
    createCheckStatus({config}) : () => ({verified: true});

  const result = await vc.verifyCredential({
    credential,
    documentLoader,
    suite,
    checkStatus
  });
  // if proof should have been checked but wasn't due to an error,
  // try to run the check again within the VC's validity period
  const validDate = credential.validUntil ?? credential.validFrom ??
    credential.issuanceDate;
  if(checks.includes('proof') &&
    result.error && !result.proof && result.results?.[0] &&
    typeof validDate === 'string') {
    const proofResult = await vc.verifyCredential({
      credential,
      documentLoader,
      suite,
      now: new Date(validDate),
      checkStatus
    });
    if(proofResult.verified) {
      // overlay original (failed) results on top of proof results
      result.results[0] = {
        ...proofResult.results[0],
        ...result.results?.[0],
        proofVerified: true
      };
    } else {
      if(!Array.isArray(result.error.errors)) {
        result.error.errors = [];
      }
      result.error.errors.push(proofResult.error);
      if(!result.results?.[0]) {
        result.results = [];
      }
      result.results[0] = {
        ...result.results[0],
        proofVerified: false
      };
    }
  }
  // ensure all proofs are verified in order to return `verified`
  let {verified} = result;
  verified = !!(verified && result?.results?.every(({verified}) => verified));
  return {...result, verified, credential};
}

export async function verifyPresentation({
  config, presentation, challenge, domain, checks
} = {}) {
  const verifyOptions = {
    challenge,
    domain,
    presentation,
    documentLoader: await createDocumentLoader({config}),
    suite: createSuites(),
    unsignedPresentation: !checks.includes('proof'),
    checkStatus: createCheckStatus({config}),
    includeCredentials: true
  };
  return vc.verify(verifyOptions);
}
