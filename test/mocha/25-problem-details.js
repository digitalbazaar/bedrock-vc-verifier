/*!
 * Copyright (c) 2026 Digital Bazaar, Inc. All rights reserved.
 */
import {deepStrictEqual, strictEqual} from 'node:assert';
// import through the package so coverage (which counts the package path) sees it
import {problemDetails, problemName} from
  '@bedrock/vc-verifier/lib/problemDetails.js';

describe('problem details', () => {
  const cases = [{
    description: 'a proof failure',
    detail: 'Invalid signature.',
    name: 'PROOF_VERIFICATION_ERROR',
    type: 'https://w3id.org/security#PROOF_VERIFICATION_ERROR'
  }, {
    description: 'a domain mismatch',
    detail: 'The proof domain did not match.',
    name: 'INVALID_DOMAIN_ERROR',
    type: 'https://w3id.org/security#INVALID_DOMAIN_ERROR'
  }, {
    description: 'a challenge mismatch',
    detail: 'The proof challenge did not match.',
    name: 'INVALID_CHALLENGE_ERROR',
    type: 'https://w3id.org/security#INVALID_CHALLENGE_ERROR'
  }, {
    description: 'a credential status failure',
    detail: 'Credential status check failed.',
    name: 'STATUS_VERIFICATION_ERROR',
    type: 'https://www.w3.org/ns/credentials/status-list#' +
      'STATUS_VERIFICATION_ERROR'
  }, {
    description: 'an unresolvable DID',
    detail: 'The DID could not be resolved.',
    name: 'NOT_FOUND',
    type: 'https://www.w3.org/ns/did#NOT_FOUND'
  }, {
    description: 'an unparseable input',
    detail: 'Could not parse JSON.',
    name: 'PARSING_ERROR',
    type: 'https://www.w3.org/TR/vc-data-model#PARSING_ERROR'
  }];

  for(const {description, detail, name, type} of cases) {
    it(`names ${description}`, () => {
      strictEqual(problemName({detail}), name);
      deepStrictEqual(problemDetails({detail}), {type, title: name, detail});
    });
  }

  it('defaults an unclassified failure to a proof verification error', () => {
    const detail = 'Verification error.';
    strictEqual(problemName({detail}), 'PROOF_VERIFICATION_ERROR');
  });

  it('uses an empty detail when none is given', () => {
    strictEqual(problemName(), 'PROOF_VERIFICATION_ERROR');
    deepStrictEqual(problemDetails(), {
      type: 'https://w3id.org/security#PROOF_VERIFICATION_ERROR',
      title: 'PROOF_VERIFICATION_ERROR',
      detail: ''
    });
  });
});
