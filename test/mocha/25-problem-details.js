/*!
 * Copyright (c) 2026 Digital Bazaar, Inc. All rights reserved.
 */
import {deepStrictEqual, throws} from 'node:assert';
// import via the package name so coverage counts the package path
import {
  DEFAULT_PROBLEM_TYPE, PROBLEM_TYPES, problemDetails, tagProblemType
} from '@bedrock/vc-verifier/lib/problemDetails.js';

describe('problem details', () => {
  describe('tagProblemType', () => {
    it('sets the problem type on the error and returns it', () => {
      const error = new Error('x');
      const tagged = tagProblemType(error, 'NOT_FOUND');
      deepStrictEqual(tagged, error);
      deepStrictEqual(error.problemType, 'NOT_FOUND');
    });

    it('throws for an unknown problem type', () => {
      throws(() => tagProblemType(new Error('x'), 'BOGUS'), /Unknown/);
    });
  });

  describe('problemDetails', () => {
    const cases = [{
      problemType: 'PROOF_VERIFICATION_ERROR',
      type: 'https://w3id.org/security#PROOF_VERIFICATION_ERROR',
      title: 'Proof verification failed'
    }, {
      problemType: 'INVALID_DOMAIN_ERROR',
      type: 'https://w3id.org/security#INVALID_DOMAIN_ERROR',
      title: 'Invalid domain'
    }, {
      problemType: 'INVALID_CHALLENGE_ERROR',
      type: 'https://w3id.org/security#INVALID_CHALLENGE_ERROR',
      title: 'Invalid challenge'
    }, {
      problemType: 'STATUS_VERIFICATION_ERROR',
      type: 'https://www.w3.org/ns/credentials/status-list#' +
        'STATUS_VERIFICATION_ERROR',
      title: 'Credential status verification failed'
    }, {
      problemType: 'NOT_FOUND',
      type: 'https://www.w3.org/ns/did#NOT_FOUND',
      title: 'Not found'
    }, {
      problemType: 'PARSING_ERROR',
      type: 'https://www.w3.org/TR/vc-data-model#PARSING_ERROR',
      title: 'Parsing error'
    }, {
      problemType: 'MALFORMED_VALUE_ERROR',
      type: 'https://www.w3.org/TR/vc-data-model#MALFORMED_VALUE_ERROR',
      title: 'Malformed value'
    }];

    for(const {problemType, type, title} of cases) {
      it(`maps ${problemType} to its W3C type and title`, () => {
        deepStrictEqual(
          problemDetails({problemType, detail: 'some detail'}),
          {type, title, detail: 'some detail'});
      });
    }

    it('covers every problem type it can report', () => {
      // every entry in PROBLEM_TYPES must be exercised by a case above
      deepStrictEqual(
        Object.keys(PROBLEM_TYPES).sort(),
        [...cases.map(({problemType}) => problemType),
          'CRYPTOGRAPHIC_SECURITY_ERROR', 'RANGE_ERROR'].sort());
    });

    it('defaults an untagged error to the proof verification error', () => {
      deepStrictEqual(problemDetails({detail: 'Invalid signature.'}), {
        type: 'https://w3id.org/security#PROOF_VERIFICATION_ERROR',
        title: 'Proof verification failed',
        detail: 'Invalid signature.'
      });
    });

    it('does not infer a problem type from the message text', () => {
      // a message that mentions a domain is not tagged, so it is not
      // classified as a domain error
      deepStrictEqual(
        problemDetails({detail: 'The proof domain did not match.'}).type,
        `https://w3id.org/security#${DEFAULT_PROBLEM_TYPE}`);
    });

    it('ignores an unknown problem type and uses the default', () => {
      deepStrictEqual(
        problemDetails({problemType: 'BOGUS', detail: 'x'}).type,
        `https://w3id.org/security#${DEFAULT_PROBLEM_TYPE}`);
    });

    it('uses an empty detail when none is given', () => {
      deepStrictEqual(problemDetails(), {
        type: 'https://w3id.org/security#PROOF_VERIFICATION_ERROR',
        title: 'Proof verification failed',
        detail: ''
      });
    });
  });
});
