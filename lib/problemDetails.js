/*!
 * Copyright (c) 2026 Digital Bazaar, Inc. All rights reserved.
 */

// URL prefixes for the problem types defined by the W3C specs
const VC_DATA_MODEL = 'https://www.w3.org/TR/vc-data-model#';
const DATA_INTEGRITY = 'https://w3id.org/security#';
const STATUS_LIST = 'https://www.w3.org/ns/credentials/status-list#';
const DID = 'https://www.w3.org/ns/did#';

/**
 * The problem types this service can report. Each entry gives the URL
 * prefix of the spec that defines the type and a short human-readable title.
 */
export const PROBLEM_TYPES = {
  PARSING_ERROR: {prefix: VC_DATA_MODEL, title: 'Parsing error'},
  MALFORMED_VALUE_ERROR: {prefix: VC_DATA_MODEL, title: 'Malformed value'},
  CRYPTOGRAPHIC_SECURITY_ERROR: {
    prefix: VC_DATA_MODEL, title: 'Cryptographic security error'
  },
  RANGE_ERROR: {prefix: VC_DATA_MODEL, title: 'Value out of range'},
  PROOF_VERIFICATION_ERROR: {
    prefix: DATA_INTEGRITY, title: 'Proof verification failed'
  },
  INVALID_DOMAIN_ERROR: {prefix: DATA_INTEGRITY, title: 'Invalid domain'},
  INVALID_CHALLENGE_ERROR: {prefix: DATA_INTEGRITY, title: 'Invalid challenge'},
  STATUS_VERIFICATION_ERROR: {
    prefix: STATUS_LIST, title: 'Credential status verification failed'
  },
  NOT_FOUND: {prefix: DID, title: 'Not found'}
};

/**
 * The problem type reported for an error that was not tagged with one. Most
 * untagged failures come from the signature and proof checks in the
 * verification libraries, which do not tag their errors, so this is the
 * default.
 */
export const DEFAULT_PROBLEM_TYPE = 'PROOF_VERIFICATION_ERROR';

/**
 * Tags an error with the W3C problem type that describes it. The tag is read
 * by `problemDetails` and survives error serialization.
 *
 * @param {Error} error - The error to tag.
 * @param {string} problemType - A key of PROBLEM_TYPES.
 *
 * @returns {Error} The same error, tagged.
 */
export function tagProblemType(error, problemType) {
  if(!PROBLEM_TYPES[problemType]) {
    throw new Error(`Unknown problem type "${problemType}".`);
  }
  error.problemType = problemType;
  return error;
}

/**
 * Builds an RFC 9457 problem details object for a verification error.
 *
 * @param {object} options - Options.
 * @param {string} [options.problemType] - The problem type tag, as set by
 *   `tagProblemType`. Untagged errors get DEFAULT_PROBLEM_TYPE.
 * @param {string} [options.detail] - Human-readable detail, the error message.
 *
 * @returns {object} `{type, title, detail}`.
 */
export function problemDetails({problemType, detail = ''} = {}) {
  const name = PROBLEM_TYPES[problemType] ? problemType : DEFAULT_PROBLEM_TYPE;
  const {prefix, title} = PROBLEM_TYPES[name];
  return {type: `${prefix}${name}`, title, detail};
}
