/*!
 * Copyright (c) 2026 Digital Bazaar, Inc. All rights reserved.
 */

// URL prefixes for the problem types defined by the W3C specs
export const PROBLEM_TYPE_PREFIXES = {
  // VC Data Model 2.0
  PARSING_ERROR: 'https://www.w3.org/TR/vc-data-model#',
  MALFORMED_VALUE_ERROR: 'https://www.w3.org/TR/vc-data-model#',
  CRYPTOGRAPHIC_SECURITY_ERROR: 'https://www.w3.org/TR/vc-data-model#',
  RANGE_ERROR: 'https://www.w3.org/TR/vc-data-model#',
  // Data Integrity
  PROOF_VERIFICATION_ERROR: 'https://w3id.org/security#',
  INVALID_DOMAIN_ERROR: 'https://w3id.org/security#',
  INVALID_CHALLENGE_ERROR: 'https://w3id.org/security#',
  // Bitstring Status List
  STATUS_VERIFICATION_ERROR: 'https://www.w3.org/ns/credentials/status-list#',
  // DID Resolution
  NOT_FOUND: 'https://www.w3.org/ns/did#'
};

/**
 * Name the W3C problem type for a verification error, from its message. Errors
 * are not tagged at their source yet, so this is a best-effort match on text.
 *
 * @param {object} options - Options.
 * @param {string} [options.detail] - The error message.
 * @returns {string} A problem type name, a key of PROBLEM_TYPE_PREFIXES.
 */
export function problemName({detail = ''} = {}) {
  if(/domain/i.test(detail)) {
    return 'INVALID_DOMAIN_ERROR';
  }
  if(/challenge/i.test(detail)) {
    return 'INVALID_CHALLENGE_ERROR';
  }
  if(/status/i.test(detail)) {
    return 'STATUS_VERIFICATION_ERROR';
  }
  if(/\bDID\b.*(not found|resolv)/i.test(detail)) {
    return 'NOT_FOUND';
  }
  if(/parse|JSON/i.test(detail)) {
    return 'PARSING_ERROR';
  }
  // proof and signature failures, and any other verification failure
  return 'PROOF_VERIFICATION_ERROR';
}

/**
 * Build a RFC 9457 problem details object for a verification error.
 *
 * @param {object} options - Options.
 * @param {string} [options.detail] - The error message.
 * @returns {object} `{type, title, detail}`.
 */
export function problemDetails({detail = ''} = {}) {
  const name = problemName({detail});
  return {
    type: `${PROBLEM_TYPE_PREFIXES[name]}${name}`,
    title: name,
    detail
  };
}
