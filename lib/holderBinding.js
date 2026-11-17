/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */

// Holder binding: when requested via the `holderBinding` check, every
// credential in a verified presentation must name the presentation's verified
// signer as a subject. Pure functions; callers pass in the verified holder
// and the verified credentials.

const KEY_MEMBERS = ['kty', 'crv', 'x', 'y', 'n', 'e'];

const didOf = id => typeof id === 'string' ? id.split('#')[0] : undefined;

function jwkFromDidJwk(did) {
  if(typeof did !== 'string' || !did.startsWith('did:jwk:')) {
    return;
  }
  try {
    return JSON.parse(
      Buffer.from(did.slice('did:jwk:'.length), 'base64url').toString());
  } catch {
    return;
  }
}

function sameKey(a, b) {
  return !!(a?.kty && b?.kty) &&
    KEY_MEMBERS.every(member => a[member] === b[member]);
}

function holderBindingError(message) {
  const error = new Error(message);
  error.name = 'HolderBindingError';
  return error;
}

/**
 * Collects every `credentialSubject.id` a credential names. For a VC-JWT,
 * the verifier has already injected the `sub` claim as `credentialSubject.id`.
 *
 * @param {object} options - The options to use.
 * @param {object} options.credential - The verified credential.
 *
 * @returns {Array<string>} The distinct subject identifiers, possibly empty.
 */
export function credentialSubjectIds({credential} = {}) {
  const subjects = [credential?.credentialSubject ?? []].flat();
  const ids = subjects.map(subject => subject?.id)
    .filter(id => typeof id === 'string' && id.length > 0);
  return [...new Set(ids)];
}

/**
 * Checks that `holder` is a subject of every credential. A holder matches a
 * subject when their DIDs are equal (ignoring any fragment), or when both are
 * `did:jwk` DIDs for the same key in a different JSON member order.
 *
 * @param {object} options - The options to use.
 * @param {string} [options.holder] - The presentation's verified signer DID.
 * @param {Array<object>} options.credentials - The verified credentials.
 *
 * @returns {{verified: boolean, error?: Error}} The result.
 */
export function checkHolderBinding({holder, credentials = []} = {}) {
  const holderDid = didOf(holder);
  if(!holderDid) {
    return {
      verified: false,
      error: holderBindingError('The presentation holder could not be ' +
        'determined, so holder binding could not be checked.')
    };
  }
  const holderJwk = jwkFromDidJwk(holderDid);
  for(const [index, credential] of credentials.entries()) {
    const subjectIds = credentialSubjectIds({credential});
    if(subjectIds.length === 0) {
      return {
        verified: false,
        error: holderBindingError(
          `Credential ${index} has no subject identifier, so it cannot be ` +
          'bound to the presentation holder.')
      };
    }
    const bound = subjectIds.some(id => didOf(id) === holderDid ||
      sameKey(jwkFromDidJwk(didOf(id)), holderJwk));
    if(!bound) {
      return {
        verified: false,
        error: holderBindingError(
          `The presentation holder is not a subject of credential ${index}.`)
      };
    }
  }
  return {verified: true};
}
