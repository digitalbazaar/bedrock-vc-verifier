/*
 * Copyright (c) 2025-2026 Digital Bazaar, Inc.
 */
import {oid4vp} from '@digitalbazaar/oid4-client';

// returns session transcript bytes
export async function getEncodedSessionTranscript({
  options, domain, challenge
} = {}) {
  const {mdl} = options;

  if(!mdl?.sessionTranscript) {
    // no `mdl` session transcript given
    return undefined;
  }

  const {sessionTranscript} = mdl;

  // if `mdl.sessionTranscript` is a base64url string, decode and return it
  if(typeof sessionTranscript === 'string') {
    return Buffer.from(sessionTranscript, 'base64url');
  }

  // backwards compatibility case: `sessionTranscript` is an object with
  // Annex B parameters; convert it
  if(sessionTranscript && typeof sessionTranscript === 'object') {
    const handover = {
      type: 'AnnexBHandover',
      responseUri: domain,
      ...sessionTranscript
    };

    // `mdocGeneratedNonce` and `verifierGeneratedNonce` are
    // base64url strings that must be converted to UTF-8 strings; the others
    // are passthrough strings
    for(const prop of ['mdocGeneratedNonce', 'verifierGeneratedNonce']) {
      if(handover[prop]) {
        handover[prop] = Buffer
          .from(handover[prop], 'base64url')
          .toString('utf8');
      }
    }

    // add `challenge` as `verifierGeneratedNonce` if not specified
    if(!handover.verifierGeneratedNonce) {
      handover.verifierGeneratedNonce = challenge;
    }

    return oid4vp.mdl.encodeSessionTranscript({handover});
  }

  // no acceptable session transcript
  return undefined;
}
