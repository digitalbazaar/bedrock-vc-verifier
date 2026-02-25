/*
 * Copyright (c) 2025-2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {DataItem} from '@auth0/mdl';

const {util: {BedrockError}} = bedrock;

// FIXME: session transcript changes based on annex B, C, D:

// returns a full or partial session transcript
export function getSessionTranscriptFromOptions({options} = {}) {
  if(!options.mdl?.sessionTranscript) {
    // no `mdl` session transcription options given
    return {};
  }

  // FIXME: add annex B, C, D determinant as needed

  // `mdocGeneratedNonce` and `verifierGeneratedNonce` are base64url-encoded
  // values; the others are passthrough strings
  const sessionTranscript = {...options.mdl.sessionTranscript};
  if(sessionTranscript.mdocGeneratedNonce) {
    sessionTranscript.mdocGeneratedNonce = Buffer
      .from(sessionTranscript.mdocGeneratedNonce, 'base64url')
      // note: ISO 18013-7 requires `verifierGeneratedNonce` to be a string
      .toString('utf8');
  }
  if(sessionTranscript.verifierGeneratedNonce) {
    sessionTranscript.verifierGeneratedNonce = Buffer
      .from(sessionTranscript.verifierGeneratedNonce, 'base64url')
      // note: ISO 18013-7 requires `verifierGeneratedNonce` to be a string
      .toString('utf8');
  }
  return sessionTranscript;
}

export function encodeSessionTranscript({sessionTranscript} = {}) {
  const {
    mdocGeneratedNonce,
    clientId,
    responseUri,
    verifierGeneratedNonce
    // FIXME: add `annex`?
  } = sessionTranscript;
  const encoded = DataItem.fromData([
    // deviceEngagementBytes
    null,
    // eReaderKeyBytes
    null,
    [mdocGeneratedNonce, clientId, responseUri, verifierGeneratedNonce],
  ]);
  return DataItem.fromData(encoded).buffer;
}
