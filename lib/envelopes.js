/*
 * Copyright (c) 2019-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as vcjwt from './vcjwt.js';

const {util: {BedrockError}} = bedrock;

export async function verifyEnvelopedCredential({envelopedCredential} = {}) {
  try {
    const {contents: jwt} = _parseEnvelope({
      envelope: envelopedCredential
    });
    return vcjwt.verifyEnvelopedCredential({jwt});
  } catch(error) {
    return {verified: false, error};
  }
}

export async function verifyEnvelopedPresentation({
  envelopedPresentation, challenge, domain
} = {}) {
  try {
    const {contents: jwt} = _parseEnvelope({
      envelope: envelopedPresentation
    });
    return vcjwt.verifyEnvelopedPresentation({jwt, challenge, domain});
  } catch(error) {
    return {verified: false, error};
  }
}

function _parseEnvelope({envelope}) {
  const {id} = envelope;
  let format;
  const comma = id.indexOf(',');
  if(id.startsWith('data:') && comma !== -1) {
    format = id.slice('data:'.length, comma);
  }
  if(format !== 'application/jwt') {
    throw new BedrockError(
      `Unknown envelope format "${format}".`, {
        name: 'DataError',
        details: {
          httpStatusCode: 400,
          public: true
        },
      });
  }
  return {contents: id.slice(comma + 1), format};
}
