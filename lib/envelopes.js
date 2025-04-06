/*
 * Copyright (c) 2019-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as vcjwt from './vcjwt.js';

const {util: {BedrockError}} = bedrock;

export async function verifyEnvelopedCredential({envelopedCredential} = {}) {
  let format;
  try {
    const parseResult = _parseEnvelope({envelope: envelopedCredential});
    const {contents} = parseResult;
    format = parseResult.format;

    let result;
    if(format === 'application/jwt') {
      result = await vcjwt.verifyEnvelopedCredential({jwt: contents});
    } else {
      _throwUnknownFormat(format);
    }
    return {...result, format};
  } catch(error) {
    return {verified: false, error, format};
  }
}

export async function verifyEnvelopedPresentation({
  envelopedPresentation, challenge, domain
} = {}) {
  let format;
  try {
    const parseResult = _parseEnvelope({envelope: envelopedPresentation});
    const {contents} = parseResult;
    format = parseResult.format;

    let result;
    if(format === 'application/jwt') {
      result = await vcjwt.verifyEnvelopedPresentation({
        jwt: contents, challenge, domain
      });
    } else {
      _throwUnknownFormat(format);
    }
    return {...result, format};
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
  return {contents: id.slice(comma + 1), format};
}

function _throwUnknownFormat(format) {
  throw new BedrockError(
    `Unknown envelope format "${format}".`, {
      name: 'DataError',
      details: {
        httpStatusCode: 400,
        public: true
      },
    });
}
