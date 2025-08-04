/*
 * Copyright (c) 2019-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as mdl from './mdl.js';
import * as vcb from './vcb.js';
import * as vcjwt from './vcjwt.js';

const {util: {BedrockError}} = bedrock;

export async function verifyEnvelopedCredential({
  config, envelopedCredential, checks
} = {}) {
  let format;
  try {
    const parseResult = _parseEnvelope({envelope: envelopedCredential});
    const {contents} = parseResult;
    format = parseResult.format;

    let result;
    if(format.typeAndSubType === 'application/jwt') {
      result = await vcjwt.verifyEnvelopedCredential({jwt: contents});
    } else if(format.typeAndSubType === 'application/vcb') {
      result = await vcb.verifyEnvelopedCredential({
        config, contents, format, checks
      });
    } else {
      _throwUnknownFormat(format);
    }
    return {...result, format};
  } catch(error) {
    return {verified: false, error, format};
  }
}

export async function verifyEnvelopedPresentation({
  config, envelopedPresentation, challenge, domain, checks, options
} = {}) {
  let format;
  try {
    const parseResult = _parseEnvelope({envelope: envelopedPresentation});
    const {contents} = parseResult;
    format = parseResult.format;

    let result;
    if(format.typeAndSubType === 'application/jwt') {
      result = await vcjwt.verifyEnvelopedPresentation({
        jwt: contents, challenge, domain
      });
    } else if(format.typeAndSubType === 'application/vcb') {
      result = await vcb.verifyEnvelopedPresentation({
        config, contents, format, challenge, checks
      });
    } else if(format.typeAndSubType === 'application/mdl-device-response') {
      result = await mdl.verifyEnvelopedPresentation({
        config, contents, format, challenge, checks, options
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
  const format = {};
  const comma = id.indexOf(',');
  if(id.startsWith('data:') && comma !== -1) {
    const mediaType = id.slice('data:'.length, comma);
    const parts = mediaType.split(';');
    format.mediaType = mediaType;
    format.typeAndSubType = parts.shift();
    const [type, subType] = format.typeAndSubType.split('/');
    format.type = type;
    format.subType = subType;
    format.parameters = new Map(parts.map(s => s.trim().split('=')));
  }
  return {contents: id.slice(comma + 1), format};
}

function _throwUnknownFormat(format) {
  throw new BedrockError(
    `Unknown envelope format "${format.mediaType}".`, {
      name: 'DataError',
      details: {
        httpStatusCode: 400,
        public: true
      },
    });
}
