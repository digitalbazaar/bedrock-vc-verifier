/*
 * Copyright (c) 2024-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as cborld from '@digitalbazaar/cborld';
import * as di from './di.js';
import {aamva} from '@digitalbazaar/pdf417-dl-canonicalizer';
import {createCborldTypeTableLoader} from '@bedrock/service-context-store';
import {createDocumentLoader} from './documentLoader.js';
import {util} from '@digitalbazaar/vpqr';

const {util: {BedrockError}} = bedrock;

const VC_CONTEXT_2 = 'https://www.w3.org/ns/credentials/v2';
const VCB_CONTEXT_1 = 'https://w3id.org/vc-barcodes/v1';

// map of AAMVA issuer identification number to VCB location
const AAMVA_IIN_TO_VCB_LOCATION = new Map([
  // VCB spec, i.e., test vector intentionally invalid issuer
  ['000000', {subfile: 'ZZ', field: 'ZZA', encoding: 'base64url'}],
  // US state of CA
  ['636014', {subfile: 'ZC', field: 'ZCE', encoding: 'base64'}],
]);

const SUPPORTED_BARCODE_FORMATS = new Set([
  'qr_code',
  'pdf417'
]);

const TEXT_DECODER = new TextDecoder();

export async function verifyEnvelopedPresentation({
  config, contents, format, challenge, checks
} = {}) {
  // handle base64 encoding
  let {parameters} = format;
  if(parameters.has('base64')) {
    contents = new Uint8Array(Buffer.from(contents, 'base64'));
    parameters = new Map(parameters);
    parameters.delete('base64');
  }
  // only parameter understood is `barcode-format` with values of:
  // 'qr_code' (default) or 'pdf417'
  const barcodeFormat = parameters.size === 1 ?
    parameters.get('barcode-format') : (parameters.size === 0 && 'qr_code');
  if(!SUPPORTED_BARCODE_FORMATS.has(barcodeFormat)) {
    _throwUnknownFormat(format);
  }
  // create loaders for JSON-LD contexts and CBOR-LD type tables
  const documentLoader = await createDocumentLoader({config});
  const typeTableLoader = await createCborldTypeTableLoader({
    config, serviceType: 'vc-verifier'
  });
  // parse credential and any verification options from contents...
  let presentation;
  let options;
  if(barcodeFormat === 'qr_code') {
    ({jsonldDocument: presentation, options} = await _parseQrCodeEnvelope({
      contents, documentLoader, typeTableLoader, expectedHeader: 'VP1-'
    }));
  }
  // checks for VCB VPs only applies if there is actually a proof to check
  checks = 'proof' in presentation ? checks : [];
  // verify VP
  const result = await di.verifyPresentation({
    config, presentation, options, challenge, checks
  });
  return {...result, presentation};
}

export async function verifyEnvelopedCredential({
  config, contents, format, checks
} = {}) {
  // handle base64 encoding
  let {parameters} = format;
  if(parameters.has('base64')) {
    contents = new Uint8Array(Buffer.from(contents, 'base64'));
    parameters = new Map(parameters);
    parameters.delete('base64');
  }

  // only parameter understood is `barcode-format` with values of:
  // 'qr_code' (default) or 'pdf417'
  const barcodeFormat = parameters.size === 1 ?
    parameters.get('barcode-format') : (parameters.size === 0 && 'qr_code');
  if(!SUPPORTED_BARCODE_FORMATS.has(barcodeFormat)) {
    _throwUnknownFormat(format);
  }

  // create loaders for JSON-LD contexts and CBOR-LD type tables
  const documentLoader = await createDocumentLoader({config});
  const typeTableLoader = await createCborldTypeTableLoader({
    config, serviceType: 'vc-verifier'
  });

  // parse credential and any verification options from contents...
  let credential;
  let options;
  if(barcodeFormat === 'qr_code') {
    ({jsonldDocument: credential, options} = await _parseQrCodeEnvelope({
      contents, documentLoader, typeTableLoader, expectedHeader: 'VC1-'
    }));
  }
  if(barcodeFormat === 'pdf417') {
    ({credential, options} = await _parsePdf417Envelope({
      contents, documentLoader, typeTableLoader
    }));
  }

  // verify VC
  const result = await di.verifyCredential({
    config, credential, options, checks
  });
  return {...result, credential};
}

async function _parseQrCodeEnvelope({
  contents, documentLoader, typeTableLoader, expectedHeader
}) {
  // `fromQrCode` requires text, so convert to text as needed
  if(contents instanceof Uint8Array) {
    contents = TEXT_DECODER.decode(contents);
  }
  const {jsonldDocument} = await util.fromQrCode({
    text: contents,
    documentLoader,
    typeTableLoader,
    expectedHeader
  });
  return {jsonldDocument};
}

async function _parsePdf417Envelope({
  contents, documentLoader, typeTableLoader
}) {
  // parse AAMVA object from scanned PDF417 data; if contents are a string,
  // presume UTF-8 encoding
  const object = aamva.decode({data: contents, encoding: 'utf8'});

  // find VCB in AAMVA object
  const credential = await findVcb({object, documentLoader, typeTableLoader});
  const componentIndex = credential.credentialSubject?.protectedComponentIndex;

  // select AAMVA DL or ID document
  const document = await aamva.select({
    object,
    selector: {
      subfile: ['DL', 'ID'],
      componentIndex
    }
  });
  // hash document and store it as `extraInformation` for verification
  const options = {
    extraInformation: await aamva.hash({document})
  };

  return {credential, options};
}

async function findVcb({object, documentLoader, typeTableLoader}) {
  const {issuerIdentificationNumber} = object;
  const location = AAMVA_IIN_TO_VCB_LOCATION.get(issuerIdentificationNumber);
  if(!location) {
    throw new BedrockError(
      'Unknown envelope format; verifiable credential barcode not found.', {
        name: 'DataError',
        details: {httpStatusCode: 400, public: true}
      });
  }

  const selection = await aamva.select({
    object,
    selector: {
      subfile: [location.subfile],
      fields: [location.field]
    }
  });

  const encoded = selection.get(location.field);
  if(!encoded) {
    throw new BedrockError('Verifiable credential barcode not found.', {
      name: 'DataError',
      details: {httpStatusCode: 400, public: true}
    });
  }

  const cborldBytes = new Uint8Array(Buffer.from(encoded, location.encoding));

  // decode CBOR-LD bytes into JSON-LD VCB
  const credential = await cborld.decode({
    cborldBytes,
    documentLoader,
    typeTableLoader
  });
  const contexts = credential['@context'];
  if(!Array.isArray(contexts) &&
    contexts[0] === VC_CONTEXT_2 &&
    contexts.includes(VCB_CONTEXT_1)) {
    throw new BedrockError('Verifiable credential barcode not found.', {
      name: 'DataError',
      details: {httpStatusCode: 400, public: true}
    });
  }

  return credential;
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
