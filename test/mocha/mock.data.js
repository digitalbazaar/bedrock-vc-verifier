/*!
* Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
*/
'use strict';

const {config} = require('bedrock');
const {
  constants: {CREDENTIALS_CONTEXT_V1_URL}
} = require('credentials-context');

const mock = {};
module.exports = mock;

// mock product IDs and reverse lookup for service products
mock.productIdMap = new Map([
  // edv service
  ['edv', 'urn:uuid:dbd15f08-ff67-11eb-893b-10bf48838a41'],
  ['urn:uuid:dbd15f08-ff67-11eb-893b-10bf48838a41', 'edv'],
  // vc-verifier service
  ['vc-verifier', 'urn:uuid:66aad4d0-8ac1-11ec-856f-10bf48838a41'],
  ['urn:uuid:66aad4d0-8ac1-11ec-856f-10bf48838a41', 'vc-verifier'],
  // webkms service
  ['webkms', 'urn:uuid:80a82316-e8c2-11eb-9570-10bf48838a41'],
  ['urn:uuid:80a82316-e8c2-11eb-9570-10bf48838a41', 'webkms']
]);

mock.baseUrl = config.server.baseUri;

const credentials = mock.credentials = {};
credentials.alpha = {
  '@context': [
    CREDENTIALS_CONTEXT_V1_URL, {
      ex1: 'https://example.com/examples/v1',
      AlumniCredential: 'ex1:AlumniCredential',
      alumniOf: 'ex1:alumniOf'
    }
  ],
  id: 'http://example.edu/credentials/58473',
  type: ['VerifiableCredential', 'AlumniCredential'],
  issuer: 'did:test:issuer:foo',
  issuanceDate: new Date().toISOString(),
  credentialSubject: {
    id: 'did:example:ebfeb1f712ebc6f1c276e12ec21',
    alumniOf: 'Example University'
  }
};

const presentations = mock.presentations = {};

presentations.alpha = {
  '@context': [CREDENTIALS_CONTEXT_V1_URL],
  type: ['VerifiablePresentation'],
  verifiableCredential: [],
};
