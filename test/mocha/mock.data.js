/*!
* Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
*/
'use strict';

const {
  constants: {CREDENTIALS_CONTEXT_V1_URL}
} = require('credentials-context');

const mock = {};
module.exports = mock;

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
