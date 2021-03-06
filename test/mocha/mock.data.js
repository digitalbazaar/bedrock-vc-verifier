/* eslint-disable max-len */
/*!
* Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
*/
'use strict';

const {constants: {VERES_ONE_CONTEXT_V1_URL}} = require('veres-one-context');
const {constants: {DID_CONTEXT_URL}} = require('did-context');
const {constants: {CREDENTIALS_CONTEXT_V1_URL}} = require('credentials-context');

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

const privateDidDocuments = mock.privateDidDocuments = {};

privateDidDocuments.alpha = {
  '@context': [
    DID_CONTEXT_URL,
    VERES_ONE_CONTEXT_V1_URL,
    'https://w3id.org/security/suites/ed25519-2018/v1',
    'https://w3id.org/security/suites/x25519-2019/v1'
  ],
  id: 'did:v1:test:nym:z279yHL6HsxRzCPU78DAWgZVieb8xPK1mJKJBbP8T2CezuFY',
  authentication: [
    {
      id: 'did:v1:test:nym:z279yHL6HsxRzCPU78DAWgZVieb8xPK1mJKJBbP8T2CezuFY#z279jeddPcVScp2qcA476nxuQnZGnmBHcXSKWgNusrT1u1V1',
      type: 'Ed25519VerificationKey2018',
      controller: 'did:v1:test:nym:z279yHL6HsxRzCPU78DAWgZVieb8xPK1mJKJBbP8T2CezuFY',
      publicKeyBase58: '2vXXVcAkogFwWGBHsyU1KCJrsFJLtuE8xnzyVNwmhhdq'
    }
  ],
  capabilityDelegation: [
    {
      id: 'did:v1:test:nym:z279yHL6HsxRzCPU78DAWgZVieb8xPK1mJKJBbP8T2CezuFY#z279odRyQVywHaU723iXRVncxmd4ELNzCL5gGfcQgDVg6mhV',
      type: 'Ed25519VerificationKey2018',
      controller: 'did:v1:test:nym:z279yHL6HsxRzCPU78DAWgZVieb8xPK1mJKJBbP8T2CezuFY',
      publicKeyBase58: '6uKsWVfFUShCv9qiCgHisBNeJpW3UhsVinEUHjzRuTrK'
    }
  ],
  capabilityInvocation: [
    {
      id: 'did:v1:test:nym:z279yHL6HsxRzCPU78DAWgZVieb8xPK1mJKJBbP8T2CezuFY#z279yHL6HsxRzCPU78DAWgZVieb8xPK1mJKJBbP8T2CezuFY',
      type: 'Ed25519VerificationKey2018',
      controller: 'did:v1:test:nym:z279yHL6HsxRzCPU78DAWgZVieb8xPK1mJKJBbP8T2CezuFY',
      publicKeyBase58: 'GZDzPsdkB4ca1ELMHs4bd4Lj2sS53g77di1C4YhQobQN'
    }
  ]
};
