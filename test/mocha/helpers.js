/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const {Ed25519Signature2020} = require('@digitalbazaar/ed25519-signature-2020');
const jsigs = require('jsonld-signatures');
const mockData = require('./mock.data');
const {_documentLoader: documentLoader} = require('bedrock-vc-verifier');

const challenge = 'challengeString';
const domain = 'example.org';
const {sign} = jsigs;
const api = {
  generateCredential,
  generatePresentation,
  challenge,
  domain
};
module.exports = api;

async function generateCredential({signingKey, issuer}) {
  const mockCredential = bedrock.util.clone(mockData.credentials.alpha);
  mockCredential.issuer = issuer;
  const {AssertionProofPurpose} = jsigs.purposes;
  const credential = await sign(mockCredential, {
    documentLoader,
    suite: new Ed25519Signature2020({key: signingKey}),
    purpose: new AssertionProofPurpose()
  });
  return {credential};
}

async function generatePresentation(
  {challenge, domain, credentialSigningKey, presentationSigningKey, issuer}) {
  const mockPresentation = bedrock.util.clone(mockData.presentations.alpha);
  const {AuthenticationProofPurpose} = jsigs.purposes;
  const {credential} = await generateCredential(
    {signingKey: credentialSigningKey, issuer});
  mockPresentation.verifiableCredential.push(credential);
  const presentation = await sign(mockPresentation, {
    documentLoader,
    suite: new Ed25519Signature2020({key: presentationSigningKey}),
    purpose: new AuthenticationProofPurpose({challenge, domain})
  });
  return {presentation};
}
