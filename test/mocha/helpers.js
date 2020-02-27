/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const {config} = bedrock;
const jsigs = require('jsonld-signatures');
const mockData = require('./mock.data');
const {loader: {documentLoader}} = require('bedrock-vc-verifier');
const v1 = new (require('did-veres-one')).VeresOne({
  hostname: config['vc-verifier'].ledgerHostname,
  mode: 'dev'
});

// FIXME: temporary, did-veres-one will be returning a keypair that can be
// used for signing operations
const {Ed25519KeyPair} = require('crypto-ld');

const challenge = 'challengeString';
const domain = 'example.org';

const api = {
  generateCredential,
  generateDid,
  generatePresentation,
  registerDid,
  waitForConsensus,
  challenge,
  domain
};
module.exports = api;

async function generateCredential({signingKey, issuer}) {
  const mockCredential = bedrock.util.clone(mockData.credentials.alpha);
  mockCredential.issuer = issuer;
  const {Ed25519Signature2018} = jsigs.suites;
  const {AssertionProofPurpose} = jsigs.purposes;
  const credential = await jsigs.sign(mockCredential, {
    compactProof: false,
    documentLoader,
    suite: new Ed25519Signature2018({key: signingKey}),
    purpose: new AssertionProofPurpose()
  });
  return {credential};
}

async function generateDid() {
  const v1DidDoc = await v1.generate();
  const [aKey] = v1DidDoc.doc.authentication;
  const _authenticationKey = v1DidDoc.keys[aKey.id];
  const akey = await _authenticationKey.export();
  const authenticationKey = new Ed25519KeyPair(akey);
  const [amKey] = v1DidDoc.doc.assertionMethod;
  const _amKey = await v1DidDoc.keys[amKey.id].export();
  const assertionMethodKey = new Ed25519KeyPair(_amKey);
  return {v1DidDoc, authenticationKey, assertionMethodKey};
}

async function generatePresentation(
  {challenge, domain, credentialSigningKey, presentationSigningKey, issuer}) {
  const mockPresentation = bedrock.util.clone(mockData.presentations.alpha);
  const {Ed25519Signature2018} = jsigs.suites;
  const {AuthenticationProofPurpose} = jsigs.purposes;
  const {credential} = await generateCredential(
    {signingKey: credentialSigningKey, issuer});
  mockPresentation.verifiableCredential.push(credential);
  const presentation = await jsigs.sign(mockPresentation, {
    compactProof: false,
    documentLoader,
    suite: new Ed25519Signature2018({key: presentationSigningKey}),
    purpose: new AuthenticationProofPurpose({challenge, domain})
  });
  return {presentation};
}

async function registerDid() {
  const {v1DidDoc, signingKey} = await generateDid();
  await v1.register({didDocument: v1DidDoc});
  await waitForConsensus({did: v1DidDoc.id});
  return {v1DidDoc, signingKey};
}

async function waitForConsensus({did}) {
  let found = false;
  let didRecord;
  while(!found) {
    try {
      // using v1.client.get here because v1.get will pull locally created
      // did from local storage as a pairwise did
      didRecord = await v1.client.get({did});
      found = true;
    } catch(e) {
      if(e.response.status !== 404) {
        throw e;
      }
      console.log('Waiting for consensus...');
      await new Promise(resolve => setTimeout(resolve, 1000));
      continue;
    }
  }
  return didRecord;
}
