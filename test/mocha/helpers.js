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

const api = {
  generateCredential,
  generateDid,
  generatePresentation,
  registerDid,
  waitForConsensus,
};
module.exports = api;

async function generateCredential({signingKey}) {
  const mockCredential = bedrock.util.clone(mockData.credentials.alpha);
  const {Ed25519Signature2018} = jsigs.suites;
  const {AuthenticationProofPurpose} = jsigs.purposes;
  const credential = await jsigs.sign(mockCredential, {
    compactProof: false,
    documentLoader,
    suite: new Ed25519Signature2018({key: signingKey}),
    purpose: new AuthenticationProofPurpose({
      challenge: 'challengeString'
    })
  });
  return {credential};
}

async function generateDid() {
  const v1DidDoc = await v1.generate();
  const [aKey] = v1DidDoc.doc.authentication;
  const authenticationKey = v1DidDoc.keys[aKey.id];
  const key = await authenticationKey.export();
  const signingKey = new Ed25519KeyPair(key);
  return {v1DidDoc, signingKey};
}

async function generatePresentation(
  {challenge, domain, credentialSigningKey, presentationSigningKey}) {
  const mockPresentation = bedrock.util.clone(mockData.presentations.alpha);
  const {Ed25519Signature2018} = jsigs.suites;
  const {AuthenticationProofPurpose} = jsigs.purposes;
  const {credential} = await generateCredential(
    {signingKey: credentialSigningKey});
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
