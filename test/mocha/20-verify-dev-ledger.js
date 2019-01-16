/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const {config} = bedrock;
const axios = require('axios');
const https = require('https');
const jsigs = require('jsonld-signatures');
const mockData = require('./mock.data');
const uuid = require('uuid/v4');
const v1 = new (require('did-veres-one')).VeresOne({
  hostname: config['vc-verifier'].ledgerHostname,
  mode: 'dev'
});
// FIXME: temporary, did-veres-one will be returning a keypair that can be
// used for signing operations
const {Ed25519KeyPair} = require('crypto-ld');

const strictSSL = false;
const url = `${config.server.baseUri}/vc/verify`;

describe('verify API using local dev ledger', () => {
  it('verifies a valid presentation', async () => {
    let error;
    const challenge = uuid();
    const domain = uuid();
    const {signingKey: credentialSigningKey} = await _registerDid();
    const {signingKey: presentationSigningKey} = await _registerDid();
    const {presentation} = await _generatePresentation(
      {challenge, domain, credentialSigningKey, presentationSigningKey});
    // register DID on the ledger

    let result;
    try {
      result = await axios({
        httpsAgent: new https.Agent({rejectUnauthorized: strictSSL}),
        data: {challenge, domain, presentation},
        method: 'POST',
        url,
      });
    } catch(e) {
      error = e;
    }
    should.not.exist(error);
    should.exist(result.data);
    const {data} = result;
    should.exist(data);
    data.should.be.an('object');
    should.exist(data.verified);
    data.verified.should.be.a('boolean');
    data.verified.should.be.true;
  });
});

async function _registerDid() {
  const v1DidDoc = await v1.generate();
  const aKey = v1DidDoc.suiteKeyNode({suiteId: 'authentication'});
  const authenticationKey = v1DidDoc.keys[aKey.id];
  const key = await authenticationKey.export();
  const signingKey = new Ed25519KeyPair(key);
  await v1.register({didDocument: v1DidDoc});
  await _waitForConsensus({did: v1DidDoc.id});
  return {v1DidDoc, signingKey};
}

async function _generateCredential({signingKey}) {
  const mockCredential = bedrock.util.clone(mockData.credentials.alpha);
  const {Ed25519Signature2018} = jsigs.suites;
  const {AuthenticationProofPurpose} = jsigs.purposes;
  const credential = await jsigs.sign(mockCredential, {
    compactProof: false,
    documentLoader: bedrock.jsonld.documentLoader,
    suite: new Ed25519Signature2018({key: signingKey}),
    purpose: new AuthenticationProofPurpose({
      challenge: 'challengeString'
    })
  });
  return {credential};
}

async function _generatePresentation(
  {challenge, domain, credentialSigningKey, presentationSigningKey}) {
  const mockPresentation = bedrock.util.clone(mockData.presentations.alpha);
  const {Ed25519Signature2018} = jsigs.suites;
  const {AuthenticationProofPurpose} = jsigs.purposes;
  const {credential} = await _generateCredential(
    {signingKey: credentialSigningKey});
  mockPresentation.verifiableCredential.push(credential);
  const presentation = await jsigs.sign(mockPresentation, {
    compactProof: false,
    documentLoader: bedrock.jsonld.documentLoader,
    suite: new Ed25519Signature2018({key: presentationSigningKey}),
    purpose: new AuthenticationProofPurpose({challenge, domain})
  });
  return {presentation};
}

async function _waitForConsensus({did}) {
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
