/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const {config} = bedrock;
const axios = require('axios');
const {loader} = require('bedrock-vc-verifier');
const https = require('https');
const jsigs = require('jsonld-signatures');
const mockData = require('./mock.data');
const v1 = new (require('did-veres-one')).VeresOne();
// FIXME: temporary, did-veres-one will be returning a keypair that can be
// used for signing operations
const {Ed25519KeyPair} = require('crypto-ld');

const strictSSL = false;
const url = `${config.server.baseUri}/vc/verify`;

describe.skip('verify API', () => {
  it('verifies a valid credential', async () => {
    let error;
    let result;
    const {v1DidDoc, credential} = await _generate();
    loader.documents.set(v1DidDoc.id, v1DidDoc.doc);
    try {
      result = await axios({
        httpsAgent: new https.Agent({rejectUnauthorized: strictSSL}),
        data: {credential},
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

async function _generate() {
  const v1DidDoc = await v1.generate();
  const aKey = v1DidDoc.suiteKeyNode({suiteId: 'authentication'});
  const authenticationKey = v1DidDoc.keys[aKey.id];
  const key = await authenticationKey.export();
  const mockCredential = bedrock.util.clone(mockData.credentials.alpha);
  const {Ed25519Signature2018} = jsigs.suites;
  const {AuthenticationProofPurpose} = jsigs.purposes;
  const credential = await jsigs.sign(mockCredential, {
    // FIXME: `sec` terms are not in the vc-v1 context, should they be?
    compactProof: true,
    documentLoader: bedrock.jsonld.documentLoader,
    suite: new Ed25519Signature2018({key: new Ed25519KeyPair(key)}),
    purpose: new AuthenticationProofPurpose({
      challenge: 'challengeString'
    })
  });
  return {credential, v1DidDoc};
}
