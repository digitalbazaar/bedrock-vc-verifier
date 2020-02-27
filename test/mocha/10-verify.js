/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const {config} = bedrock;
const axios = require('axios');
const {loader} = require('bedrock-vc-verifier');
const helpers = require('./helpers');
const https = require('https');

const strictSSL = false;

const urls = {
  verify: `${config.server.baseUri}/vc/verify`,
  verification({verifierId, referenceId}) {
    return `${config.server.baseUri}/verifiers/${verifierId}/` +
      `verifications/${referenceId}`;
  }
};

// FIXME: update to latest vc-js APIs
describe('verify API using local DID document loader', () => {
  it('verifies a valid credential', async () => {
    const {challenge, domain} = helpers;
    let error;
    let result;
    const {
      v1DidDoc: credentialSignerDoc,
      assertionMethodKey: credentialSigningKey
    } = await helpers.generateDid();
    const {
      v1DidDoc: presentationSignerDoc,
      authenticationKey: presentationSigningKey
    } = await helpers.generateDid();
    loader.documents.set(credentialSignerDoc.id, credentialSignerDoc.doc);
    loader.documents.set(presentationSignerDoc.id, presentationSignerDoc.doc);
    const {presentation} = await helpers.generatePresentation({
      challenge,
      domain,
      credentialSigningKey,
      presentationSigningKey,
      issuer: credentialSignerDoc.id
    });
    try {
      result = await axios({
        httpsAgent: new https.Agent({rejectUnauthorized: strictSSL}),
        data: {challenge, domain, presentation},
        method: 'POST',
        url: urls.verify,
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
  it('verifies a credential with a verifierId and a referenceId', async () => {
    const {challenge, domain} = helpers;
    let error;
    let result;
    const {
      v1DidDoc: credentialSignerDid,
      assertionMethodKey: credentialSigningKey
    } = await helpers.generateDid();
    const {
      v1DidDoc: presentationSignerDid,
      authenticationKey: presentationSigningKey
    } = await helpers.generateDid();
    loader.documents.set(credentialSignerDid.id, credentialSignerDid.doc);
    loader.documents.set(presentationSignerDid.id, presentationSignerDid.doc);
    const {presentation} = await helpers.generatePresentation(
      {challenge, domain, credentialSigningKey, presentationSigningKey});
    const url = urls.verification({verifiedId: 'foo', referenceId: 'bar'});
    try {
      result = await axios({
        httpsAgent: new https.Agent({rejectUnauthorized: strictSSL}),
        data: {challenge, domain, presentation},
        method: 'POST',
        url
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
