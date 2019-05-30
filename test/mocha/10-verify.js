/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const {config, util: {uuid}} = bedrock;
const axios = require('axios');
const {loader} = require('bedrock-vc-verifier');
const helpers = require('./helpers');
const https = require('https');

const strictSSL = false;
const url = `${config.server.baseUri}/vc/verify`;

// FIXME: update to latest vc-js APIs
describe.skip('verify API using local DID document loader', () => {
  it('verifies a valid credential', async () => {
    const challenge = uuid();
    const domain = uuid();
    let error;
    let result;
    const {v1DidDoc: credentialSignerDid, signingKey: credentialSigningKey} =
      await helpers.generateDid();
    const {
      v1DidDoc: presentationSignerDid,
      signingKey: presentationSigningKey
    } = await helpers.generateDid();
    loader.documents.set(credentialSignerDid.id, credentialSignerDid.doc);
    loader.documents.set(presentationSignerDid.id, presentationSignerDid.doc);
    const {presentation} = await helpers.generatePresentation(
      {challenge, domain, credentialSigningKey, presentationSigningKey});
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
