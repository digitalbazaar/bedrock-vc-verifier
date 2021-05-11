/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const {config} = bedrock;
const helpers = require('./helpers');
const {httpClient} = require('@digitalbazaar/http-client');
const https = require('https');

const strictSSL = false;
const url = `${config.server.baseUri}/vc/verify`;

// this test can only be run if there is a dev veres-one ledger on localhost
describe.skip('verify API using local dev ledger', () => {
  it('verifies a valid presentation', async () => {
    let error;
    const {challenge, domain} = helpers;
    const {signingKey: credentialSigningKey} = await helpers.registerDid();
    const {signingKey: presentationSigningKey} = await helpers.registerDid();
    const {presentation} = await helpers.generatePresentation(
      {challenge, domain, credentialSigningKey, presentationSigningKey});
    // register DID on the ledger

    let result;
    try {
      result = await httpClient.post(url, {
        agent: new https.Agent({rejectUnauthorized: strictSSL}),
        json: {challenge, domain, presentation},
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
