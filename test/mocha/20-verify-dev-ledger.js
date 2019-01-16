/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const {config} = bedrock;
const axios = require('axios');
const helpers = require('./helpers');
const https = require('https');
const uuid = require('uuid/v4');

const strictSSL = false;
const url = `${config.server.baseUri}/vc/verify`;

describe('verify API using local dev ledger', () => {
  it('verifies a valid presentation', async () => {
    let error;
    const challenge = uuid();
    const domain = uuid();
    const {signingKey: credentialSigningKey} = await helpers.registerDid();
    const {signingKey: presentationSigningKey} = await helpers.registerDid();
    const {presentation} = await helpers.generatePresentation(
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
