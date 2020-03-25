/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {config} = require('bedrock');
const {create} = require('apisauce');
const {httpsAgent} = require('bedrock-https-agent');

const api = create({
  baseURL: `${config.server.baseUri}/verifier`,
  httpsAgent,
  timeout: 1000,
});

// NOTE: using embedded context in mockCredential:
// https://www.w3.org/2018/credentials/examples/v1
const mockCredential = require('./mock-credential');

describe('Interop Verifier API', () => {
  describe('credentials endpoint', () => {
    it('verifies a valid credential', async () => {
      let error;
      let result;
      try {
        result = await api.post('/credentials', {
          verifiableCredential: mockCredential
        });
      } catch(e) {
        error = e;
      }
      should.not.exist(error);
      // apisauce API does not throw it puts errors in `result.problem`
      should.not.exist(result.problem);
      should.exist(result.data.verified);
      result.data.verified.should.be.a('boolean');
      result.data.verified.should.be.true;
    });
    it('does not verify an invalid credential', async () => {
      let error;
      let result;

      const badCredential = Object.assign({}, mockCredential);

      // change the degree name
      badCredential.credentialSubject.degree.name =
        'Bachelor of Science in Nursing';

      try {
        result = await api.post('/credentials', {
          verifiableCredential: mockCredential
        });
      } catch(e) {
        error = e;
      }
      should.not.exist(error);
      // apisauce API does not throw it puts errors in `result.problem`
      should.not.exist(result.problem);
      should.exist(result.data.verified);
      result.data.verified.should.be.a('boolean');
      result.data.verified.should.be.false;
      // the signature is no longer valid because the data was changed
      result.data.results[0].error.message.should.equal('Invalid signature.');
    });
  });
});
