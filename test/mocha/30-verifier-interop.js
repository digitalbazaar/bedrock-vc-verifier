/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {config, util: {clone}} = require('bedrock');
const {create} = require('apisauce');
const {httpsAgent} = require('bedrock-https-agent');
const vc = require('vc-js');
const {Ed25519KeyPair} = require('crypto-ld');
const {suites: {Ed25519Signature2018}} = require('jsonld-signatures');

const api = create({
  baseURL: `${config.server.baseUri}/verifier`,
  httpsAgent,
  timeout: 1000,
});

// NOTE: using embedded context in mockCredential:
// https://www.w3.org/2018/credentials/examples/v1
const mockCredential = require('./mock-credential');

const mockPresentationSigningKey = {
  type: 'Ed25519VerificationKey2018',
  // eslint-disable-next-line max-len
  privateKeyBase58: '2NHZPVtqrTZ1FDDkjWT2yALQ7PxifWPVKbupzPdKqpHBzCZSwigPboHDnXxmQSJ6SdZnjnskLwXurzKkSQmQS945',
  publicKeyBase58: 'G6RxBxsmPtk2dnGrJmGBuRXv1FejiCAYKAQ139wDNZRs'
};

describe('Interop Verifier API', () => {
  describe('credentials endpoint', () => {
    it('verifies a valid credential', async () => {
      const verifiableCredential = clone(mockCredential);
      let error;
      let result;
      try {
        result = await api.post('/credentials', {
          verifiableCredential
        });
      } catch(e) {
        error = e;
      }
      should.not.exist(error);
      // apisauce API does not throw it puts errors in `result.problem`
      should.not.exist(result.problem);
      should.exist(result.data.checks);
      const {checks} = result.data;
      checks.should.be.an('array');
      checks.should.have.length(1);
      const [check] = checks;
      check.verified.should.be.a('boolean');
      check.verified.should.be.true;
    });
    it('does not verify an invalid credential', async () => {
      let error;
      let result;

      const badCredential = clone(mockCredential);

      // change the degree name
      badCredential.credentialSubject.degree.name =
        'Bachelor of Science in Nursing';

      try {
        result = await api.post('/credentials', {
          verifiableCredential: badCredential
        });
      } catch(e) {
        error = e;
      }
      should.not.exist(error);
      // apisauce API does not throw it puts errors in `result.problem`
      should.not.exist(result.problem);
      should.exist(result.data.checks);
      const {checks} = result.data;
      checks.should.be.an('array');
      checks.should.have.length(1);
      const [check] = checks;
      check.verified.should.be.a('boolean');
      check.verified.should.be.false;
      // the signature is no longer valid because the data was changed
      check.error.message.should.equal('Invalid signature.');
    });
  });

  describe('presentations endpoint', () => {
    it('verifies a valid presentation', async () => {
      const verifiableCredential = clone(mockCredential);
      const presentation = vc.createPresentation({
        // FIXME: is a holder required?
        // holder: 'foo',
        id: 'urn:uuid:3e793029-d699-4096-8e74-5ebd956c3137',
        verifiableCredential
      });

      const presentationSigningKey = new Ed25519KeyPair(
        mockPresentationSigningKey);
      const fingerprint = presentationSigningKey.fingerprint();
      const verificationMethod = `did:key:${fingerprint}#${fingerprint}`;

      const suite = new Ed25519Signature2018({
        verificationMethod,
        signer: presentationSigningKey.signer(),
      });

      const challenge = 'acdbba77-9b5f-4079-887b-97e7eda06081';
      await vc.signPresentation({presentation, suite, challenge});

      let error;
      let result;
      try {
        result = await api.post('/presentations', {
          presentation
        });
      } catch(e) {
        error = e;
      }
      should.not.exist(error);
      // apisauce API does not throw it puts errors in `result.problem`
      should.not.exist(result.problem);
      should.exist(result.data.checks);

      const {checks} = result.data;
      checks.should.be.an('array');
      checks.should.have.length(2);
      const [check1, check2] = checks;
      check1.verified.should.be.a('boolean');
      check1.verified.should.be.true;
      // check2.verified.should.be.a('boolean');
      // check2.verified.should.be.true;
    });
    it.skip('does not verify an invalid presentation', async () => {

    });
  });
});
