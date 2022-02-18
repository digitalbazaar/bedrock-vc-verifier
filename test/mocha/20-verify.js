/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {config, util: {clone}} = require('bedrock');
const {CryptoLD} = require('crypto-ld');
const didKeyDriver = require('@digitalbazaar/did-method-key').driver();
const {Ed25519Signature2020} = require('@digitalbazaar/ed25519-signature-2020');
const {Ed25519VerificationKey2020} = require(
  '@digitalbazaar/ed25519-verification-key-2020');
const {httpClient} = require('@digitalbazaar/http-client');
const {agent} = require('bedrock-https-agent');
const {_documentLoader: documentLoader} = require('bedrock-vc-verifier');
const vc = require('@digitalbazaar/vc');

const cryptoLd = new CryptoLD();
cryptoLd.use(Ed25519VerificationKey2020);

// NOTE: using embedded context in mockCredential:
// https://www.w3.org/2018/credentials/examples/v1
const mockCredential = require('./mock-credential');

describe('Verify APIs', () => {
  describe('/challenges', () => {
    // FIXME: implement me
  });
  describe('/credentials/verify', () => {
    it('verifies a valid credential', async () => {
      const verifiableCredential = clone(mockCredential);
      let error;
      let result;
      try {
        result = await httpClient.post(
          `${config.server.baseUri}/verifier/credentials`, {
            agent,
            json: {
              options: {
                checks: ['proof'],
              },
              verifiableCredential,
            }
          });
      } catch(e) {
        error = e;
      }
      should.not.exist(error);
      should.exist(result.data.verified);
      result.data.verified.should.be.a('boolean');
      result.data.verified.should.equal(true);
      const {checks} = result.data;
      checks.should.be.an('array');
      checks.should.have.length(1);
      const [check] = checks;
      check.should.be.a('string');
      check.should.equal('proof');
      should.exist(result.data.results);
      result.data.results.should.be.an('array');
      result.data.results.should.have.length(1);
      const [r] = result.data.results;
      r.verified.should.be.a('boolean');
      r.verified.should.equal(true);
    });
    it('does not verify an invalid credential', async () => {
      let error;
      let result;

      const badCredential = clone(mockCredential);
      // change the degree name
      badCredential.credentialSubject.degree.name =
        'Bachelor of Science in Nursing';

      try {
        result = await httpClient.post(
          `${config.server.baseUri}/verifier/credentials`, {
            agent,
            json: {
              options: {
                checks: ['proof'],
              },
              verifiableCredential: badCredential
            }
          });
      } catch(e) {
        error = e;
      }
      should.exist(error);
      should.not.exist(result);
      should.exist(error.data);
      error.data.should.be.an('object');
      error.data.verified.should.be.a('boolean');
      error.data.verified.should.equal(false);
      error.data.error.name.should.equal('VerificationError');
      error.data.error.errors[0].message.should.equal('Invalid signature.');
    });
  });

  describe('/presentations/verify', () => {
    it('verifies a valid presentation', async () => {
      const verifiableCredential = clone(mockCredential);
      const presentation = vc.createPresentation({
        holder: 'did:test:foo',
        id: 'urn:uuid:3e793029-d699-4096-8e74-5ebd956c3137',
        verifiableCredential
      });

      const {
        methodFor
      } = await didKeyDriver.generate();

      const signingKey = methodFor({purpose: 'assertionMethod'});
      const suite = new Ed25519Signature2020({key: signingKey});

      const challenge = 'acdbba77-9b5f-4079-887b-97e7eda06081';
      await vc.signPresentation({
        presentation,
        suite,
        challenge,
        documentLoader
      });

      let error;
      let result;

      const payload = {
        options: {
          challenge,
          checks: ['proof'],
        },
        verifiablePresentation: presentation,
      };

      try {
        result = await httpClient.post(
          `${config.server.baseUri}/verifier/presentations`, {
            agent,
            json: payload
          });
      } catch(e) {
        error = e;
      }
      should.not.exist(error);
      should.exist(result.data.checks);
      const {checks} = result.data;
      checks.should.be.an('array');
      checks.should.have.length(1);
      checks[0].should.be.a('string');
      checks[0].should.equal('proof');
      should.exist(result.data.verified);
      result.data.verified.should.be.a('boolean');
      result.data.verified.should.equal(true);
      should.exist(result.data.presentationResult);
      result.data.presentationResult.should.be.an('object');
      should.exist(result.data.presentationResult.verified);
      result.data.presentationResult.verified.should.be.a('boolean');
      result.data.presentationResult.verified.should.equal(true);
      should.exist(result.data.credentialResults);
      const {data: {credentialResults}} = result;
      credentialResults.should.be.an('array');
      credentialResults.should.have.length(1);
      const [credentialResult] = credentialResults;
      should.exist(credentialResult.verified);
      credentialResult.verified.should.be.a('boolean');
      credentialResult.verified.should.equal(true);
    });
    it('returns an error if challenge is not specified', async () => {
      const verifiableCredential = clone(mockCredential);
      const presentation = vc.createPresentation({
        holder: 'foo',
        id: 'urn:uuid:3e793029-d699-4096-8e74-5ebd956c3137',
        verifiableCredential
      });
      const {
        methodFor
      } = await didKeyDriver.generate();

      const signingKey = methodFor({purpose: 'assertionMethod'});

      const suite = new Ed25519Signature2020({key: signingKey});

      const challenge = 'acdbba77-9b5f-4079-887b-97e7eda06081';
      await vc.signPresentation({
        presentation, suite, challenge, documentLoader
      });

      let error;
      let result;
      try {
        result = await httpClient.post(
          `${config.server.baseUri}/verifier/presentations`, {
            agent,
            json: {presentation}
          });
      } catch(e) {
        error = e;
      }
      should.exist(error);
      should.exist(error.data);
      should.not.exist(result);
      error.data.should.be.an('object');
      error.data.verified.should.be.a('boolean');
      error.data.verified.should.equal(false);
      error.data.error.message.should.equal('"options.challenge" is required.');
      error.data.error.name.should.equal('TypeError');
    });
    it('does not verify a presentation with a bad credential', async () => {
      const badCredential = clone(mockCredential);
      // change the degree name
      badCredential.credentialSubject.degree.name =
        'Bachelor of Science in Nursing';

      const presentation = vc.createPresentation({
        id: 'urn:uuid:3e793029-d699-4096-8e74-5ebd956c3137',
        verifiableCredential: badCredential,
      });

      const {
        methodFor
      } = await didKeyDriver.generate();

      const signingKey = methodFor({purpose: 'assertionMethod'});

      const suite = new Ed25519Signature2020({key: signingKey});

      const challenge = 'acdbba77-9b5f-4079-887b-97e7eda06081';
      await vc.signPresentation({
        presentation, suite, challenge, documentLoader
      });

      let error;
      let result;
      const payload = {
        options: {
          challenge,
          checks: ['proof'],
        },
        verifiablePresentation: presentation,
      };
      try {
        result = await httpClient.post(
          `${config.server.baseUri}/verifier/presentations`, {
            agent,
            json: payload
          });
      } catch(e) {
        error = e;
      }
      should.exist(error);
      should.not.exist(result);
      should.exist(error.data.checks);
      const {checks} = error.data;
      checks.should.be.an('array');
      checks.should.have.length(1);
      checks[0].should.be.an('object');
      checks[0].check.should.eql(['proof']);
      should.exist(error.data.verified);
      error.data.verified.should.be.a('boolean');
      error.data.verified.should.equal(false);
      should.exist(error.data.error);
      error.data.error.errors.should.be.an('array');
      error.data.error.errors.should.have.length(1);
      error.data.error.name.should.equal('VerificationError');
      const e = error.data.error.errors[0];
      e.should.be.an('object');
      should.exist(e.name);
      e.message.should.equal('Invalid signature.');
    });
  });
});
