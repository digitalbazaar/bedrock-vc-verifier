/*!
 * Copyright (c) 2020-2022 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {agent} = require('bedrock-https-agent');
const bedrock = require('bedrock');
const {CapabilityAgent} = require('@digitalbazaar/webkms-client');
const didKeyDriver = require('@digitalbazaar/did-method-key').driver();
const {documentLoader: brDocLoader} =
  require('bedrock-jsonld-document-loader');
const {Ed25519Signature2020} = require('@digitalbazaar/ed25519-signature-2020');
const helpers = require('./helpers');
const {httpClient} = require('@digitalbazaar/http-client');
const vc = require('@digitalbazaar/vc');
const mockData = require('./mock.data');
const {util: {clone}} = bedrock;

const {baseUrl} = mockData;
const serviceType = 'vc-verifier';

// NOTE: using embedded context in mockCredential:
// https://www.w3.org/2018/credentials/examples/v1
const mockCredential = require('./mock-credential');

describe('verify APIs', () => {
  let capabilityAgent;
  let verifierConfig;
  let verifierId;
  let rootZcap;
  const zcaps = {};
  beforeEach(async () => {
    const secret = '53ad64ce-8e1d-11ec-bb12-10bf48838a41';
    const handle = 'test';
    capabilityAgent = await CapabilityAgent.fromSecret({secret, handle});

    // create keystore for capability agent
    const keystoreAgent = await helpers.createKeystoreAgent(
      {capabilityAgent});

    // create EDV for storage (creating hmac and kak in the process)
    const {
      edvConfig,
      hmac,
      keyAgreementKey
    } = await helpers.createEdv({capabilityAgent, keystoreAgent});

    // get service agent to delegate to
    const serviceAgentUrl =
      `${baseUrl}/service-agents/${encodeURIComponent(serviceType)}`;
    const {data: serviceAgent} = await httpClient.get(serviceAgentUrl, {
      agent
    });

    // delegate edv, hmac, and key agreement key zcaps to service agent
    const {id: edvId} = edvConfig;
    zcaps.edv = await helpers.delegate({
      controller: serviceAgent.id,
      delegator: capabilityAgent,
      invocationTarget: edvId
    });
    const {keystoreId} = keystoreAgent;
    zcaps.hmac = await helpers.delegate({
      capability: `urn:zcap:root:${encodeURIComponent(keystoreId)}`,
      controller: serviceAgent.id,
      invocationTarget: hmac.id,
      delegator: capabilityAgent
    });
    zcaps.keyAgreementKey = await helpers.delegate({
      capability: `urn:zcap:root:${encodeURIComponent(keystoreId)}`,
      controller: serviceAgent.id,
      invocationTarget: keyAgreementKey.kmsId,
      delegator: capabilityAgent
    });

    // create verifier instance
    verifierConfig = await helpers.createConfig({capabilityAgent, zcaps});
    verifierId = verifierConfig.id;
    rootZcap = `urn:zcap:root:${encodeURIComponent(verifierId)}`;
  });
  describe('/challenges', () => {
    it('create a challenge', async () => {
      let err;
      let result;
      try {
        result = await helpers.createChallenge({capabilityAgent, verifierId});
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result.data);
      result.status.should.equal(200);
      result.data.should.have.keys(['challenge']);
      result.data.challenge.should.be.a('string');
    });
  });
  describe('/credentials/verify', () => {
    it('verifies a valid credential', async () => {
      const verifiableCredential = clone(mockCredential);
      let error;
      let result;
      try {
        const zcapClient = helpers.createZcapClient({capabilityAgent});
        result = await zcapClient.write({
          url: `${verifierId}/credentials/verify`,
          capability: rootZcap,
          json: {
            options: {
              checks: ['proof'],
            },
            verifiableCredential
          }
        });
      } catch(e) {
        error = e;
      }
      assertNoError(error);
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
      const badCredential = clone(mockCredential);
      // change the degree name
      badCredential.credentialSubject.degree.name =
        'Bachelor of Science in Nursing';

      let error;
      let result;
      try {
        const zcapClient = helpers.createZcapClient({capabilityAgent});
        result = await zcapClient.write({
          url: `${verifierConfig.id}/credentials/verify`,
          capability: rootZcap,
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
      // get signing key
      const {methodFor} = await didKeyDriver.generate();
      const signingKey = methodFor({purpose: 'assertionMethod'});
      const suite = new Ed25519Signature2020({key: signingKey});

      const verifiableCredential = clone(mockCredential);
      const presentation = vc.createPresentation({
        holder: 'did:test:foo',
        id: 'urn:uuid:3e793029-d699-4096-8e74-5ebd956c3137',
        verifiableCredential
      });

      // get challenge from verifier
      const {data: {challenge}} = await helpers.createChallenge(
        {capabilityAgent, verifierId});

      await vc.signPresentation({
        presentation,
        suite,
        challenge,
        documentLoader: brDocLoader
      });

      let error;
      let result;
      try {
        const zcapClient = helpers.createZcapClient({capabilityAgent});
        result = await zcapClient.write({
          url: `${verifierConfig.id}/presentations/verify`,
          capability: rootZcap,
          json: {
            options: {
              challenge,
              checks: ['proof'],
            },
            verifiablePresentation: presentation
          }
        });
      } catch(e) {
        error = e;
      }
      assertNoError(error);
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
    it('returns an error if bad challenge is specified', async () => {
      // get signing key
      const {methodFor} = await didKeyDriver.generate();
      const signingKey = methodFor({purpose: 'assertionMethod'});
      const suite = new Ed25519Signature2020({key: signingKey});

      const verifiableCredential = clone(mockCredential);
      const presentation = vc.createPresentation({
        holder: 'foo',
        id: 'urn:uuid:3e793029-d699-4096-8e74-5ebd956c3137',
        verifiableCredential
      });

      // expired / bad challenge
      const challenge = 'z1A9b6RjuUzVWC3VcvsFX5fPb';

      await vc.signPresentation({
        presentation, suite, challenge, documentLoader: brDocLoader
      });

      let error;
      let result;
      try {
        const zcapClient = helpers.createZcapClient({capabilityAgent});
        result = await zcapClient.write({
          url: `${verifierConfig.id}/presentations/verify`,
          capability: rootZcap,
          json: {
            options: {
              challenge,
              checks: ['proof'],
            },
            verifiablePresentation: presentation
          }
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
      error.data.error.message.should.equal('Invalid or expired challenge.');
      error.data.error.name.should.equal('DataError');
    });
    it('returns an error if challenge is not specified', async () => {
      // get signing key
      const {methodFor} = await didKeyDriver.generate();
      const signingKey = methodFor({purpose: 'assertionMethod'});
      const suite = new Ed25519Signature2020({key: signingKey});

      const verifiableCredential = clone(mockCredential);
      const presentation = vc.createPresentation({
        holder: 'foo',
        id: 'urn:uuid:3e793029-d699-4096-8e74-5ebd956c3137',
        verifiableCredential
      });

      // get challenge from verifier
      const {data: {challenge}} = await helpers.createChallenge(
        {capabilityAgent, verifierId});

      await vc.signPresentation({
        presentation, suite, challenge, documentLoader: brDocLoader
      });

      let error;
      let result;
      try {
        const zcapClient = helpers.createZcapClient({capabilityAgent});
        result = await zcapClient.write({
          url: `${verifierConfig.id}/presentations/verify`,
          capability: rootZcap,
          json: {
            options: {
              // intentionally omit challenge
              checks: ['proof'],
            },
            verifiablePresentation: presentation
          }
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
      // get signing key
      const {methodFor} = await didKeyDriver.generate();
      const signingKey = methodFor({purpose: 'assertionMethod'});
      const suite = new Ed25519Signature2020({key: signingKey});

      const badCredential = clone(mockCredential);
      // change the degree name
      badCredential.credentialSubject.degree.name =
        'Bachelor of Science in Nursing';
      const presentation = vc.createPresentation({
        id: 'urn:uuid:3e793029-d699-4096-8e74-5ebd956c3137',
        verifiableCredential: badCredential
      });

      // get challenge from verifier
      const {data: {challenge}} = await helpers.createChallenge(
        {capabilityAgent, verifierId});

      await vc.signPresentation({
        presentation, suite, challenge, documentLoader: brDocLoader
      });

      let error;
      let result;
      try {
        const zcapClient = helpers.createZcapClient({capabilityAgent});
        result = await zcapClient.write({
          url: `${verifierConfig.id}/presentations/verify`,
          capability: rootZcap,
          json: {
            options: {
              challenge,
              checks: ['proof'],
            },
            verifiablePresentation: presentation
          }
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