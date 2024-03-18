/*!
 * Copyright (c) 2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from './helpers.js';
import * as vc from '@digitalbazaar/vc';
import {driver as _didKeyDriver} from '@digitalbazaar/did-method-key';
import {agent} from '@bedrock/https-agent';
import {documentLoader as brDocLoader} from '@bedrock/jsonld-document-loader';
import {CapabilityAgent} from '@digitalbazaar/webkms-client';
import {
  createDiscloseCryptosuite as createBbs2023DiscloseCryptosuite
} from '@digitalbazaar/bbs-2023-cryptosuite';
import {
  createDiscloseCryptosuite as createEcdsaSd2023DiscloseCryptosuite
} from '@digitalbazaar/ecdsa-sd-2023-cryptosuite';
import {createRequire} from 'node:module';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {httpClient} from '@digitalbazaar/http-client';
import {klona} from 'klona';

import {mockData} from './mock.data.js';

const require = createRequire(import.meta.url);

const {baseUrl} = mockData;
const serviceType = 'vc-verifier';
const didKeyDriver = _didKeyDriver();

// NOTE: using embedded context in mockCredentials:
// https://www.w3.org/2018/credentials/examples/v1
const mockCredentials = require('./mock-credentials.json');

describe('did resolver option', () => {
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

    // create verifier instance w/DID resolver option
    const configOptions = {
      verifyOptions: {
        didResolver: {
          // use mocked universal DID resolver on own server
          url: `${baseUrl}/1.0/identifiers`
        }
      }
    };
    verifierConfig = await helpers.createConfig({
      capabilityAgent, configOptions, zcaps
    });
    verifierId = verifierConfig.id;
    rootZcap = `urn:zcap:root:${encodeURIComponent(verifierId)}`;
  });
  describe('/credentials/verify', () => {
    for(const mockCredential of mockCredentials) {
      let description;
      const {type, cryptosuite} = mockCredential.proof;
      if(cryptosuite) {
        if(cryptosuite === 'ecdsa-2019') {
          const keyType = helpers.getEcdsaAlgorithms({
            credential: mockCredential
          })[0];
          description = `${type} - ${cryptosuite}, keytype: ${keyType}`;
        } else {
          description = `${type} - ${cryptosuite}`;
        }
      } else {
        description = `${type}`;
      }
      describe(description, () => {
        it('verifies a valid credential', async () => {
          let verifiableCredential = klona(mockCredential);
          if(cryptosuite === 'ecdsa-sd-2023') {
            const cryptosuite = createEcdsaSd2023DiscloseCryptosuite({
              selectivePointers: [
                '/credentialSubject/id'
              ]
            });
            const suite = new DataIntegrityProof({cryptosuite});
            const derivedVC = await vc.derive({
              verifiableCredential,
              suite,
              documentLoader: brDocLoader
            });
            verifiableCredential = derivedVC;
          } else if(cryptosuite === 'bbs-2023') {
            const cryptosuite = createBbs2023DiscloseCryptosuite({
              selectivePointers: [
                '/credentialSubject/id'
              ]
            });
            const suite = new DataIntegrityProof({cryptosuite});
            const derivedVC = await vc.derive({
              verifiableCredential,
              suite,
              documentLoader: brDocLoader
            });
            verifiableCredential = derivedVC;
          }
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
            console.log('error', error.message);
          }
          //process.exit(1);
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
      });
    }
    const [mockCredential] = mockCredentials;
    it('does not verify an invalid credential', async () => {
      const badCredential = klona(mockCredential);
      // change the degree name
      badCredential.credentialSubject.degree.name =
        'Bachelor of Science in Nursing';
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
    for(const mockCredential of mockCredentials) {
      let description;
      const {type, cryptosuite} = mockCredential.proof;
      if(cryptosuite) {
        if(
          cryptosuite === 'ecdsa-2019' || cryptosuite === 'ecdsa-rdfc-2019' ||
          cryptosuite === 'ecdsa-sd-2023'
        ) {
          const keyType = helpers.getEcdsaAlgorithms({
            credential: mockCredential
          })[0];
          description = `${type} - ${cryptosuite}, keytype: ${keyType}`;
        } else {
          description = `${type} - ${cryptosuite}`;
        }
      } else {
        description = `${type}`;
      }
      describe(description, () => {
        it('verifies a valid presentation', async () => {
          // get signing key
          const {methodFor} = await didKeyDriver.generate();
          const signingKey = methodFor({purpose: 'assertionMethod'});
          const suite = new Ed25519Signature2020({key: signingKey});

          let verifiableCredential = klona(mockCredential);
          if(cryptosuite === 'ecdsa-sd-2023') {
            const cryptosuite = createEcdsaSd2023DiscloseCryptosuite({
              selectivePointers: [
                '/credentialSubject/id'
              ]
            });
            const suite = new DataIntegrityProof({cryptosuite});
            const derivedVC = await vc.derive({
              verifiableCredential,
              suite,
              documentLoader: brDocLoader
            });
            verifiableCredential = derivedVC;
          } else if(cryptosuite === 'bbs-2023') {
            const cryptosuite = createBbs2023DiscloseCryptosuite({
              selectivePointers: [
                '/credentialSubject/id'
              ]
            });
            const suite = new DataIntegrityProof({cryptosuite});
            const derivedVC = await vc.derive({
              verifiableCredential,
              suite,
              documentLoader: brDocLoader
            });
            verifiableCredential = derivedVC;
          }
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
              url: `${verifierId}/presentations/verify`,
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
      });
    }
    const [mockCredential] = mockCredentials;
    it('does not verify a presentation with a bad credential', async () => {
      // get signing key
      const {methodFor} = await didKeyDriver.generate();
      const signingKey = methodFor({purpose: 'assertionMethod'});
      const suite = new Ed25519Signature2020({key: signingKey});

      const badCredential = klona(mockCredential);
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
          url: `${verifierId}/presentations/verify`,
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
