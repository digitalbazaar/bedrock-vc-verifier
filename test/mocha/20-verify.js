/*!
 * Copyright (c) 2020-2025 Digital Bazaar, Inc. All rights reserved.
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
import {util} from '@digitalbazaar/vpqr';

import {mockData} from './mock.data.js';

const require = createRequire(import.meta.url);

const {baseUrl} = mockData;
const serviceType = 'vc-verifier';
const didKeyDriver = _didKeyDriver();

// NOTE: using embedded context in mockCredentials:
// https://www.w3.org/2018/credentials/examples/v1
const mockCredentials = require('./mock-credentials.json');
const mockExpiredCredential = require('./mock-expired-credential.json');

const VC_CONTEXT_1 = 'https://www.w3.org/2018/credentials/v1';

describe('verify APIs', () => {
  let capabilityAgent;
  let verifierConfig;
  let verifierId;
  let rootZcap;
  let oauth2VerifierConfig;
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

    // create verifier instance w/oauth2-based authz
    oauth2VerifierConfig = await helpers.createConfig(
      {capabilityAgent, zcaps, oauth2: true});
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
    it('create a challenge w/oauth2', async () => {
      let err;
      let result;
      try {
        const configId = oauth2VerifierConfig.id;
        const accessToken = await helpers.getOAuth2AccessToken(
          {configId, action: 'write', target: '/challenges'});
        result = await helpers.createChallenge(
          {verifierId: configId, accessToken});
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
    for(const mockCredential of mockCredentials) {
      const {method} = helpers.getDidParts({did: mockCredential.issuer});
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
      description += `, DID method ${method}`;
      describe(description, () => {
        it('verifies a valid credential', async () => {
          let verifiableCredential = structuredClone(mockCredential);
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
      });
    }
    const [mockCredential] = mockCredentials;
    it('verifies a VC-JWT enveloped credential', async () => {
      let verifiableCredential = structuredClone(mockCredential);
      delete verifiableCredential.proof;
      // for simplicity, sign with existing capability agent
      const signer = capabilityAgent.getSigner();
      signer.algorithm = 'Ed25519';
      verifiableCredential.issuer = capabilityAgent.id;
      verifiableCredential = await helpers.envelopeCredential({
        verifiableCredential,
        signer
      });
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
    it('verifies a VC-JWT enveloped credential with DI', async () => {
      let verifiableCredential = structuredClone(mockCredential);
      delete verifiableCredential.proof;
      // for simplicity, sign with existing capability agent
      const signer = capabilityAgent.getSigner();
      signer.algorithm = 'Ed25519';
      verifiableCredential.issuer = capabilityAgent.id;
      verifiableCredential = await helpers.envelopeCredential({
        verifiableCredential,
        signer
      });
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
    it('verifies a QR code VCB', async () => {
      let verifiableCredential = structuredClone(mockCredential);
      delete verifiableCredential.proof;
      // for simplicity, sign with existing capability agent
      const signer = capabilityAgent.getSigner();
      signer.algorithm = 'Ed25519';
      verifiableCredential.issuer = capabilityAgent.id;
      verifiableCredential = await vc.issue({
        credential: verifiableCredential,
        documentLoader: brDocLoader,
        suite: new Ed25519Signature2020({signer})
      });
      // generate vanilla VCB
      const {payload} = await util.toQrCode({
        header: 'VC1-',
        jsonldDocument: verifiableCredential,
        registryEntryId: 1,
        documentLoader: brDocLoader,
        qrMultibaseEncoding: 'R',
        diagnose: null
      });
      const envelopedVerifiableCredential = {
        '@context': 'https://www.w3.org/ns/credentials/v2',
        id: 'data:application/vcb;barcode-format=qr_code;base64,' +
          Buffer.from(payload, 'utf8').toString('base64'),
        type: 'EnvelopedVerifiableCredential'
      };
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
            verifiableCredential: envelopedVerifiableCredential
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
    it('verifies a legacy-range QR code VCB', async () => {
      let verifiableCredential = structuredClone(mockCredential);
      delete verifiableCredential.proof;
      // for simplicity, sign with existing capability agent
      const signer = capabilityAgent.getSigner();
      signer.algorithm = 'Ed25519';
      verifiableCredential.issuer = capabilityAgent.id;
      verifiableCredential = await vc.issue({
        credential: verifiableCredential,
        documentLoader: brDocLoader,
        suite: new Ed25519Signature2020({signer})
      });
      // generate vanilla VCB
      const {payload} = await util.toQrCode({
        header: 'VC1-',
        jsonldDocument: verifiableCredential,
        format: 'legacy-range',
        registryEntryId: 1,
        documentLoader: brDocLoader,
        qrMultibaseEncoding: 'R',
        diagnose: null
      });
      const envelopedVerifiableCredential = {
        '@context': 'https://www.w3.org/ns/credentials/v2',
        id: 'data:application/vcb;barcode-format=qr_code;base64,' +
          Buffer.from(payload, 'utf8').toString('base64'),
        type: 'EnvelopedVerifiableCredential'
      };
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
            verifiableCredential: envelopedVerifiableCredential
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
    it('verifies a legacy-singleton QR code VCB', async () => {
      let verifiableCredential = structuredClone(mockCredential);
      delete verifiableCredential.proof;
      // for simplicity, sign with existing capability agent
      const signer = capabilityAgent.getSigner();
      signer.algorithm = 'Ed25519';
      verifiableCredential.issuer = capabilityAgent.id;
      verifiableCredential = await vc.issue({
        credential: verifiableCredential,
        documentLoader: brDocLoader,
        suite: new Ed25519Signature2020({signer})
      });
      // generate vanilla VCB
      const {payload} = await util.toQrCode({
        header: 'VC1-',
        jsonldDocument: verifiableCredential,
        format: 'legacy-singleton',
        documentLoader: brDocLoader,
        qrMultibaseEncoding: 'R',
        diagnose: null
      });
      const envelopedVerifiableCredential = {
        '@context': 'https://www.w3.org/ns/credentials/v2',
        id: 'data:application/vcb;barcode-format=qr_code;base64,' +
          Buffer.from(payload, 'utf8').toString('base64'),
        type: 'EnvelopedVerifiableCredential'
      };
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
            verifiableCredential: envelopedVerifiableCredential
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
    it.skip('verifies a QR code VCB w/extra information', async () => {
      // add required CBOR-LD registry entry
      const zcapClient = helpers.createZcapClient({capabilityAgent});
      /* eslint-disable */
      const registryEntry = [
        {
          type: "context",
          table:
          {
            "https://www.w3.org/ns/credentials/v2": 32768,
            "https://w3id.org/vc-barcodes/v1": 32769,
            "https://w3id.org/utopia/v2": 32770
          }
        },
        {
          type: "https://w3id.org/security#cryptosuiteString",
          table:
          {
            "ecdsa-rdfc-2019": 1,
            "ecdsa-sd-2023": 2,
            "eddsa-rdfc-2022": 3,
            "ecdsa-xi-2023": 4
          }
        }
      ];
      /* eslint-enable */
      await zcapClient.write({
        url: `${verifierId}/cborld-registry-entries`,
        json: {id: `urn:cborld:registry-entry:100`, registryEntry},
        capability: rootZcap
      });

      const verifiableCredential = {
        '@context': 'https://www.w3.org/ns/credentials/v2',
        id: 'data:application/vcb;barcode-format=qr_code,' +
          Buffer.from(mockData.vcbs.qr_code, 'utf8').toString('base64'),
        type: 'EnvelopedVerifiableCredential'
      };
      let error;
      let result;
      try {
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
    it('verifies a PDF417 VCB', async () => {
      // add required CBOR-LD registry entry
      const zcapClient = helpers.createZcapClient({capabilityAgent});
      /* eslint-disable */
      const registryEntry = [
        {
          type: "context",
          table:
          {
            "https://www.w3.org/ns/credentials/v2": 32768,
            "https://w3id.org/vc-barcodes/v1": 32769,
            "https://w3id.org/utopia/v2": 32770
          }
        },
        {
          type: "https://w3id.org/security#cryptosuiteString",
          table:
          {
            "ecdsa-rdfc-2019": 1,
            "ecdsa-sd-2023": 2,
            "eddsa-rdfc-2022": 3,
            "ecdsa-xi-2023": 4
          }
        }
      ];
      /* eslint-enable */
      await zcapClient.write({
        url: `${verifierId}/cborld-registry-entries`,
        json: {id: `urn:cborld:registry-entry:100`, registryEntry},
        capability: rootZcap
      });

      const verifiableCredential = {
        '@context': 'https://www.w3.org/ns/credentials/v2',
        id: 'data:application/vcb;barcode-format=pdf417;base64,' +
          Buffer.from(mockData.vcbs.pdf417, 'utf8').toString('base64'),
        type: 'EnvelopedVerifiableCredential'
      };
      let error;
      let result;
      try {
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
    it('verifies a valid credential w/oauth2 w/root scope', async () => {
      const verifiableCredential = structuredClone(mockCredential);
      let error;
      let result;
      try {
        const configId = oauth2VerifierConfig.id;
        const url = `${configId}/credentials/verify`;
        const accessToken = await helpers.getOAuth2AccessToken(
          {configId, action: 'write', target: '/'});
        result = await httpClient.post(url, {
          agent,
          headers: {authorization: `Bearer ${accessToken}`},
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
    it('verifies a valid credential w/oauth2 w/credentials scope',
      async () => {
        const verifiableCredential = structuredClone(mockCredential);
        let error;
        let result;
        try {
          const configId = oauth2VerifierConfig.id;
          const url = `${configId}/credentials/verify`;
          const accessToken = await helpers.getOAuth2AccessToken(
            {configId, action: 'write', target: '/credentials'});
          result = await httpClient.post(url, {
            agent,
            headers: {authorization: `Bearer ${accessToken}`},
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
    it('verifies a valid credential w/oauth2 w/targeted scope',
      async () => {
        const verifiableCredential = structuredClone(mockCredential);
        let error;
        let result;
        try {
          const configId = oauth2VerifierConfig.id;
          const url = `${configId}/credentials/verify`;
          const accessToken = await helpers.getOAuth2AccessToken(
            {configId, action: 'write', target: '/credentials/verify'});
          result = await httpClient.post(url, {
            agent,
            headers: {authorization: `Bearer ${accessToken}`},
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
    it('fails to verify a valid credential w/bad oauth2 scope',
      async () => {
        const verifiableCredential = structuredClone(mockCredential);
        let error;
        let result;
        try {
          const configId = oauth2VerifierConfig.id;
          const url = `${configId}/credentials/verify`;
          const accessToken = await helpers.getOAuth2AccessToken(
            // wrong action: `read`
            {configId, action: 'read', target: '/credentials/verify'});
          result = await httpClient.post(url, {
            agent,
            headers: {authorization: `Bearer ${accessToken}`},
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
        should.exist(error);
        should.not.exist(result);
        error.status.should.equal(403);
        error.data.type.should.equal('NotAllowedError');
        should.exist(error.data.cause);
        should.exist(error.data.cause.details);
        should.exist(error.data.cause.details.code);
        error.data.cause.details.code.should.equal(
          'ERR_JWT_CLAIM_VALIDATION_FAILED');
        should.exist(error.data.cause.details.claim);
        error.data.cause.details.claim.should.equal('scope');
      });
    it('does not verify an invalid credential', async () => {
      const badCredential = structuredClone(mockCredential);
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
    it('does not verify an expired credential', async () => {
      const expiredCredential = structuredClone(mockExpiredCredential);
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
            verifiableCredential: expiredCredential
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
      error.data.error.message.should.equal('Credential has expired.');
    });
  });

  describe('/presentations/verify', () => {
    for(const mockCredential of mockCredentials) {
      let description;
      const {type, cryptosuite} = mockCredential.proof;
      if(cryptosuite) {
        if(
          cryptosuite === 'ecdsa-2019' || cryptosuite === 'ecdsa-rdfc-2019' ||
          cryptosuite === 'ecdsa-jcs-2019' || cryptosuite === 'ecdsa-sd-2023'
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

          let verifiableCredential = structuredClone(mockCredential);
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
    it('verifies a VC-JWT enveloped VP', async () => {
      let verifiableCredential = structuredClone(mockCredential);
      delete verifiableCredential.proof;
      // for simplicity, sign with existing capability agent
      const signer = capabilityAgent.getSigner();
      signer.algorithm = 'Ed25519';
      verifiableCredential.issuer = capabilityAgent.id;
      verifiableCredential = await helpers.envelopeCredential({
        verifiableCredential,
        signer
      });

      const presentation = vc.createPresentation({
        holder: capabilityAgent.id,
        id: 'urn:uuid:3e793029-d699-4096-8e74-5ebd956c3137'
      });
      presentation.verifiableCredential = verifiableCredential;

      // get challenge from verifier
      const {data: {challenge}} = await helpers.createChallenge(
        {capabilityAgent, verifierId});

      const domain = 'rp.example';
      const envelopedPresentation = await helpers.envelopePresentation({
        verifiablePresentation: presentation,
        challenge,
        domain,
        signer
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
              domain,
              checks: ['proof'],
            },
            verifiablePresentation: envelopedPresentation
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
    it('verifies a VC-JWT 1.1 enveloped VP', async () => {
      let verifiableCredential = structuredClone(mockCredential);
      delete verifiableCredential.proof;
      // for simplicity, sign with existing capability agent
      const signer = capabilityAgent.getSigner();
      signer.algorithm = 'Ed25519';
      verifiableCredential.issuer = capabilityAgent.id;
      verifiableCredential = await helpers.envelopeCredential({
        verifiableCredential,
        signer
      });

      const presentation = vc.createPresentation({
        holder: capabilityAgent.id,
        id: 'urn:uuid:3e793029-d699-4096-8e74-5ebd956c3137'
      });
      presentation.verifiableCredential = verifiableCredential;
      // force VC-JWT 1.1 mode with `verifiableCredential` as a string
      presentation['@context'] = [VC_CONTEXT_1];
      const credentialJwt = verifiableCredential.id.slice(
        'data:application/jwt,'.length);
      presentation.verifiableCredential = [credentialJwt];

      // get challenge from verifier
      const {data: {challenge}} = await helpers.createChallenge(
        {capabilityAgent, verifierId});

      const domain = 'rp.example';
      const envelopedPresentation = await helpers.envelopePresentation({
        verifiablePresentation: presentation,
        challenge,
        domain,
        signer
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
              domain,
              checks: ['proof'],
            },
            verifiablePresentation: envelopedPresentation
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
    it('verifies a VC-JWT enveloped VP with DI VC', async () => {
      let verifiableCredential = structuredClone(mockCredential);
      delete verifiableCredential.proof;
      // for simplicity, sign with existing capability agent
      const signer = capabilityAgent.getSigner();
      signer.algorithm = 'Ed25519';
      verifiableCredential.issuer = capabilityAgent.id;
      verifiableCredential = await vc.issue({
        credential: verifiableCredential,
        documentLoader: brDocLoader,
        suite: new Ed25519Signature2020({signer})
      });
      verifiableCredential = await helpers.envelopeCredential({
        verifiableCredential,
        signer
      });

      const presentation = vc.createPresentation({
        holder: capabilityAgent.id,
        id: 'urn:uuid:3e793029-d699-4096-8e74-5ebd956c3137'
      });
      presentation.verifiableCredential = verifiableCredential;

      // get challenge from verifier
      const {data: {challenge}} = await helpers.createChallenge(
        {capabilityAgent, verifierId});

      const domain = 'rp.example';
      const envelopedPresentation = await helpers.envelopePresentation({
        verifiablePresentation: presentation,
        challenge,
        domain,
        signer
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
              domain,
              checks: ['proof'],
            },
            verifiablePresentation: envelopedPresentation
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
    it('verifies a DI VP with a VC-JWT enveloped credential', async () => {
      let verifiableCredential = structuredClone(mockCredential);
      delete verifiableCredential.proof;
      // for simplicity, sign with existing capability agent
      const signer = capabilityAgent.getSigner();
      signer.algorithm = 'Ed25519';
      verifiableCredential.issuer = capabilityAgent.id;
      verifiableCredential = await vc.issue({
        credential: verifiableCredential,
        documentLoader: brDocLoader,
        suite: new Ed25519Signature2020({signer})
      });
      verifiableCredential = await helpers.envelopeCredential({
        verifiableCredential,
        signer
      });

      const presentation = vc.createPresentation({
        holder: capabilityAgent.id,
        id: 'urn:uuid:3e793029-d699-4096-8e74-5ebd956c3137'
      });
      presentation.verifiableCredential = verifiableCredential;

      // get challenge from verifier
      const {data: {challenge}} = await helpers.createChallenge(
        {capabilityAgent, verifierId});

      const domain = 'rp.example';
      await vc.signPresentation({
        presentation,
        suite: new Ed25519Signature2020({signer}),
        challenge,
        domain,
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
              domain,
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
    it('verifies an enveloped VP containing a VCB', async () => {
      let verifiableCredential = structuredClone(mockCredential);
      delete verifiableCredential.id;
      delete verifiableCredential.proof;
      // for simplicity, sign with existing capability agent
      const signer = capabilityAgent.getSigner();
      signer.algorithm = 'Ed25519';
      verifiableCredential.issuer = capabilityAgent.id;
      verifiableCredential = await vc.issue({
        credential: verifiableCredential,
        documentLoader: brDocLoader,
        suite: new Ed25519Signature2020({signer})
      });
      const verifiablePresentation = {
        '@context': 'https://www.w3.org/2018/credentials/v1',
        type: 'VerifiablePresentation',
        verifiableCredential: [verifiableCredential]
      };
      // generate vanilla VCB
      const {payload} = await util.toQrCode({
        header: 'VP1-',
        jsonldDocument: verifiablePresentation,
        registryEntryId: 1,
        documentLoader: brDocLoader,
        qrMultibaseEncoding: 'R',
        diagnose: null
      });
      const envelopedVerifiablePresentation = {
        '@context': 'https://www.w3.org/ns/credentials/v2',
        id: 'data:application/vcb;barcode-format=qr_code;base64,' +
          Buffer.from(payload, 'utf8').toString('base64'),
        type: 'EnvelopedVerifiablePresentation'
      };
      // get challenge from verifier
      const {data: {challenge}} = await helpers.createChallenge(
        {capabilityAgent, verifierId});
      let error;
      let result;
      try {
        const zcapClient = helpers.createZcapClient({capabilityAgent});
        result = await zcapClient.write({
          url: `${verifierId}/presentations/verify`,
          capability: rootZcap,
          json: {
            verifiablePresentation: envelopedVerifiablePresentation,
            options: {
              challenge,
              checks: [],
            }
          }
        });
      } catch(e) {
        error = e;
      }
      assertNoError(error);
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
    it('should not verify an enveloped VP containing a VCB' +
      'with a bad signature', async () => {
      let verifiableCredential = structuredClone(mockCredential);
      delete verifiableCredential.id;
      delete verifiableCredential.proof;
      // for simplicity, sign with existing capability agent
      const signer = capabilityAgent.getSigner();
      signer.algorithm = 'Ed25519';
      verifiableCredential.issuer = capabilityAgent.id;
      verifiableCredential = await vc.issue({
        credential: verifiableCredential,
        documentLoader: brDocLoader,
        suite: new Ed25519Signature2020({signer})
      });
      verifiableCredential = {
        ...structuredClone(verifiableCredential),
        id: 'http://example.gov/credentials/3732/INVALID-SIGNATURE'
      };
      const verifiablePresentation = {
        '@context': 'https://www.w3.org/2018/credentials/v1',
        type: 'VerifiablePresentation',
        verifiableCredential: [verifiableCredential]
      };
      // generate vanilla VCB
      const {payload} = await util.toQrCode({
        header: 'VP1-',
        jsonldDocument: verifiablePresentation,
        registryEntryId: 1,
        documentLoader: brDocLoader,
        qrMultibaseEncoding: 'R',
        diagnose: null
      });
      const envelopedVerifiablePresentation = {
        '@context': 'https://www.w3.org/ns/credentials/v2',
        id: 'data:application/vcb;barcode-format=qr_code;base64,' +
          Buffer.from(payload, 'utf8').toString('base64'),
        type: 'EnvelopedVerifiablePresentation'
      };
      // get challenge from verifier
      const {data: {challenge}} = await helpers.createChallenge(
        {capabilityAgent, verifierId});
      let error;
      let result;
      try {
        const zcapClient = helpers.createZcapClient({capabilityAgent});
        result = await zcapClient.write({
          url: `${verifierId}/presentations/verify`,
          capability: rootZcap,
          json: {
            verifiablePresentation: envelopedVerifiablePresentation,
            options: {
              challenge,
              checks: [],
            }
          }
        });
      } catch(e) {
        error = e;
      }
      should.not.exist(result);
      should.exist(error.data);
      error.data.error.message.should.equal('Verification error.');
      should.exist(error.data.verified);
      error.data.verified.should.be.a('boolean');
      error.data.verified.should.equal(false);
      should.exist(error.data.presentationResult);
      error.data.presentationResult.should.be.an('object');
      should.exist(error.data.presentationResult.verified);
      error.data.presentationResult.verified.should.be.a('boolean');
      error.data.presentationResult.verified.should.equal(false);
      should.exist(error.data.presentationResult.credentialResults);
      const {data: {presentationResult: {credentialResults}}} = error;
      credentialResults.should.be.an('array');
      credentialResults.should.have.length(1);
      const [credentialResult] = credentialResults;
      should.exist(credentialResult.verified);
      credentialResult.verified.should.be.a('boolean');
      credentialResult.verified.should.equal(false);
    });
    it('verifies a DI VP with a VCB enveloped VC', async () => {
      let verifiableCredential = structuredClone(mockCredential);
      delete verifiableCredential.proof;
      // for simplicity, sign with existing capability agent
      const signer = capabilityAgent.getSigner();
      signer.algorithm = 'Ed25519';
      verifiableCredential.issuer = capabilityAgent.id;
      verifiableCredential = await vc.issue({
        credential: verifiableCredential,
        documentLoader: brDocLoader,
        suite: new Ed25519Signature2020({signer})
      });
      const {payload} = await util.toQrCode({
        header: 'VC1-',
        jsonldDocument: verifiableCredential,
        registryEntryId: 1,
        documentLoader: brDocLoader,
        qrMultibaseEncoding: 'R',
        diagnose: null
      });
      verifiableCredential = {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        id: 'data:application/vcb;barcode-format=qr_code;base64,' +
          Buffer.from(payload, 'utf8').toString('base64'),
        type: 'EnvelopedVerifiableCredential'
      };
      const presentation = vc.createPresentation({
        holder: capabilityAgent.id,
        id: 'urn:uuid:3e793029-d699-4096-8e74-5ebd956c3137'
      });
      presentation.verifiableCredential = verifiableCredential;

      // get challenge from verifier
      const {data: {challenge}} = await helpers.createChallenge(
        {capabilityAgent, verifierId});

      const domain = 'rp.example';
      await vc.signPresentation({
        presentation,
        suite: new Ed25519Signature2020({signer}),
        challenge,
        domain,
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
              domain,
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
    it('verifies a DI VP w/legacy-range VCB enveloped VC', async () => {
      let verifiableCredential = structuredClone(mockCredential);
      delete verifiableCredential.proof;
      // for simplicity, sign with existing capability agent
      const signer = capabilityAgent.getSigner();
      signer.algorithm = 'Ed25519';
      verifiableCredential.issuer = capabilityAgent.id;
      verifiableCredential = await vc.issue({
        credential: verifiableCredential,
        documentLoader: brDocLoader,
        suite: new Ed25519Signature2020({signer})
      });
      const {payload} = await util.toQrCode({
        header: 'VC1-',
        jsonldDocument: verifiableCredential,
        format: 'legacy-range',
        registryEntryId: 1,
        documentLoader: brDocLoader,
        qrMultibaseEncoding: 'R',
        diagnose: null
      });
      verifiableCredential = {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        id: 'data:application/vcb;barcode-format=qr_code;base64,' +
          Buffer.from(payload, 'utf8').toString('base64'),
        type: 'EnvelopedVerifiableCredential'
      };
      const presentation = vc.createPresentation({
        holder: capabilityAgent.id,
        id: 'urn:uuid:3e793029-d699-4096-8e74-5ebd956c3137'
      });
      presentation.verifiableCredential = verifiableCredential;

      // get challenge from verifier
      const {data: {challenge}} = await helpers.createChallenge(
        {capabilityAgent, verifierId});

      const domain = 'rp.example';
      await vc.signPresentation({
        presentation,
        suite: new Ed25519Signature2020({signer}),
        challenge,
        domain,
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
              domain,
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
    it('verifies a DI VP w/legacy-singleton VCB enveloped VC', async () => {
      let verifiableCredential = structuredClone(mockCredential);
      delete verifiableCredential.proof;
      // for simplicity, sign with existing capability agent
      const signer = capabilityAgent.getSigner();
      signer.algorithm = 'Ed25519';
      verifiableCredential.issuer = capabilityAgent.id;
      verifiableCredential = await vc.issue({
        credential: verifiableCredential,
        documentLoader: brDocLoader,
        suite: new Ed25519Signature2020({signer})
      });
      const {payload} = await util.toQrCode({
        header: 'VC1-',
        jsonldDocument: verifiableCredential,
        format: 'legacy-singleton',
        documentLoader: brDocLoader,
        qrMultibaseEncoding: 'R',
        diagnose: null
      });
      verifiableCredential = {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        id: 'data:application/vcb;barcode-format=qr_code;base64,' +
          Buffer.from(payload, 'utf8').toString('base64'),
        type: 'EnvelopedVerifiableCredential'
      };
      const presentation = vc.createPresentation({
        holder: capabilityAgent.id,
        id: 'urn:uuid:3e793029-d699-4096-8e74-5ebd956c3137'
      });
      presentation.verifiableCredential = verifiableCredential;

      // get challenge from verifier
      const {data: {challenge}} = await helpers.createChallenge(
        {capabilityAgent, verifierId});

      const domain = 'rp.example';
      await vc.signPresentation({
        presentation,
        suite: new Ed25519Signature2020({signer}),
        challenge,
        domain,
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
              domain,
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
    it('verifies a VC-JWT + DI VP', async () => {
      let verifiableCredential = structuredClone(mockCredential);
      delete verifiableCredential.proof;
      // for simplicity, sign with existing capability agent
      const signer = capabilityAgent.getSigner();
      signer.algorithm = 'Ed25519';
      verifiableCredential.issuer = capabilityAgent.id;
      verifiableCredential = await vc.issue({
        credential: verifiableCredential,
        documentLoader: brDocLoader,
        suite: new Ed25519Signature2020({signer})
      });
      verifiableCredential = await helpers.envelopeCredential({
        verifiableCredential,
        signer
      });

      const presentation = vc.createPresentation({
        holder: capabilityAgent.id,
        id: 'urn:uuid:3e793029-d699-4096-8e74-5ebd956c3137'
      });
      presentation.verifiableCredential = verifiableCredential;

      // get challenge from verifier
      const {data: {challenge}} = await helpers.createChallenge(
        {capabilityAgent, verifierId});

      const domain = 'rp.example';
      await vc.signPresentation({
        presentation,
        suite: new Ed25519Signature2020({signer}),
        challenge,
        domain,
        documentLoader: brDocLoader
      });

      const envelopedPresentation = await helpers.envelopePresentation({
        verifiablePresentation: presentation,
        challenge,
        domain,
        signer
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
              domain,
              checks: ['proof'],
            },
            verifiablePresentation: envelopedPresentation
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
    it('fails to verify a VC-JWT enveloped VP with DI VC', async () => {
      let verifiableCredential = structuredClone(mockCredential);
      // intentionally keep proof and change `issuer`...
      // for simplicity, sign with existing capability agent
      const signer = capabilityAgent.getSigner();
      signer.algorithm = 'Ed25519';
      verifiableCredential.issuer = capabilityAgent.id;
      verifiableCredential = await vc.issue({
        credential: verifiableCredential,
        documentLoader: brDocLoader,
        suite: new Ed25519Signature2020({signer})
      });
      verifiableCredential = await helpers.envelopeCredential({
        verifiableCredential,
        signer
      });

      const presentation = vc.createPresentation({
        holder: capabilityAgent.id,
        id: 'urn:uuid:3e793029-d699-4096-8e74-5ebd956c3137'
      });
      presentation.verifiableCredential = verifiableCredential;

      // get challenge from verifier
      const {data: {challenge}} = await helpers.createChallenge(
        {capabilityAgent, verifierId});

      const domain = 'rp.example';
      const envelopedPresentation = await helpers.envelopePresentation({
        verifiablePresentation: presentation,
        challenge,
        domain,
        signer
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
              domain,
              checks: ['proof'],
            },
            verifiablePresentation: envelopedPresentation
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
      error.data.error.name.should.equal('VerificationError');
      error.data.credentialResults[0].verified.should.equal(false);
      const proofResults = error.data.credentialResults[0].proofResult.results;
      // one proof should pass, one should fail
      const same = (proofResults[0].verified === proofResults[1].verified);
      same.should.equal(false);
      const failedProofResult = !proofResults[0].verified ?
        proofResults[0] : proofResults[1];
      failedProofResult.verified.should.equal(false);
      failedProofResult.error.message.should.equal('Invalid signature.');
    });
    it('verifies a valid presentation w/oauth2 w/root scope', async () => {
      // get signing key
      const {methodFor} = await didKeyDriver.generate();
      const signingKey = methodFor({purpose: 'assertionMethod'});
      const suite = new Ed25519Signature2020({key: signingKey});

      const verifiableCredential = structuredClone(mockCredential);
      const presentation = vc.createPresentation({
        holder: 'did:test:foo',
        id: 'urn:uuid:3e793029-d699-4096-8e74-5ebd956c3137',
        verifiableCredential
      });

      // get challenge from verifier
      const configId = oauth2VerifierConfig.id;
      const accessToken = await helpers.getOAuth2AccessToken(
        {configId, action: 'write', target: '/challenges'});
      const {data: {challenge}} = await helpers.createChallenge(
        {verifierId: configId, accessToken});

      await vc.signPresentation({
        presentation,
        suite,
        challenge,
        documentLoader: brDocLoader
      });

      let error;
      let result;
      try {
        const url = `${configId}/presentations/verify`;
        const accessToken = await helpers.getOAuth2AccessToken(
          {configId, action: 'write', target: '/'});
        result = await httpClient.post(url, {
          agent,
          headers: {authorization: `Bearer ${accessToken}`},
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
    it('verifies a valid presentation w/oauth2 w/vps scope', async () => {
      // get signing key
      const {methodFor} = await didKeyDriver.generate();
      const signingKey = methodFor({purpose: 'assertionMethod'});
      const suite = new Ed25519Signature2020({key: signingKey});

      const verifiableCredential = structuredClone(mockCredential);
      const presentation = vc.createPresentation({
        holder: 'did:test:foo',
        id: 'urn:uuid:3e793029-d699-4096-8e74-5ebd956c3137',
        verifiableCredential
      });

      // get challenge from verifier
      const configId = oauth2VerifierConfig.id;
      const accessToken = await helpers.getOAuth2AccessToken(
        {configId, action: 'write', target: '/challenges'});
      const {data: {challenge}} = await helpers.createChallenge(
        {verifierId: configId, accessToken});

      await vc.signPresentation({
        presentation,
        suite,
        challenge,
        documentLoader: brDocLoader
      });

      let error;
      let result;
      try {
        const url = `${configId}/presentations/verify`;
        const accessToken = await helpers.getOAuth2AccessToken(
          {configId, action: 'write', target: '/presentations'});
        result = await httpClient.post(url, {
          agent,
          headers: {authorization: `Bearer ${accessToken}`},
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
    it('verifies a valid presentation w/oauth2 w/targeted scope',
      async () => {
      // get signing key
        const {methodFor} = await didKeyDriver.generate();
        const signingKey = methodFor({purpose: 'assertionMethod'});
        const suite = new Ed25519Signature2020({key: signingKey});

        const verifiableCredential = structuredClone(mockCredential);
        const presentation = vc.createPresentation({
          holder: 'did:test:foo',
          id: 'urn:uuid:3e793029-d699-4096-8e74-5ebd956c3137',
          verifiableCredential
        });

        // get challenge from verifier
        const configId = oauth2VerifierConfig.id;
        const accessToken = await helpers.getOAuth2AccessToken(
          {configId, action: 'write', target: '/challenges'});
        const {data: {challenge}} = await helpers.createChallenge(
          {verifierId: configId, accessToken});

        await vc.signPresentation({
          presentation,
          suite,
          challenge,
          documentLoader: brDocLoader
        });

        let error;
        let result;
        try {
          const url = `${configId}/presentations/verify`;
          const accessToken = await helpers.getOAuth2AccessToken(
            {configId, action: 'write', target: '/presentations/verify'});
          result = await httpClient.post(url, {
            agent,
            headers: {authorization: `Bearer ${accessToken}`},
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
    it('fails to verify a valid presentation w/bad action scope',
      async () => {
      // get signing key
        const {methodFor} = await didKeyDriver.generate();
        const signingKey = methodFor({purpose: 'assertionMethod'});
        const suite = new Ed25519Signature2020({key: signingKey});

        const verifiableCredential = structuredClone(mockCredential);
        const presentation = vc.createPresentation({
          holder: 'did:test:foo',
          id: 'urn:uuid:3e793029-d699-4096-8e74-5ebd956c3137',
          verifiableCredential
        });

        // get challenge from verifier
        const configId = oauth2VerifierConfig.id;
        const accessToken = await helpers.getOAuth2AccessToken(
          {configId, action: 'write', target: '/challenges'});
        const {data: {challenge}} = await helpers.createChallenge(
          {verifierId: configId, accessToken});

        await vc.signPresentation({
          presentation,
          suite,
          challenge,
          documentLoader: brDocLoader
        });

        let error;
        let result;
        try {
          const url = `${configId}/presentations/verify`;
          const accessToken = await helpers.getOAuth2AccessToken(
            // wrong action: `read`
            {configId, action: 'read', target: '/'});
          result = await httpClient.post(url, {
            agent,
            headers: {authorization: `Bearer ${accessToken}`},
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
        error.status.should.equal(403);
        error.data.type.should.equal('NotAllowedError');
        should.exist(error.data.cause);
        should.exist(error.data.cause.details);
        should.exist(error.data.cause.details.code);
        error.data.cause.details.code.should.equal(
          'ERR_JWT_CLAIM_VALIDATION_FAILED');
        should.exist(error.data.cause.details.claim);
        error.data.cause.details.claim.should.equal('scope');
      });
    it('fails to verify a valid presentation w/bad path scope',
      async () => {
      // get signing key
        const {methodFor} = await didKeyDriver.generate();
        const signingKey = methodFor({purpose: 'assertionMethod'});
        const suite = new Ed25519Signature2020({key: signingKey});

        const verifiableCredential = structuredClone(mockCredential);
        const presentation = vc.createPresentation({
          holder: 'did:test:foo',
          id: 'urn:uuid:3e793029-d699-4096-8e74-5ebd956c3137',
          verifiableCredential
        });

        // get challenge from verifier
        const configId = oauth2VerifierConfig.id;
        const accessToken = await helpers.getOAuth2AccessToken(
          {configId, action: 'write', target: '/challenges'});
        const {data: {challenge}} = await helpers.createChallenge(
          {verifierId: configId, accessToken});

        await vc.signPresentation({
          presentation,
          suite,
          challenge,
          documentLoader: brDocLoader
        });

        let error;
        let result;
        try {
          const url = `${configId}/presentations/verify`;
          const accessToken = await helpers.getOAuth2AccessToken(
            // wrong path: `/foo`
            {configId, action: 'write', target: '/foo'});
          result = await httpClient.post(url, {
            agent,
            headers: {authorization: `Bearer ${accessToken}`},
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
        error.status.should.equal(403);
        error.data.type.should.equal('NotAllowedError');
        should.exist(error.data.cause);
        should.exist(error.data.cause.details);
        should.exist(error.data.cause.details.code);
        error.data.cause.details.code.should.equal(
          'ERR_JWT_CLAIM_VALIDATION_FAILED');
        should.exist(error.data.cause.details.claim);
        error.data.cause.details.claim.should.equal('scope');
      });
    it('returns an error if bad challenge is specified', async () => {
      // get signing key
      const {methodFor} = await didKeyDriver.generate();
      const signingKey = methodFor({purpose: 'assertionMethod'});
      const suite = new Ed25519Signature2020({key: signingKey});

      const verifiableCredential = structuredClone(mockCredential);
      const presentation = vc.createPresentation({
        holder: 'urn:uuid:c8d4f2d0-11ea-4603-8b8b-fb24fa6b29c0',
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
          url: `${verifierId}/presentations/verify`,
          capability: rootZcap,
          json: {
            options: {
              challenge,
              // check challenge via verifier challenge management
              checks: ['proof', 'challenge'],
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
      error.data.error.message.should.equal(
        'Invalid or expired challenge.');
      error.data.error.name.should.equal('DataError');
    });
    it('should pass if unmanaged challenge is specified', async () => {
      // get signing key
      const {methodFor} = await didKeyDriver.generate();
      const signingKey = methodFor({purpose: 'assertionMethod'});
      const suite = new Ed25519Signature2020({key: signingKey});

      const verifiableCredential = structuredClone(mockCredential);
      const presentation = vc.createPresentation({
        holder: 'urn:uuid:c8d4f2d0-11ea-4603-8b8b-fb24fa6b29c0',
        id: 'urn:uuid:3e793029-d699-4096-8e74-5ebd956c3137',
        verifiableCredential
      });

      // unmanaged challenge
      const challenge = '677bb7db-3e60-45c2-b3a0-e61e88b0b5d4';

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
              // do not include `challenge` in checks to do local challenge
              // management
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
    it('returns an error if challenge is not specified', async () => {
      // get signing key
      const {methodFor} = await didKeyDriver.generate();
      const signingKey = methodFor({purpose: 'assertionMethod'});
      const suite = new Ed25519Signature2020({key: signingKey});

      const verifiableCredential = structuredClone(mockCredential);
      const presentation = vc.createPresentation({
        holder: 'urn:uuid:c8d4f2d0-11ea-4603-8b8b-fb24fa6b29c0',
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
          url: `${verifierId}/presentations/verify`,
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
      error.data.error.message.should.equal(
        '"options.challenge" is required.');
      error.data.error.name.should.equal('TypeError');
    });
    it('does not verify a presentation with a bad credential', async () => {
      // get signing key
      const {methodFor} = await didKeyDriver.generate();
      const signingKey = methodFor({purpose: 'assertionMethod'});
      const suite = new Ed25519Signature2020({key: signingKey});

      const badCredential = structuredClone(mockCredential);
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
