/*!
 * Copyright (c) 2025-2026 Digital Bazaar, Inc.
 */
import * as helpers from './helpers.js';
import * as mdlUtils from './mdlUtils.js';
import {generateCertificateChain, generateKeyPair} from './certUtils.js';
import {agent} from '@bedrock/https-agent';
import {CapabilityAgent} from '@digitalbazaar/webkms-client';
import {httpClient} from '@digitalbazaar/http-client';
import {oid4vp} from '@digitalbazaar/oid4-client';
import {randomUUID} from 'node:crypto';

import {mockData} from './mock.data.js';

const {baseUrl} = mockData;
const serviceType = 'vc-verifier';

const MDL_NAMESPACE = 'org.iso.18013.5.1';
const MDOC_TYPE_MDL = `${MDL_NAMESPACE}.mDL`;
const PRESENTATION_DEFINITION_1 = {
  id: 'mdl-test-age-over-21',
  input_descriptors: [
    {
      id: MDOC_TYPE_MDL,
      format: {
        mso_mdoc: {
          alg: ['ES256']
        }
      },
      constraints: {
        limit_disclosure: 'required',
        fields: [
          {
            // eslint-disable-next-line @stylistic/quotes
            path: ["$['org.iso.18013.5.1']['age_over_21']"],
            intent_to_retain: false
          }
        ]
      }
    }
  ]
};

const VC_CONTEXT_2 = 'https://www.w3.org/ns/credentials/v2';

describe('mdoc /presentations/verify', () => {
  let capabilityAgent;
  let verifierConfig;
  let verifierId;
  let rootZcap;
  let certChain;
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

    // add `mdoc` config to verifier config options
    const caStoreId = `urn:mdoc-ca-store:${randomUUID()}`;
    const configOptions = {
      verifyOptions: {
        mdoc: {
          caStores: [caStoreId]
        }
      }
    };

    // create verifier instance
    verifierConfig = await helpers.createConfig({
      capabilityAgent, zcaps, configOptions
    });
    verifierId = verifierConfig.id;
    rootZcap = `urn:zcap:root:${encodeURIComponent(verifierId)}`;

    // create a certificate chain that ends in the mdoc issuer (leaf)
    certChain = await generateCertificateChain();

    // add mdoc CA store with intermediate certificate
    {
      const client = helpers.createZcapClient({capabilityAgent});
      const url = `${verifierConfig.id}/mdoc/ca-stores`;
      const trustedCertificates = [certChain.intermediate.pemCertificate];
      await client.write({
        url, json: {id: caStoreId, trustedCertificates},
        capability: rootZcap
      });
    }
  });

  it('verifies a valid Annex B presentation', async () => {
    // get device key pair
    const deviceKeyPair = await mdlUtils.generateDeviceKeyPair();

    // issue an mdoc
    const issuerPrivateJwk = certChain.leaf.subject.jwk;
    const issuerCertificate = certChain.leaf.pemCertificate;
    const mdoc = await mdlUtils.issue({
      issuerPrivateJwk, issuerCertificate,
      devicePublicJwk: deviceKeyPair.publicJwk
    });

    // get challenge from verifier
    const {data: {challenge}} = await helpers.createChallenge(
      {capabilityAgent, verifierId});

    // create an mdoc handover
    const handover = {
      type: 'AnnexBHandover',
      mdocGeneratedNonce: randomUUID(),
      clientId: randomUUID(),
      // note: expected to be an OID4VP exchange response URL
      responseUri: 'https://test.example',
      verifierGeneratedNonce: challenge
    };

    // create mdoc enveloped presentation
    const envelopedPresentation = await mdlUtils.createPresentation({
      presentationDefinition: PRESENTATION_DEFINITION_1,
      mdoc,
      handover,
      devicePrivateJwk: deviceKeyPair.privateJwk
    });

    // uncomment code to run local mdoc verification
    /*
    const vpToken = envelopedPresentation.id.slice(
      envelopedPresentation.id.indexOf(',') + 1);
    const deviceResponse = Buffer.from(vpToken, 'base64url');
    await mdlUtils.verifyPresentation({
      deviceResponse, handover,
      trustedCertificates: [certChain.intermediate.pemCertificate]
    });
    */

    // send VP to verifier VC API
    let error;
    let result;
    try {
      const zcapClient = helpers.createZcapClient({capabilityAgent});
      result = await zcapClient.write({
        url: `${verifierId}/presentations/verify`,
        capability: rootZcap,
        json: {
          options: {
            domain: handover.responseUri,
            challenge,
            // ensure `challenge` is checked
            checks: ['challenge'],
            mdoc: {
              sessionTranscript: Buffer
                .from(await oid4vp.mdoc.encodeSessionTranscript({handover}))
                .toString('base64url')
            }
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
    checks[0].should.equal('challenge');
    should.exist(result.data.verified);
    result.data.verified.should.be.a('boolean');
    result.data.verified.should.equal(true);
    should.exist(result.data.presentationResult);
    result.data.presentationResult.should.be.an('object');
    should.exist(result.data.presentationResult.verified);
    result.data.presentationResult.verified.should.be.a('boolean');
    result.data.presentationResult.verified.should.equal(true);
    should.exist(result.data.presentation);
    result.data.presentation.should.be.an('object');
    result.data.presentation.type.should.equal('VerifiablePresentation');
    result.data.presentation.verifiableCredential.should.be.an('object');
    result.data.presentation.verifiableCredential.type.should
      .equal('EnvelopedVerifiableCredential');
  });

  it('verifies a valid Annex C presentation', async () => {
    // get device key pair
    const deviceKeyPair = await mdlUtils.generateDeviceKeyPair();

    // issue an mdoc
    const issuerPrivateJwk = certChain.leaf.subject.jwk;
    const issuerCertificate = certChain.leaf.pemCertificate;
    const mdoc = await mdlUtils.issue({
      issuerPrivateJwk, issuerCertificate,
      devicePublicJwk: deviceKeyPair.publicJwk
    });

    // get challenge from verifier
    const {data: {challenge}} = await helpers.createChallenge(
      {capabilityAgent, verifierId});

    // create an Annex C mdoc handover
    const handover = {
      type: 'dcapi',
      origin: 'https://test.example',
      nonce: randomUUID(),
      // note: expected to be an OID4VP key, not the device key
      recipientPublicJwk: deviceKeyPair.publicJwk
    };

    // create mdoc enveloped presentation
    const envelopedPresentation = await mdlUtils.createPresentation({
      presentationDefinition: PRESENTATION_DEFINITION_1,
      mdoc,
      handover,
      devicePrivateJwk: deviceKeyPair.privateJwk
    });

    // uncomment code to run local mdoc verification
    /*
    const vpToken = envelopedPresentation.id.slice(
      envelopedPresentation.id.indexOf(',') + 1);
    const deviceResponse = Buffer.from(vpToken, 'base64url');
    await mdlUtils.verifyPresentation({
      deviceResponse, handover,
      trustedCertificates: [certChain.intermediate.pemCertificate]
    });
    */

    // send VP to verifier VC API
    let error;
    let result;
    try {
      const zcapClient = helpers.createZcapClient({capabilityAgent});
      result = await zcapClient.write({
        url: `${verifierId}/presentations/verify`,
        capability: rootZcap,
        json: {
          options: {
            domain: handover.responseUri,
            challenge,
            // ensure `challenge` is checked
            checks: ['challenge'],
            mdoc: {
              sessionTranscript: Buffer
                .from(await oid4vp.mdoc.encodeSessionTranscript({handover}))
                .toString('base64url')
            }
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
    checks[0].should.equal('challenge');
    should.exist(result.data.verified);
    result.data.verified.should.be.a('boolean');
    result.data.verified.should.equal(true);
    should.exist(result.data.presentationResult);
    result.data.presentationResult.should.be.an('object');
    should.exist(result.data.presentationResult.verified);
    result.data.presentationResult.verified.should.be.a('boolean');
    result.data.presentationResult.verified.should.equal(true);
    should.exist(result.data.presentation);
    result.data.presentation.should.be.an('object');
    result.data.presentation.type.should.equal('VerifiablePresentation');
    result.data.presentation.verifiableCredential.should.be.an('object');
    result.data.presentation.verifiableCredential.type.should
      .equal('EnvelopedVerifiableCredential');
  });

  it('verifies a valid Annex D presentation', async () => {
    // get device key pair
    const deviceKeyPair = await mdlUtils.generateDeviceKeyPair();

    // issue an mdoc
    const issuerPrivateJwk = certChain.leaf.subject.jwk;
    const issuerCertificate = certChain.leaf.pemCertificate;
    const mdoc = await mdlUtils.issue({
      issuerPrivateJwk, issuerCertificate,
      devicePublicJwk: deviceKeyPair.publicJwk
    });

    // get challenge from verifier
    const {data: {challenge}} = await helpers.createChallenge(
      {capabilityAgent, verifierId});

    // create an Annex D MDL handover
    const handover = {
      type: 'OpenID4VPDCAPIHandover',
      origin: 'https://test.example',
      nonce: randomUUID(),
      // note: expected to be an OID4VP key, not the device key
      recipientPublicJwk: deviceKeyPair.publicJwk
    };

    // create mdoc enveloped presentation
    const envelopedPresentation = await mdlUtils.createPresentation({
      presentationDefinition: PRESENTATION_DEFINITION_1,
      mdoc,
      handover,
      devicePrivateJwk: deviceKeyPair.privateJwk
    });

    // uncomment code to run local mdoc verification
    /*
    const vpToken = envelopedPresentation.id.slice(
      envelopedPresentation.id.indexOf(',') + 1);
    const deviceResponse = Buffer.from(vpToken, 'base64url');
    await mdlUtils.verifyPresentation({
      deviceResponse, handover,
      trustedCertificates: [certChain.intermediate.pemCertificate]
    });
    */

    // send VP to verifier VC API
    let error;
    let result;
    try {
      const zcapClient = helpers.createZcapClient({capabilityAgent});
      result = await zcapClient.write({
        url: `${verifierId}/presentations/verify`,
        capability: rootZcap,
        json: {
          options: {
            domain: handover.responseUri,
            challenge,
            // ensure `challenge` is checked
            checks: ['challenge'],
            mdoc: {
              sessionTranscript: Buffer
                .from(await oid4vp.mdoc.encodeSessionTranscript({handover}))
                .toString('base64url')
            }
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
    checks[0].should.equal('challenge');
    should.exist(result.data.verified);
    result.data.verified.should.be.a('boolean');
    result.data.verified.should.equal(true);
    should.exist(result.data.presentationResult);
    result.data.presentationResult.should.be.an('object');
    should.exist(result.data.presentationResult.verified);
    result.data.presentationResult.verified.should.be.a('boolean');
    result.data.presentationResult.verified.should.equal(true);
    should.exist(result.data.presentation);
    result.data.presentation.should.be.an('object');
    result.data.presentation.type.should.equal('VerifiablePresentation');
    result.data.presentation.verifiableCredential.should.be.an('object');
    result.data.presentation.verifiableCredential.type.should
      .equal('EnvelopedVerifiableCredential');
  });

  it('verifies a valid Annex D presentation w/owf libs', async () => {
    // get device key pair
    const deviceKeyPair = await mdlUtils.generateDeviceKeyPair();

    // issue an mdoc
    const issuerPrivateJwk = certChain.leaf.subject.jwk;
    const issuerCertificate = certChain.leaf.pemCertificate;
    const issuerSigned = await mdlUtils.issueWithOwf({
      issuerPrivateJwk, issuerCertificate,
      devicePublicJwk: deviceKeyPair.publicJwk
    });

    // get challenge from verifier
    const {data: {challenge}} = await helpers.createChallenge(
      {capabilityAgent, verifierId});

    // create an Annex D mdoc handover
    const handover = {
      type: 'OpenID4VPDCAPIHandover',
      origin: 'https://test.example',
      nonce: randomUUID(),
      // note: expected to be an OID4VP key, not the device key
      recipientPublicJwk: deviceKeyPair.publicJwk
    };

    // create mdoc enveloped presentation
    const envelopedPresentation = await mdlUtils.createPresentationWithOwf({
      presentationDefinition: PRESENTATION_DEFINITION_1,
      issuerSigned,
      handover,
      devicePrivateJwk: deviceKeyPair.privateJwk
    });

    // uncomment code to run local mdoc verification
    /*
    const vpToken = envelopedPresentation.id.slice(
      envelopedPresentation.id.indexOf(',') + 1);
    const deviceResponse = Buffer.from(vpToken, 'base64url');
    await mdlUtils.verifyPresentationWithOwf({
      deviceResponse, handover,
      trustedCertificates: [certChain.intermediate.pemCertificate]
    });
    */

    // send VP to verifier VC API
    let error;
    let result;
    try {
      const zcapClient = helpers.createZcapClient({capabilityAgent});
      result = await zcapClient.write({
        url: `${verifierId}/presentations/verify`,
        capability: rootZcap,
        json: {
          options: {
            domain: handover.responseUri,
            challenge,
            // ensure `challenge` is checked
            checks: ['challenge'],
            mdoc: {
              sessionTranscript: Buffer
                .from(await oid4vp.mdoc.encodeSessionTranscript({handover}))
                .toString('base64url')
            }
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
    checks[0].should.equal('challenge');
    should.exist(result.data.verified);
    result.data.verified.should.be.a('boolean');
    result.data.verified.should.equal(true);
    should.exist(result.data.presentationResult);
    result.data.presentationResult.should.be.an('object');
    should.exist(result.data.presentationResult.verified);
    result.data.presentationResult.verified.should.be.a('boolean');
    result.data.presentationResult.verified.should.equal(true);
    should.exist(result.data.presentation);
    result.data.presentation.should.be.an('object');
    result.data.presentation.type.should.equal('VerifiablePresentation');
    result.data.presentation.verifiableCredential.should.be.an('object');
    result.data.presentation.verifiableCredential.type.should
      .equal('EnvelopedVerifiableCredential');
  });

  it('verifies a valid Annex B presentation as a credential', async () => {
    // get device key pair
    const deviceKeyPair = await mdlUtils.generateDeviceKeyPair();

    // issue an mdoc
    const issuerPrivateJwk = certChain.leaf.subject.jwk;
    const issuerCertificate = certChain.leaf.pemCertificate;
    const mdoc = await mdlUtils.issue({
      issuerPrivateJwk, issuerCertificate,
      devicePublicJwk: deviceKeyPair.publicJwk
    });

    // get challenge from verifier
    const {data: {challenge}} = await helpers.createChallenge(
      {capabilityAgent, verifierId});

    // create an mdoc handover
    const handover = {
      type: 'AnnexBHandover',
      mdocGeneratedNonce: randomUUID(),
      clientId: randomUUID(),
      // note: expected to be an OID4VP exchange response URL
      responseUri: 'https://test.example',
      verifierGeneratedNonce: challenge
    };

    // create mdoc enveloped credential
    const envelopedCredential = await mdlUtils.createDerivedCredential({
      presentationDefinition: PRESENTATION_DEFINITION_1,
      mdoc,
      handover,
      devicePrivateJwk: deviceKeyPair.privateJwk
    });

    // uncomment code to run local mdoc verification
    /*
    const vpToken = envelopedCredential.id.slice(
      envelopedCredential.id.indexOf(',') + 1);
    const deviceResponse = Buffer.from(vpToken, 'base64url');
    await mdlUtils.verifyPresentation({
      deviceResponse, handover,
      trustedCertificates: [certChain.intermediate.pemCertificate]
    });
    */

    // create presentation w/ credential
    const verifiablePresentation = {
      '@context': [VC_CONTEXT_2],
      type: ['VerifiablePresentation'],
      verifiableCredential: envelopedCredential
    };

    // send VP to verifier VC API
    let error;
    let result;
    try {
      const zcapClient = helpers.createZcapClient({capabilityAgent});
      result = await zcapClient.write({
        url: `${verifierId}/presentations/verify`,
        capability: rootZcap,
        json: {
          options: {
            domain: handover.responseUri,
            challenge,
            // ensure `challenge` is checked
            checks: ['challenge'],
            mdoc: {
              sessionTranscript: Buffer
                .from(await oid4vp.mdoc.encodeSessionTranscript({handover}))
                .toString('base64url')
            }
          },
          verifiablePresentation
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
    checks[0].should.equal('challenge');
    should.exist(result.data.verified);
    result.data.verified.should.be.a('boolean');
    result.data.verified.should.equal(true);
    should.exist(result.data.credentialResults);
    result.data.credentialResults.should.be.an('array');
    result.data.credentialResults.length.should.equal(1);
    const [credentialResult] = result.data.credentialResults;
    should.exist(credentialResult.verified);
    credentialResult.verified.should.be.a('boolean');
    credentialResult.verified.should.equal(true);
    should.exist(credentialResult.credential);
    credentialResult.credential.should.be.an('object');
    credentialResult.credential.type.should
      .equal('EnvelopedVerifiableCredential');
  });

  it('verifies a valid Annex C presentation as a credential', async () => {
    // get device key pair
    const deviceKeyPair = await mdlUtils.generateDeviceKeyPair();

    // issue an mdoc
    const issuerPrivateJwk = certChain.leaf.subject.jwk;
    const issuerCertificate = certChain.leaf.pemCertificate;
    const mdoc = await mdlUtils.issue({
      issuerPrivateJwk, issuerCertificate,
      devicePublicJwk: deviceKeyPair.publicJwk
    });

    // get challenge from verifier
    const {data: {challenge}} = await helpers.createChallenge(
      {capabilityAgent, verifierId});

    // create an Annex C mdoc handover
    const handover = {
      type: 'dcapi',
      origin: 'https://test.example',
      nonce: randomUUID(),
      // note: expected to be an OID4VP key, not the device key
      recipientPublicJwk: deviceKeyPair.publicJwk
    };

    // create mdoc enveloped credential
    const envelopedCredential = await mdlUtils.createDerivedCredential({
      presentationDefinition: PRESENTATION_DEFINITION_1,
      mdoc,
      handover,
      devicePrivateJwk: deviceKeyPair.privateJwk
    });

    // uncomment code to run local mdoc verification
    /*
    const vpToken = envelopedCredential.id.slice(
      envelopedCredential.id.indexOf(',') + 1);
    const deviceResponse = Buffer.from(vpToken, 'base64url');
    await mdlUtils.verifyPresentation({
      deviceResponse, handover,
      trustedCertificates: [certChain.intermediate.pemCertificate]
    });
    */

    // create presentation w/ credential
    const verifiablePresentation = {
      '@context': [VC_CONTEXT_2],
      type: ['VerifiablePresentation'],
      verifiableCredential: envelopedCredential
    };

    // send VP to verifier VC API
    let error;
    let result;
    try {
      const zcapClient = helpers.createZcapClient({capabilityAgent});
      result = await zcapClient.write({
        url: `${verifierId}/presentations/verify`,
        capability: rootZcap,
        json: {
          options: {
            domain: handover.responseUri,
            challenge,
            // ensure `challenge` is checked
            checks: ['challenge'],
            mdoc: {
              sessionTranscript: Buffer
                .from(await oid4vp.mdoc.encodeSessionTranscript({handover}))
                .toString('base64url')
            }
          },
          verifiablePresentation
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
    checks[0].should.equal('challenge');
    should.exist(result.data.verified);
    result.data.verified.should.be.a('boolean');
    result.data.verified.should.equal(true);
    should.exist(result.data.credentialResults);
    result.data.credentialResults.should.be.an('array');
    result.data.credentialResults.length.should.equal(1);
    const [credentialResult] = result.data.credentialResults;
    should.exist(credentialResult.verified);
    credentialResult.verified.should.be.a('boolean');
    credentialResult.verified.should.equal(true);
    should.exist(credentialResult.credential);
    credentialResult.credential.should.be.an('object');
    credentialResult.credential.type.should
      .equal('EnvelopedVerifiableCredential');
  });

  it('verifies a valid Annex D presentation as a credential', async () => {
    // get device key pair
    const deviceKeyPair = await mdlUtils.generateDeviceKeyPair();

    // issue an mdoc
    const issuerPrivateJwk = certChain.leaf.subject.jwk;
    const issuerCertificate = certChain.leaf.pemCertificate;
    const mdoc = await mdlUtils.issue({
      issuerPrivateJwk, issuerCertificate,
      devicePublicJwk: deviceKeyPair.publicJwk
    });

    // get challenge from verifier
    const {data: {challenge}} = await helpers.createChallenge(
      {capabilityAgent, verifierId});

    // create an Annex D mdoc handover
    const handover = {
      type: 'OpenID4VPDCAPIHandover',
      origin: 'https://test.example',
      nonce: randomUUID(),
      // note: expected to be an OID4VP key, not the device key
      recipientPublicJwk: deviceKeyPair.publicJwk
    };

    // create mdoc enveloped presentation
    const envelopedCredential = await mdlUtils.createDerivedCredential({
      presentationDefinition: PRESENTATION_DEFINITION_1,
      mdoc,
      handover,
      devicePrivateJwk: deviceKeyPair.privateJwk
    });

    // uncomment code to run local mdoc verification
    /*
    const vpToken = envelopedCredential.id.slice(
      envelopedCredential.id.indexOf(',') + 1);
    const deviceResponse = Buffer.from(vpToken, 'base64url');
    await mdlUtils.verifyPresentation({
      deviceResponse, handover,
      trustedCertificates: [certChain.intermediate.pemCertificate]
    });
    */

    // create presentation w/ credential
    const verifiablePresentation = {
      '@context': [VC_CONTEXT_2],
      type: ['VerifiablePresentation'],
      verifiableCredential: envelopedCredential
    };

    // send VP to verifier VC API
    let error;
    let result;
    try {
      const zcapClient = helpers.createZcapClient({capabilityAgent});
      result = await zcapClient.write({
        url: `${verifierId}/presentations/verify`,
        capability: rootZcap,
        json: {
          options: {
            domain: handover.responseUri,
            challenge,
            // ensure `challenge` is checked
            checks: ['challenge'],
            mdl: {
              sessionTranscript: Buffer
                .from(await oid4vp.mdoc.encodeSessionTranscript({handover}))
                .toString('base64url')
            }
          },
          verifiablePresentation
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
    checks[0].should.equal('challenge');
    should.exist(result.data.verified);
    result.data.verified.should.be.a('boolean');
    result.data.verified.should.equal(true);
    should.exist(result.data.credentialResults);
    result.data.credentialResults.should.be.an('array');
    result.data.credentialResults.length.should.equal(1);
    const [credentialResult] = result.data.credentialResults;
    should.exist(credentialResult.verified);
    credentialResult.verified.should.be.a('boolean');
    credentialResult.verified.should.equal(true);
    should.exist(credentialResult.credential);
    credentialResult.credential.should.be.an('object');
    credentialResult.credential.type.should
      .equal('EnvelopedVerifiableCredential');
  });

  it('verifies a valid Annex D presentation as a credential w/owf libs',
    async () => {
      // get device key pair
      const deviceKeyPair = await mdlUtils.generateDeviceKeyPair();

      // issue an mdoc
      const issuerPrivateJwk = certChain.leaf.subject.jwk;
      const issuerCertificate = certChain.leaf.pemCertificate;
      const issuerSigned = await mdlUtils.issueWithOwf({
        issuerPrivateJwk, issuerCertificate,
        devicePublicJwk: deviceKeyPair.publicJwk
      });

      // get challenge from verifier
      const {data: {challenge}} = await helpers.createChallenge(
        {capabilityAgent, verifierId});

      // create an Annex D mdoc handover
      const handover = {
        type: 'OpenID4VPDCAPIHandover',
        origin: 'https://test.example',
        nonce: randomUUID(),
        // note: expected to be an OID4VP key, not the device key
        recipientPublicJwk: deviceKeyPair.publicJwk
      };

      // create mdoc enveloped credential
      const envelopedCredential =
        await mdlUtils.createDerivedCredentialWithOwf({
          presentationDefinition: PRESENTATION_DEFINITION_1,
          issuerSigned,
          handover,
          devicePrivateJwk: deviceKeyPair.privateJwk
        });

      // uncomment code to run local mdoc verification
      /*
      const vpToken = envelopedCredential.id.slice(
        envelopedCredential.id.indexOf(',') + 1);
      const deviceResponse = Buffer.from(vpToken, 'base64url');
      await mdlUtils.verifyPresentationWithOwf({
        deviceResponse, handover,
        trustedCertificates: [certChain.intermediate.pemCertificate]
      });
      */

      // create presentation w/ credential
      const verifiablePresentation = {
        '@context': [VC_CONTEXT_2],
        type: ['VerifiablePresentation'],
        verifiableCredential: envelopedCredential
      };

      // send VP to verifier VC API
      let error;
      let result;
      try {
        const zcapClient = helpers.createZcapClient({capabilityAgent});
        result = await zcapClient.write({
          url: `${verifierId}/presentations/verify`,
          capability: rootZcap,
          json: {
            options: {
              domain: handover.responseUri,
              challenge,
              // ensure `challenge` is checked
              checks: ['challenge'],
              mdl: {
                sessionTranscript: Buffer
                  .from(await oid4vp.mdoc.encodeSessionTranscript({handover}))
                  .toString('base64url')
              }
            },
            verifiablePresentation
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
      checks[0].should.equal('challenge');
      should.exist(result.data.verified);
      result.data.verified.should.be.a('boolean');
      result.data.verified.should.equal(true);
      should.exist(result.data.credentialResults);
      result.data.credentialResults.should.be.an('array');
      result.data.credentialResults.length.should.equal(1);
      const [credentialResult] = result.data.credentialResults;
      should.exist(credentialResult.verified);
      credentialResult.verified.should.be.a('boolean');
      credentialResult.verified.should.equal(true);
      should.exist(credentialResult.credential);
      credentialResult.credential.should.be.an('object');
      credentialResult.credential.type.should
        .equal('EnvelopedVerifiableCredential');
    });

  it('fails without a matching trusted certificate', async () => {
    // generate a different (untrusted) issuer and shadow `certChain` var
    const certChain = await generateCertificateChain();

    // get device key pair
    const deviceKeyPair = await mdlUtils.generateDeviceKeyPair();

    // issue an mdoc
    const issuerPrivateJwk = certChain.leaf.subject.jwk;
    const issuerCertificate = certChain.leaf.pemCertificate;
    const mdoc = await mdlUtils.issue({
      issuerPrivateJwk, issuerCertificate,
      devicePublicJwk: deviceKeyPair.publicJwk
    });

    // get challenge from verifier
    const {data: {challenge}} = await helpers.createChallenge(
      {capabilityAgent, verifierId});

    // create an mdoc handover
    const handover = {
      type: 'AnnexBHandover',
      mdocGeneratedNonce: randomUUID(),
      clientId: randomUUID(),
      // note: expected to be an OID4VP exchange response URL
      responseUri: 'https://test.example',
      verifierGeneratedNonce: challenge
    };

    // create mdoc enveloped presentation
    const envelopedPresentation = await mdlUtils.createPresentation({
      presentationDefinition: PRESENTATION_DEFINITION_1,
      mdoc,
      handover,
      devicePrivateJwk: deviceKeyPair.privateJwk
    });

    // uncomment code to run local mdoc verification
    /*
    const vpToken = envelopedPresentation.id.slice(
      envelopedPresentation.id.indexOf(',') + 1);
    const deviceResponse = Buffer.from(vpToken, 'base64url');
    await mdlUtils.verifyPresentation({
      deviceResponse, handover,
      trustedCertificates: [certChain.intermediate.pemCertificate]
    });
    */

    // send VP to verifier VC API
    let error;
    let result;
    try {
      const zcapClient = helpers.createZcapClient({capabilityAgent});
      result = await zcapClient.write({
        url: `${verifierId}/presentations/verify`,
        capability: rootZcap,
        json: {
          options: {
            domain: handover.responseUri,
            challenge,
            // ensure `challenge` is checked
            checks: ['challenge'],
            mdoc: {
              sessionTranscript: Buffer
                .from(await oid4vp.mdoc.encodeSessionTranscript({handover}))
                .toString('base64url')
            }
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
    e.name.should.equal('MDLError');
    e.message.should.include('No valid certificate paths found');
  });

  it('fails with an invalid issuer signature', async () => {
    // get device key pair
    const deviceKeyPair = await mdlUtils.generateDeviceKeyPair();

    // issue an mdoc; but *importantly for this test* with the wrong JWK
    const issuerPrivateJwk = certChain.intermediate.subject.jwk;
    const issuerCertificate = certChain.leaf.pemCertificate;
    const mdoc = await mdlUtils.issue({
      issuerPrivateJwk, issuerCertificate,
      devicePublicJwk: deviceKeyPair.publicJwk
    });

    // get challenge from verifier
    const {data: {challenge}} = await helpers.createChallenge(
      {capabilityAgent, verifierId});

    // create an mdoc handover
    const handover = {
      type: 'AnnexBHandover',
      mdocGeneratedNonce: randomUUID(),
      clientId: randomUUID(),
      // note: expected to be an OID4VP exchange response URL
      responseUri: 'https://test.example',
      verifierGeneratedNonce: challenge
    };

    // create mdoc enveloped presentation
    const envelopedPresentation = await mdlUtils.createPresentation({
      presentationDefinition: PRESENTATION_DEFINITION_1,
      mdoc,
      handover,
      devicePrivateJwk: deviceKeyPair.privateJwk
    });

    // uncomment code to run local mdoc verification
    /*
    const vpToken = envelopedPresentation.id.slice(
      envelopedPresentation.id.indexOf(',') + 1);
    const deviceResponse = Buffer.from(vpToken, 'base64url');
    await mdlUtils.verifyPresentation({
      deviceResponse, handover,
      trustedCertificates: [certChain.intermediate.pemCertificate]
    });
    */

    // send VP to verifier VC API
    let error;
    let result;
    try {
      const zcapClient = helpers.createZcapClient({capabilityAgent});
      result = await zcapClient.write({
        url: `${verifierId}/presentations/verify`,
        capability: rootZcap,
        json: {
          options: {
            domain: handover.responseUri,
            challenge,
            // ensure `challenge` is checked
            checks: ['challenge'],
            mdoc: {
              sessionTranscript: Buffer
                .from(await oid4vp.mdoc.encodeSessionTranscript({handover}))
                .toString('base64url')
            }
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
    e.name.should.equal('MDLError');
    e.message.should.include('Issuer signature must be valid');
  });

  it('fails to verify with an invalid device signature', async () => {
    // get device key pair
    const deviceKeyPair = await mdlUtils.generateDeviceKeyPair();

    // issue an mdoc
    const issuerPrivateJwk = certChain.leaf.subject.jwk;
    const issuerCertificate = certChain.leaf.pemCertificate;
    const mdoc = await mdlUtils.issue({
      issuerPrivateJwk, issuerCertificate,
      devicePublicJwk: deviceKeyPair.publicJwk
    });

    // get challenge from verifier
    const {data: {challenge}} = await helpers.createChallenge(
      {capabilityAgent, verifierId});

    // create an mdoc handover
    const handover = {
      type: 'AnnexBHandover',
      mdocGeneratedNonce: randomUUID(),
      clientId: randomUUID(),
      // note: expected to be an OID4VP exchange response URL
      responseUri: 'https://test.example',
      verifierGeneratedNonce: challenge
    };

    // generate a different JWK to sign with so that the signature will NOT
    // match
    const otherDeviceJwk = await generateKeyPair();

    // create mdoc enveloped presentation
    const envelopedPresentation = await mdlUtils.createPresentation({
      presentationDefinition: PRESENTATION_DEFINITION_1,
      mdoc,
      handover,
      devicePrivateJwk: otherDeviceJwk.jwk
    });

    // uncomment code to run local mdoc verification
    /*
    const vpToken = envelopedPresentation.id.slice(
      envelopedPresentation.id.indexOf(',') + 1);
    const deviceResponse = Buffer.from(vpToken, 'base64url');
    await mdlUtils.verifyPresentation({
      deviceResponse, handover,
      trustedCertificates: [certChain.intermediate.pemCertificate]
    });
    */

    // send VP to verifier VC API
    let error;
    let result;
    try {
      const zcapClient = helpers.createZcapClient({capabilityAgent});
      result = await zcapClient.write({
        url: `${verifierId}/presentations/verify`,
        capability: rootZcap,
        json: {
          options: {
            domain: handover.responseUri,
            challenge,
            // ensure `challenge` is checked
            checks: ['challenge'],
            mdoc: {
              sessionTranscript: Buffer
                .from(await oid4vp.mdoc.encodeSessionTranscript({handover}))
                .toString('base64url')
            }
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
    e.name.should.equal('MDLError');
    e.message.should.include('Device signature must be valid');
  });
});
