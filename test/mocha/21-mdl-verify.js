/*!
 * Copyright (c) 2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from './helpers.js';
import * as mdlUtils from './mdlUtils.js';
import {generateCertificateChain, generateKeyPair} from './certUtils.js';
import {agent} from '@bedrock/https-agent';
import {CapabilityAgent} from '@digitalbazaar/webkms-client';
import {httpClient} from '@digitalbazaar/http-client';
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
            // eslint-disable-next-line quotes
            path: ["$['org.iso.18013.5.1']['age_over_21']"],
            intent_to_retain: false
          }
        ]
      }
    }
  ]
};

describe('mDL /presentations/verify', () => {
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

    // add `mdlCAStores` to verifier config options
    const caStoreId = `urn:mdl-ca-store:${randomUUID()}`;
    const configOptions = {
      verifyOptions: {
        mdl: {
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

    // create a certificate chain that ends in the MDL issuer (leaf)
    certChain = await generateCertificateChain();

    // add mDL CA store with intermediate certificate
    {
      const client = helpers.createZcapClient({capabilityAgent});
      const url = `${verifierConfig.id}/mdl/ca-stores`;
      const trustedCertificates = [certChain.intermediate.pemCertificate];
      await client.write({
        url, json: {id: caStoreId, trustedCertificates},
        capability: rootZcap
      });
    }
  });

  it('verifies a valid presentation', async () => {
    // get device key pair
    const deviceKeyPair = await mdlUtils.generateDeviceKeyPair();

    // issue an MDL
    const issuerPrivateJwk = certChain.leaf.subject.jwk;
    const issuerCertificate = certChain.leaf.pemCertificate;
    const mdoc = await mdlUtils.issue({
      issuerPrivateJwk, issuerCertificate,
      devicePublicJwk: deviceKeyPair.publicJwk
    });

    // get challenge from verifier
    const {data: {challenge}} = await helpers.createChallenge(
      {capabilityAgent, verifierId});

    // create an MDL session transcript
    const sessionTranscript = {
      mdocGeneratedNonce: randomUUID(),
      clientId: randomUUID(),
      // note: expected to be an OID4VP exchange response URL
      responseUri: 'https://test.example',
      verifierGeneratedNonce: challenge
    };

    // create MDL enveloped presentation
    const envelopedPresentation = await mdlUtils.createPresentation({
      presentationDefinition: PRESENTATION_DEFINITION_1,
      mdoc,
      sessionTranscript,
      devicePrivateJwk: deviceKeyPair.privateJwk
    });

    // uncomment code to run local mDL verification
    /*
    const vpToken = envelopedPresentation.id.slice(
      envelopedPresentation.id.indexOf(',') + 1);
    const deviceResponse = Buffer.from(vpToken, 'base64url');
    await mdlUtils.verifyPresentation({
      deviceResponse, sessionTranscript,
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
            domain: sessionTranscript.responseUri,
            challenge,
            // ensure `challenge` is checked
            checks: ['challenge'],
            mdl: {
              // note: in session transcript:
              // `domain` will be used for `responseUri`
              // `challenge` will be used for `verifierGeneratedNonce`
              // so do not send here to avoid redundancy
              sessionTranscript: {
                mdocGeneratedNonce: sessionTranscript.mdocGeneratedNonce,
                clientId: sessionTranscript.clientId
              }
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

  // FIXME: add negative test that fails to verify w/o trusted cert
  // FIXME: add negative test that fails w/bad issuer signature

  it('fails to verify with an invalid device signature', async () => {
    // get device key pair
    const deviceKeyPair = await mdlUtils.generateDeviceKeyPair();

    // issue an MDL
    const issuerPrivateJwk = certChain.leaf.subject.jwk;
    const issuerCertificate = certChain.leaf.pemCertificate;
    const mdoc = await mdlUtils.issue({
      issuerPrivateJwk, issuerCertificate,
      devicePublicJwk: deviceKeyPair.publicJwk
    });

    // get challenge from verifier
    const {data: {challenge}} = await helpers.createChallenge(
      {capabilityAgent, verifierId});

    // create an MDL session transcript
    const sessionTranscript = {
      mdocGeneratedNonce: randomUUID(),
      clientId: randomUUID(),
      // note: expected to be an OID4VP exchange response URL
      responseUri: 'https://test.example',
      verifierGeneratedNonce: challenge
    };

    // generate a different JWK to sign with so that the signature will NOT
    // match
    const otherDeviceJwk = await generateKeyPair();

    // create MDL enveloped presentation
    const envelopedPresentation = await mdlUtils.createPresentation({
      presentationDefinition: PRESENTATION_DEFINITION_1,
      mdoc,
      sessionTranscript,
      devicePrivateJwk: otherDeviceJwk.jwk
    });

    // uncomment code to run local mDL verification
    /*
    const vpToken = envelopedPresentation.id.slice(
      envelopedPresentation.id.indexOf(',') + 1);
    const deviceResponse = Buffer.from(vpToken, 'base64url');
    await mdlUtils.verifyPresentation({
      deviceResponse, sessionTranscript,
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
            domain: sessionTranscript.responseUri,
            challenge,
            // ensure `challenge` is checked
            checks: ['challenge'],
            mdl: {
              // note: in session transcript:
              // `domain` will be used for `responseUri`
              // `challenge` will be used for `verifierGeneratedNonce`
              // so do not send here to avoid redundancy
              sessionTranscript: {
                mdocGeneratedNonce: sessionTranscript.mdocGeneratedNonce,
                clientId: sessionTranscript.clientId
              }
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
