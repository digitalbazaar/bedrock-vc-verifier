/*!
 * Copyright (c) 2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from './helpers.js';
import {agent} from '@bedrock/https-agent';
import {CapabilityAgent} from '@digitalbazaar/webkms-client';
import {generateCertificateChain} from './certUtils.js';
import {httpClient} from '@digitalbazaar/http-client';
import {randomUUID} from 'node:crypto';

// FIXME: move elsewhere, load order matters right now because of pkijs globals
import * as mdlUtils from './mdlUtils.js';

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

describe('mDL verify APIs', () => {
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
    // create a certificate chain that ends in the MDL issuer (leaf)
    const certChain = await generateCertificateChain();

    // get device key pair
    const deviceKeyPair = await mdlUtils.generateDeviceKeyPair();

    // issue an MDL
    const issuerPrivateJwk = certChain.leaf.subject.jwk;
    const issuerCertificate = certChain.leaf.pemCertificate;
    const mdoc = await mdlUtils.issue({
      issuerPrivateJwk, issuerCertificate,
      devicePublicJwk: deviceKeyPair.publicJwk
    });

    // create an MDL session transcript
    const sessionTranscript = {
      mdocGeneratedNonce: randomUUID(),
      clientId: randomUUID(),
      // FIXME: replace with OID4VP exchange URL
      responseUri: 'https://test.example',
      verifierGeneratedNonce: randomUUID()
    };

    // create MDL enveloped presentation
    const envelopedPresentation = await mdlUtils.createPresentation({
      presentationDefinition: PRESENTATION_DEFINITION_1,
      mdoc,
      sessionTranscript,
      devicePrivateJwk: deviceKeyPair.privateJwk
    });

    // FIXME: send `sessionTranscript` as an `option` in presentation
    // verification options, i.e.,
    // `{verifiablePresentation, mdl: {sessionTranscript}}`

    // FIXME: send VP to verifier VC API ...

    // FIXME: verifier API will do this...

    // FIXME: use robust parser
    const vpToken = envelopedPresentation.id.slice(
      envelopedPresentation.id.indexOf(',') + 1);
    const deviceResponse = Buffer.from(vpToken, 'base64url');

    await mdlUtils.verifyPresentation({
      deviceResponse, sessionTranscript,
      trustedCertificates: [certChain.intermediate.pemCertificate]
    });

    /*

    // get signing key
    const {methodFor} = await didKeyDriver.generate();
    const signingKey = methodFor({purpose: 'assertionMethod'});
    const suite = new Ed25519Signature2020({key: signingKey});

    const mockCredential = {};
    const cryptosuite = '';
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

    */
  });

  // FIXME: add negative test that fails to verify w/o trusted cert
  // FIXME: add negative test that fails w/bad issuer signature
  // FIXME: add negative test that fails w/bad device signature
});
