/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import * as helpers from './helpers.js';
import * as mdlUtils from './mdlUtils.js';
import {Document, MDoc} from '@auth0/mdl';
import {agent} from '@bedrock/https-agent';
import {applyReturnHint} from '@bedrock/vc-verifier/lib/returnHints.js';
import {CapabilityAgent} from '@digitalbazaar/webkms-client';
import {generateCertificateChain} from './certUtils.js';
import {httpClient} from '@digitalbazaar/http-client';
import {mdl2vdl} from '@bedrock/vc-verifier/lib/returnHints/mdl2vdl.js';
import {oid4vp} from '@digitalbazaar/oid4-client';
import {randomUUID} from 'node:crypto';

import {mockData} from './mock.data.js';

const {baseUrl} = mockData;
const serviceType = 'vc-verifier';

const VC_CONTEXT_2 = 'https://www.w3.org/ns/credentials/v2';
const MDL_NAMESPACE = 'org.iso.18013.5.1';
const AAMVA_NAMESPACE = `${MDL_NAMESPACE}.aamva`;
const MDOC_TYPE_MDL = `${MDL_NAMESPACE}.mDL`;
const RETURN_HINT_NOT_APPLIED =
  'tag:digitalbazaar.com,2026:vc-verifier:return-hint-not-applied';

// JPEG start-of-image marker plus some bytes
const PORTRAIT = new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10]);

const DEVICE_PUBLIC_JWK = {
  kty: 'EC',
  crv: 'P-256',
  x: 'QiUaYhZak1NubJEphQWmafykivrD80D2IpwqkkCU0oQ',
  y: 'sdNfR3813hzaUqF3-kWWOjI1xtSEqb93-graWFK-bA4'
};

// issue an mdoc with ISO and AAMVA elements, and return it as an enveloped
// credential holding the CBOR-encoded mdoc
async function _envelopedMdoc({
  certChain, docType = MDOC_TYPE_MDL, encoding = 'base64'
}) {
  const document = await new Document(docType)
    .addIssuerNameSpace(MDL_NAMESPACE, {
      family_name: 'Doe',
      given_name: 'Jane',
      birth_date: '1990-01-01',
      issue_date: '2024-02-03',
      expiry_date: '2032-02-03',
      issuing_authority: 'Test DMV',
      age_over_21: true,
      height: 170,
      portrait: PORTRAIT,
      driving_privileges: [{
        vehicle_category_code: 'C',
        issue_date: '2024-02-03'
      }],
      // not defined by the vDL context
      biometric_template_face: new Uint8Array([1, 2, 3])
    })
    .addIssuerNameSpace(AAMVA_NAMESPACE, {
      DHS_compliance: 'F',
      organ_donor: 1,
      'aka_family_name.v2': 'Smith',
      hazmat_endorsement_expiration_date: '2030-05-06',
      // not defined by the vDL AAMVA context
      not_an_aamva_element: 'x'
    })
    .useDigestAlgorithm('SHA-256')
    .addValidityInfo({signed: new Date()})
    .addDeviceKeyInfo({deviceKey: DEVICE_PUBLIC_JWK})
    .sign({
      issuerPrivateKey: certChain.leaf.subject.jwk,
      issuerCertificate: certChain.leaf.pemCertificate,
      kid: certChain.leaf.subject.jwk.kid,
      alg: 'ES256'
    });
  const encoded = Buffer.from(new MDoc([document]).encode());
  const id = encoding === 'base64' ?
    `data:application/mdoc;base64,${encoded.toString('base64')}` :
    `data:application/mdl-vp-token,${encoded.toString('base64url')}`;
  return {
    '@context': [VC_CONTEXT_2],
    id,
    type: 'EnvelopedVerifiableCredential'
  };
}

describe('mdl2vdl return hint', () => {
  let certChain;
  before(async () => {
    certChain = await generateCertificateChain();
  });

  describe('mapping', () => {
    it('maps an mdoc mDL to a vDL', async () => {
      const payload = await _envelopedMdoc({certChain});
      const vdl = await mdl2vdl({payload, kind: 'credential'});

      vdl['@context'].should.eql([
        VC_CONTEXT_2,
        'https://w3id.org/vdl/v1',
        'https://w3id.org/vdl/aamva/v1'
      ]);
      vdl.type.should.eql([
        'VerifiableCredential', 'Iso18013DriversLicenseCredential'
      ]);
      vdl.validFrom.should.match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
      vdl.validUntil.should.match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
      vdl.credentialSubject.type.should.equal('LicensedDriver');

      const {driversLicense} = vdl.credentialSubject;
      driversLicense.should.eql({
        type: 'Iso18013DriversLicense',
        family_name: 'Doe',
        given_name: 'Jane',
        // date-only values become midnight UTC
        birth_date: '1990-01-01T00:00:00Z',
        issue_date: '2024-02-03T00:00:00Z',
        expiry_date: '2032-02-03T00:00:00Z',
        issuing_authority: 'Test DMV',
        age_over_21: true,
        height: 170,
        portrait: 'data:image/jpeg;base64,' +
          Buffer.from(PORTRAIT).toString('base64'),
        // `@json` values keep date-only values
        driving_privileges: [{
          vehicle_category_code: 'C',
          issue_date: '2024-02-03'
        }],
        aamva_dhs_compliance: 'F',
        aamva_organ_donor: 1,
        aamva_aka_family_name_v2: 'Smith',
        aamva_hazmat_endorsement_expiration_date: '2030-05-06T00:00:00Z'
      });
    });

    it('identifies the issuer by a did:jwk for its certificate key',
      async () => {
        const payload = await _envelopedMdoc({certChain});
        const vdl = await mdl2vdl({payload, kind: 'credential'});
        vdl.issuer.id.should.match(/^did:jwk:/);
        const jwk = JSON.parse(Buffer.from(
          vdl.issuer.id.slice('did:jwk:'.length), 'base64url').toString());
        const {crv, kty, x, y} = certChain.leaf.subject.jwk;
        jwk.should.eql({crv, kty, x, y});
        vdl.issuer.name.should.be.a('string');
      });

    it('maps a base64url-encoded mdoc envelope', async () => {
      const payload = await _envelopedMdoc({certChain, encoding: 'base64url'});
      const vdl = await mdl2vdl({payload, kind: 'credential'});
      vdl.credentialSubject.driversLicense.family_name.should.equal('Doe');
    });

    it('returns a presentation holding the vDL', async () => {
      const payload = await _envelopedMdoc({certChain});
      const vp = await mdl2vdl({payload, kind: 'presentation'});
      vp['@context'].should.eql([VC_CONTEXT_2]);
      vp.type.should.eql(['VerifiablePresentation']);
      vp.verifiableCredential.should.be.an('array');
      vp.verifiableCredential.should.have.length(1);
      vp.verifiableCredential[0].type.should.include(
        'Iso18013DriversLicenseCredential');
    });

    it('returns the payload with problemDetails for another doc type',
      async () => {
        const payload = await _envelopedMdoc({
          certChain, docType: 'org.example.other'
        });
        const result = await applyReturnHint({
          hint: 'mdl2vdl', payload, kind: 'credential',
          mediaType: 'application/mdoc'
        });
        result.payload.should.equal(payload);
        result.problemDetails.type.should.equal(RETURN_HINT_NOT_APPLIED);
        result.problemDetails.detail.should.equal(
          `"mdl2vdl": Only a single "${MDOC_TYPE_MDL}" document can be ` +
          'mapped to a vDL.');
      });

    it('does not apply to a payload that is not an mdoc', async () => {
      const payload = {
        '@context': [VC_CONTEXT_2],
        type: ['VerifiableCredential']
      };
      const result = await applyReturnHint({
        hint: 'mdl2vdl', payload, kind: 'credential',
        mediaType: 'application/vc'
      });
      result.should.eql({payload});
    });
  });

  describe('POST /presentations/verify', () => {
    let capabilityAgent;
    let verifierId;
    let rootZcap;
    beforeEach(async () => {
      const secret = '53ad64ce-8e1d-11ec-bb12-10bf48838a41';
      const handle = 'test';
      capabilityAgent = await CapabilityAgent.fromSecret({secret, handle});
      const keystoreAgent = await helpers.createKeystoreAgent(
        {capabilityAgent});
      const {
        edvConfig, hmac, keyAgreementKey
      } = await helpers.createEdv({capabilityAgent, keystoreAgent});
      const serviceAgentUrl =
        `${baseUrl}/service-agents/${encodeURIComponent(serviceType)}`;
      const {data: serviceAgent} = await httpClient.get(serviceAgentUrl, {
        agent
      });
      const zcaps = {};
      zcaps.edv = await helpers.delegate({
        controller: serviceAgent.id,
        delegator: capabilityAgent,
        invocationTarget: edvConfig.id
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

      // default the verifier instance to the `mdl2vdl` return hint
      const caStoreId = `urn:mdoc-ca-store:${randomUUID()}`;
      const verifierConfig = await helpers.createConfig({
        capabilityAgent, zcaps,
        configOptions: {
          verifyOptions: {
            mdoc: {caStores: [caStoreId]},
            returnHint: 'mdl2vdl'
          }
        }
      });
      verifierId = verifierConfig.id;
      rootZcap = `urn:zcap:root:${encodeURIComponent(verifierId)}`;

      const client = helpers.createZcapClient({capabilityAgent});
      await client.write({
        url: `${verifierId}/mdoc/ca-stores`,
        json: {
          id: caStoreId,
          trustedCertificates: [certChain.intermediate.pemCertificate]
        },
        capability: rootZcap
      });
    });

    it('returns a vDL for a verified mdoc presentation', async () => {
      const deviceKeyPair = await mdlUtils.generateDeviceKeyPair();
      const mdoc = await mdlUtils.issue({
        issuerPrivateJwk: certChain.leaf.subject.jwk,
        issuerCertificate: certChain.leaf.pemCertificate,
        devicePublicJwk: deviceKeyPair.publicJwk
      });
      const {data: {challenge}} = await helpers.createChallenge(
        {capabilityAgent, verifierId});
      const handover = {
        type: 'OpenID4VPDCAPIHandover',
        origin: 'https://test.example',
        nonce: randomUUID(),
        recipientPublicJwk: deviceKeyPair.publicJwk
      };
      const presentationDefinition = {
        id: 'mdl-test-mdl2vdl',
        input_descriptors: [{
          id: MDOC_TYPE_MDL,
          format: {mso_mdoc: {alg: ['ES256']}},
          constraints: {
            limit_disclosure: 'required',
            fields: ['family_name', 'birth_date', 'age_over_21'].map(e => ({
              path: [`$['${MDL_NAMESPACE}']['${e}']`],
              intent_to_retain: false
            }))
          }
        }]
      };
      const envelopedPresentation = await mdlUtils.createPresentation({
        presentationDefinition, mdoc, handover,
        devicePrivateJwk: deviceKeyPair.privateJwk
      });

      const zcapClient = helpers.createZcapClient({capabilityAgent});
      const {data} = await zcapClient.write({
        url: `${verifierId}/presentations/verify`,
        capability: rootZcap,
        json: {
          options: {
            challenge,
            checks: ['challenge'],
            responseFormat: 'vcalm-v1',
            returnPresentation: true,
            mdoc: {
              sessionTranscript: Buffer
                .from(await oid4vp.mdoc.encodeSessionTranscript({handover}))
                .toString('base64url')
            }
          },
          verifiablePresentation: envelopedPresentation
        }
      });
      data.verified.should.equal(true);
      data.should.not.have.property('problemDetails');
      const {verifiablePresentation: vp} = data;
      vp.type.should.eql(['VerifiablePresentation']);
      const [vdl] = vp.verifiableCredential;
      vdl.type.should.include('Iso18013DriversLicenseCredential');
      vdl.credentialSubject.driversLicense.should.eql({
        type: 'Iso18013DriversLicense',
        family_name: 'FamilyName',
        birth_date: '1990-01-01T00:00:00Z',
        age_over_21: true
      });
    });
  });
});
