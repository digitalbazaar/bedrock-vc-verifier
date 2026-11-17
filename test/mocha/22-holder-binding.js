/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import * as helpers from './helpers.js';
import * as vc from '@digitalbazaar/vc';
import {
  checkHolderBinding,
  credentialSubjectIds
} from '../../lib/holderBinding.js';
import {driver as _didKeyDriver} from '@digitalbazaar/did-method-key';
import {agent} from '@bedrock/https-agent';
import {documentLoader as brDocLoader} from '@bedrock/jsonld-document-loader';
import {CapabilityAgent} from '@digitalbazaar/webkms-client';
import {createRequire} from 'node:module';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {httpClient} from '@digitalbazaar/http-client';

import {mockData} from './mock.data.js';

const require = createRequire(import.meta.url);

const {baseUrl} = mockData;
const serviceType = 'vc-verifier';
const didKeyDriver = _didKeyDriver();
const mockCredentials = require('./mock-credentials.json');
const mockCredential = mockCredentials.find(
  c => c.proof.type === 'Ed25519Signature2020');

const VC_CONTEXT_1 = 'https://www.w3.org/2018/credentials/v1';
const OTHER_DID = 'did:example:not-the-presenter';

describe('holder binding', () => {
  describe('checkHolderBinding()', () => {
    const jwk = {kty: 'EC', crv: 'P-256', x: 'xValue', y: 'yValue'};
    const didJwk = key =>
      `did:jwk:${Buffer.from(JSON.stringify(key)).toString('base64url')}`;
    const holder = didJwk(jwk);

    it('collects `credentialSubject.id` from an object or an array', () => {
      credentialSubjectIds({credential: {credentialSubject: {id: holder}}})
        .should.eql([holder]);
      credentialSubjectIds({credential: {
        credentialSubject: [{id: holder}, {id: OTHER_DID}]
      }}).should.eql([holder, OTHER_DID]);
      credentialSubjectIds({credential: {credentialSubject: {name: 'x'}}})
        .should.eql([]);
    });

    it('binds when the holder is a subject, ignoring fragments', () => {
      checkHolderBinding({
        holder: `${holder}#0`, credentials: [{credentialSubject: {id: holder}}]
      }).verified.should.equal(true);
    });

    it('binds a did:jwk subject to the same key in another member order',
      () => {
        const reordered = didJwk({y: 'yValue', x: 'xValue', crv: 'P-256',
          kty: 'EC'});
        reordered.should.not.equal(holder);
        checkHolderBinding({
          holder, credentials: [{credentialSubject: {id: reordered}}]
        }).verified.should.equal(true);
      });

    it('fails when the holder is not a subject', () => {
      const result = checkHolderBinding({
        holder, credentials: [{credentialSubject: {id: OTHER_DID}}]
      });
      result.verified.should.equal(false);
      result.error.name.should.equal('HolderBindingError');
    });

    it('fails when any one credential is not bound', () => {
      checkHolderBinding({
        holder, credentials: [
          {credentialSubject: {id: holder}},
          {credentialSubject: {id: OTHER_DID}}
        ]
      }).verified.should.equal(false);
    });

    it('fails when a credential has no subject identifier', () => {
      checkHolderBinding({
        holder, credentials: [{credentialSubject: {name: 'x'}}]
      }).verified.should.equal(false);
    });

    it('fails when the holder is unknown', () => {
      checkHolderBinding({
        credentials: [{credentialSubject: {id: holder}}]
      }).verified.should.equal(false);
    });
  });

  describe('/presentations/verify with "holderBinding"', () => {
    let capabilityAgent;
    let verifierId;
    let rootZcap;
    const zcaps = {};
    before(async () => {
      const secret = '7f0bbfd2-1e0f-4a7e-9f43-3c0b6c0b6a11';
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
      const verifierConfig = await helpers.createConfig(
        {capabilityAgent, zcaps});
      verifierId = verifierConfig.id;
      rootZcap = `urn:zcap:root:${encodeURIComponent(verifierId)}`;
    });

    async function verify({verifiablePresentation, challenge, domain, checks}) {
      const zcapClient = helpers.createZcapClient({capabilityAgent});
      try {
        const {data} = await zcapClient.write({
          url: `${verifierId}/presentations/verify`,
          capability: rootZcap,
          json: {options: {challenge, domain, checks}, verifiablePresentation}
        });
        return data;
      } catch(e) {
        return e.data;
      }
    }

    // VC-JWT 1.1 credential with the given subject, enveloped in a VP-JWT
    // signed by the capability agent. When `holder` is given, it is set on
    // the VP while `iss` stays the signer's DID.
    async function jwtPresentation({subjectId, holder}) {
      const signer = capabilityAgent.getSigner();
      signer.algorithm = 'Ed25519';
      let credential = structuredClone(mockCredential);
      delete credential.proof;
      credential.issuer = capabilityAgent.id;
      if(subjectId === undefined) {
        delete credential.credentialSubject.id;
      } else {
        credential.credentialSubject.id = subjectId;
      }
      credential = await helpers.envelopeCredential(
        {verifiableCredential: credential, signer});
      const presentation = vc.createPresentation(
        {holder: holder ?? capabilityAgent.id});
      presentation['@context'] = [VC_CONTEXT_1];
      presentation.verifiableCredential = [
        credential.id.slice('data:application/jwt,'.length)
      ];
      const {data: {challenge}} = await helpers.createChallenge(
        {capabilityAgent, verifierId});
      const domain = 'rp.example';
      if(holder === undefined) {
        const verifiablePresentation = await helpers.envelopePresentation({
          verifiablePresentation: presentation, challenge, domain, signer
        });
        return {verifiablePresentation, challenge, domain};
      }
      const jwt = await helpers.signJWT({
        payload: {
          iss: capabilityAgent.id, aud: domain, nonce: challenge,
          vp: presentation
        },
        protectedHeader: {alg: 'EdDSA', kid: signer.id},
        signer
      });
      const verifiablePresentation = {
        '@context': 'https://www.w3.org/ns/credentials/v2',
        id: `data:application/jwt,${jwt}`,
        type: 'EnvelopedVerifiablePresentation'
      };
      return {verifiablePresentation, challenge, domain};
    }

    // DI VP signed by `signingKey`, presenting a DI VC issued to
    // `subjectId`, with an optional self-asserted `holder`.
    async function diPresentation({signingKey, subjectId, holder}) {
      const {methodFor: issuerMethodFor} = await didKeyDriver.generate();
      const issuerKey = issuerMethodFor({purpose: 'assertionMethod'});
      const credential = structuredClone(mockCredential);
      delete credential.proof;
      credential.issuer = issuerKey.controller;
      credential.credentialSubject.id = subjectId;
      const verifiableCredential = await vc.issue({
        credential,
        suite: new Ed25519Signature2020({key: issuerKey}),
        documentLoader: brDocLoader
      });
      const presentation = vc.createPresentation(
        {holder, verifiableCredential});
      const {data: {challenge}} = await helpers.createChallenge(
        {capabilityAgent, verifierId});
      await vc.signPresentation({
        presentation,
        suite: new Ed25519Signature2020({key: signingKey}),
        challenge,
        documentLoader: brDocLoader
      });
      return {verifiablePresentation: presentation, challenge};
    }

    async function presenterKey() {
      const {methodFor} = await didKeyDriver.generate();
      return methodFor({purpose: 'authentication'});
    }

    it('verifies a VC-JWT VP signed by the credential subject', async () => {
      const result = await verify({
        ...await jwtPresentation({subjectId: capabilityAgent.id}),
        checks: ['proof', 'holderBinding']
      });
      result.verified.should.equal(true);
      result.checks.should.include('holderBinding');
    });

    it('rejects a VC-JWT VP not signed by the credential subject',
      async () => {
        const result = await verify({
          ...await jwtPresentation({subjectId: OTHER_DID}),
          checks: ['proof', 'holderBinding']
        });
        result.verified.should.equal(false);
        result.error.name.should.equal('HolderBindingError');
      });

    it('rejects a VC-JWT VP whose credential has no subject', async () => {
      const result = await verify({
        ...await jwtPresentation({subjectId: undefined}),
        checks: ['proof', 'holderBinding']
      });
      result.verified.should.equal(false);
      result.error.name.should.equal('HolderBindingError');
    });

    it('binds a VC-JWT VP whose holder is an object without an id',
      async () => {
        // the holder comes from the verified signer, not from `holder`
        const result = await verify({
          ...await jwtPresentation({
            subjectId: capabilityAgent.id, holder: {type: 'Person'}
          }),
          checks: ['proof', 'holderBinding']
        });
        result.verified.should.equal(true);
      });

    it('does not check binding unless "holderBinding" is requested',
      async () => {
        const result = await verify({
          ...await jwtPresentation({subjectId: OTHER_DID}),
          checks: ['proof']
        });
        result.verified.should.equal(true);
      });

    it('verifies a DI VP signed by the credential subject', async () => {
      const signingKey = await presenterKey();
      const result = await verify({
        ...await diPresentation({
          signingKey, subjectId: signingKey.controller
        }),
        checks: ['proof', 'holderBinding']
      });
      result.verified.should.equal(true);
    });

    it('rejects a DI VP whose self-asserted holder is the subject but whose ' +
      'proof is by another key', async () => {
      const signingKey = await presenterKey();
      const result = await verify({
        ...await diPresentation({
          signingKey, subjectId: OTHER_DID, holder: OTHER_DID
        }),
        checks: ['proof', 'holderBinding']
      });
      result.verified.should.equal(false);
      result.error.name.should.equal('HolderBindingError');
    });
  });
});
