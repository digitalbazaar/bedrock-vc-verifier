/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import * as bedrock from '@bedrock/core';
import * as helpers from './helpers.js';
import * as vc from '@digitalbazaar/vc';
import {
  applyReturnHint, resolveReturnHint
} from '@bedrock/vc-verifier/lib/returnHints.js';
import {driver as _didKeyDriver} from '@digitalbazaar/did-method-key';
import {agent} from '@bedrock/https-agent';
import {documentLoader as brDocLoader} from '@bedrock/jsonld-document-loader';
import {CapabilityAgent} from '@digitalbazaar/webkms-client';
import {createRequire} from 'node:module';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {httpClient} from '@digitalbazaar/http-client';
import {registerReturnHint} from '@bedrock/vc-verifier';

import {mockData} from './mock.data.js';

const require = createRequire(import.meta.url);

const {baseUrl} = mockData;
const serviceType = 'vc-verifier';
const didKeyDriver = _didKeyDriver();

const mockCredentials = require('./mock-credentials.json');

const RETURN_HINT_NOT_APPLIED =
  'tag:digitalbazaar.com,2026:vc-verifier:return-hint-not-applied';

// test-only return hints; each adds a marker naming the hint to a copy of
// the payload
const markWith = hint => async ({payload}) => {
  payload.returnHintMarker = hint;
  return payload;
};
// applies to payloads that are not in an envelope (Data Integrity)
const notEnveloped = [
  {kind: 'credential', mediaType: 'application/vc'},
  {kind: 'presentation', mediaType: 'application/vp'}
];
registerReturnHint({
  hint: 'test-marker', appliesTo: notEnveloped, map: markWith('test-marker')
});
registerReturnHint({
  hint: 'test-other-marker',
  appliesTo: notEnveloped,
  map: markWith('test-other-marker')
});
registerReturnHint({
  hint: 'test-vc-only',
  appliesTo: [{mediaType: 'application/vc'}],
  map: markWith('test-vc-only')
});
// uses the function form of `appliesTo`
registerReturnHint({
  hint: 'test-function',
  appliesTo: ({payload, kind}) =>
    kind === 'credential' && payload.id === 'urn:test:function',
  map: markWith('test-function')
});
registerReturnHint({
  hint: 'test-jwt-only',
  appliesTo: [{mediaType: 'application/jwt'}],
  map: markWith('test-jwt-only')
});
registerReturnHint({
  hint: 'test-throws',
  appliesTo: [{}],
  async map() {
    throw new Error('Mapping failed.');
  }
});
registerReturnHint({
  hint: 'test-throws-public',
  appliesTo: [{}],
  async map() {
    throw new bedrock.util.BedrockError('Unsupported document.', {
      name: 'NotSupportedError',
      details: {public: true}
    });
  }
});
registerReturnHint({
  hint: 'test-returns-nothing',
  appliesTo: [{}],
  async map() {}
});
registerReturnHint({
  hint: 'test-returns-string',
  appliesTo: [{}],
  async map() {
    return 'not a credential';
  }
});
registerReturnHint({
  hint: 'test-applies-to-throws',
  appliesTo() {
    throw new Error('Matcher failed.');
  },
  map: markWith('test-applies-to-throws')
});

describe('return hints', () => {
  describe('registerReturnHint', () => {
    it('rejects a duplicate hint', () => {
      let error;
      try {
        registerReturnHint({
          hint: 'test-marker', appliesTo: [], map: markWith('test-marker')
        });
      } catch(e) {
        error = e;
      }
      should.exist(error);
      error.message.should.equal(
        'Return hint "test-marker" is already registered.');
    });

    it('rejects invalid options', () => {
      const map = markWith('x');
      const cases = [
        {appliesTo: [], map},
        {hint: '', appliesTo: [], map},
        {hint: 'test-invalid', appliesTo: {}, map},
        {hint: 'test-invalid', appliesTo: []}
      ];
      for(const options of cases) {
        let error;
        try {
          registerReturnHint(options);
        } catch(e) {
          error = e;
        }
        should.exist(error);
        error.should.be.instanceOf(TypeError);
      }
    });
  });

  describe('resolveReturnHint', () => {
    it('uses the request option over the instance default', () => {
      resolveReturnHint({
        config: {verifyOptions: {returnHint: 'a'}},
        options: {returnHint: 'b'}
      }).should.equal('b');
    });

    it('uses the instance default when the request has none', () => {
      resolveReturnHint({
        config: {verifyOptions: {returnHint: 'a'}}, options: {}
      }).should.equal('a');
    });

    it('returns undefined when neither is set', () => {
      should.not.exist(resolveReturnHint({config: {}, options: {}}));
    });
  });

  describe('applyReturnHint', () => {
    it('maps a copy of the payload', async () => {
      const payload = {id: 'urn:test:1'};
      const result = await applyReturnHint({
        hint: 'test-marker', payload, kind: 'credential',
        mediaType: 'application/vc'
      });
      result.should.eql({
        payload: {id: 'urn:test:1', returnHintMarker: 'test-marker'}
      });
      // the input payload is not changed
      payload.should.eql({id: 'urn:test:1'});
    });

    it('matches on kind and media type', async () => {
      const payload = {id: 'urn:test:1'};
      const vp = await applyReturnHint({
        hint: 'test-marker', payload, kind: 'presentation',
        mediaType: 'application/vp'
      });
      vp.payload.returnHintMarker.should.equal('test-marker');
      // `test-marker` does not apply to a credential w/`application/vp`
      const mismatch = await applyReturnHint({
        hint: 'test-marker', payload, kind: 'credential',
        mediaType: 'application/vp'
      });
      mismatch.should.eql({payload});
    });

    it('applies an appliesTo function', async () => {
      const applied = await applyReturnHint({
        hint: 'test-function', payload: {id: 'urn:test:function'},
        kind: 'credential', mediaType: 'application/vc'
      });
      applied.payload.returnHintMarker.should.equal('test-function');
      const payload = {id: 'urn:test:1'};
      const notApplied = await applyReturnHint({
        hint: 'test-function', payload, kind: 'credential',
        mediaType: 'application/vc'
      });
      notApplied.should.eql({payload});
    });

    it('matches on media type', async () => {
      const payload = {id: 'urn:test:1'};
      const result = await applyReturnHint({
        hint: 'test-jwt-only', payload, kind: 'presentation',
        mediaType: 'application/jwt'
      });
      result.payload.returnHintMarker.should.equal('test-jwt-only');
    });

    it('returns a payload it does not apply to unchanged', async () => {
      const payload = {id: 'urn:test:1'};
      const result = await applyReturnHint({
        hint: 'test-jwt-only', payload, kind: 'credential'
      });
      result.should.eql({payload});
    });

    it('returns problem details when the mapping fails', async () => {
      const payload = {id: 'urn:test:1'};
      const result = await applyReturnHint({
        hint: 'test-throws', payload, kind: 'credential'
      });
      result.should.eql({
        payload,
        problemDetails: {
          type: RETURN_HINT_NOT_APPLIED,
          title: 'Return hint not applied',
          detail: 'Return hint "test-throws" could not be applied.'
        }
      });
    });

    it('returns the message of a public mapping error', async () => {
      const payload = {id: 'urn:test:1'};
      const result = await applyReturnHint({
        hint: 'test-throws-public', payload, kind: 'credential'
      });
      result.payload.should.equal(payload);
      result.problemDetails.detail.should.equal(
        '"test-throws-public": Unsupported document.');
    });

    it('returns problem details when the mapping returns nothing',
      async () => {
        const payload = {id: 'urn:test:1'};
        const result = await applyReturnHint({
          hint: 'test-returns-nothing', payload, kind: 'credential'
        });
        result.should.eql({
          payload,
          problemDetails: {
            type: RETURN_HINT_NOT_APPLIED,
            title: 'Return hint not applied',
            detail: '"test-returns-nothing": mapping returned no payload.'
          }
        });
      });

    it('returns problem details when the mapping returns a non-object',
      async () => {
        const payload = {id: 'urn:test:1'};
        const result = await applyReturnHint({
          hint: 'test-returns-string', payload, kind: 'credential'
        });
        result.payload.should.equal(payload);
        result.problemDetails.detail.should.equal(
          '"test-returns-string": mapping returned no payload.');
      });

    it('returns problem details when appliesTo throws', async () => {
      const payload = {id: 'urn:test:1'};
      const result = await applyReturnHint({
        hint: 'test-applies-to-throws', payload, kind: 'credential'
      });
      result.payload.should.equal(payload);
      result.problemDetails.type.should.equal(RETURN_HINT_NOT_APPLIED);
      result.problemDetails.detail.should.equal(
        'Return hint "test-applies-to-throws" could not be applied.');
    });

    it('returns problem details for an unknown hint', async () => {
      const payload = {id: 'urn:test:1'};
      const result = await applyReturnHint({
        hint: 'test-unknown', payload, kind: 'credential',
        mediaType: 'application/vc'
      });
      result.should.eql({
        payload,
        problemDetails: {
          type: RETURN_HINT_NOT_APPLIED,
          title: 'Return hint not applied',
          detail: 'Unknown return hint "test-unknown".'
        }
      });
    });
  });

  describe('verify APIs', () => {
    let capabilityAgent;
    let verifierId;
    let rootZcap;
    let hintVerifierId;
    let hintRootZcap;
    let zcaps;
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
      zcaps = {};
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
      const verifierConfig = await helpers.createConfig(
        {capabilityAgent, zcaps});
      verifierId = verifierConfig.id;
      rootZcap = `urn:zcap:root:${encodeURIComponent(verifierId)}`;

      // create verifier instance w/a default return hint
      const hintVerifierConfig = await helpers.createConfig({
        capabilityAgent, zcaps,
        configOptions: {verifyOptions: {returnHint: 'test-marker'}}
      });
      hintVerifierId = hintVerifierConfig.id;
      hintRootZcap = `urn:zcap:root:${encodeURIComponent(hintVerifierId)}`;
    });

    const verifyWith = async ({
      options, verifiableCredential, id = verifierId, capability = rootZcap
    }) => {
      const zcapClient = helpers.createZcapClient({capabilityAgent});
      return zcapClient.write({
        url: `${id}/credentials/verify`,
        capability,
        json: {options, verifiableCredential}
      });
    };
    // signs a presentation of mockCredentials[0] with a fresh challenge
    const signedPresentation = async () => {
      const {data: {challenge}} = await helpers.createChallenge(
        {capabilityAgent, verifierId});
      const {methodFor} = await didKeyDriver.generate();
      const signingKey = methodFor({purpose: 'assertionMethod'});
      const suite = new Ed25519Signature2020({key: signingKey});
      const presentation = vc.createPresentation({
        holder: 'did:test:foo',
        id: 'urn:uuid:3e793029-d699-4096-8e74-5ebd956c3137',
        verifiableCredential: structuredClone(mockCredentials[0])
      });
      await vc.signPresentation({
        presentation, suite, challenge, documentLoader: brDocLoader
      });
      return {challenge, presentation};
    };
    const verifyPresentationWith = async ({
      options, presentation, id = verifierId, capability = rootZcap
    }) => {
      const zcapClient = helpers.createZcapClient({capabilityAgent});
      return zcapClient.write({
        url: `${id}/presentations/verify`,
        capability,
        json: {options, verifiablePresentation: presentation}
      });
    };
    const v1Options = ({returnHint, returnCredential = true} = {}) => ({
      checks: ['proof'],
      responseFormat: 'vcalm-v1',
      returnCredential,
      ...(returnHint !== undefined && {returnHint})
    });

    it('applies a request return hint to a credential', async () => {
      const {data} = await verifyWith({
        options: v1Options({returnHint: 'test-marker'}),
        verifiableCredential: mockCredentials[0]
      });
      data.verified.should.equal(true);
      data.credential.should.eql({
        ...mockCredentials[0], returnHintMarker: 'test-marker'
      });
      data.should.not.have.property('problemDetails');
    });

    it('applies a request return hint to a presentation', async () => {
      const {challenge, presentation} = await signedPresentation();
      const {data} = await verifyPresentationWith({
        options: {
          challenge,
          checks: ['proof'],
          responseFormat: 'vcalm-v1',
          returnPresentation: true,
          returnHint: 'test-marker'
        },
        presentation
      });
      data.verified.should.equal(true);
      data.verifiablePresentation.should.eql({
        ...presentation, returnHintMarker: 'test-marker'
      });
      data.should.not.have.property('problemDetails');
    });

    it('applies the instance default return hint', async () => {
      const {data} = await verifyWith({
        options: v1Options(),
        verifiableCredential: mockCredentials[0],
        id: hintVerifierId,
        capability: hintRootZcap
      });
      data.verified.should.equal(true);
      data.credential.returnHintMarker.should.equal('test-marker');
    });

    it('uses the request return hint over the instance default', async () => {
      const {data} = await verifyWith({
        options: v1Options({returnHint: 'test-other-marker'}),
        verifiableCredential: mockCredentials[0],
        id: hintVerifierId,
        capability: hintRootZcap
      });
      data.verified.should.equal(true);
      data.credential.returnHintMarker.should.equal('test-other-marker');
    });

    it('returns the payload unchanged when the hint does not apply',
      async () => {
        const {data} = await verifyWith({
          options: v1Options({returnHint: 'test-jwt-only'}),
          verifiableCredential: mockCredentials[0]
        });
        data.verified.should.equal(true);
        data.credential.should.eql(mockCredentials[0]);
        data.should.not.have.property('problemDetails');
      });

    it('returns the original payload with problemDetails for an unknown ' +
      'return hint', async () => {
      const {data, status} = await verifyWith({
        options: v1Options({returnHint: 'test-unknown'}),
        verifiableCredential: mockCredentials[0]
      });
      status.should.equal(200);
      data.verified.should.equal(true);
      data.credential.should.eql(mockCredentials[0]);
      data.problemDetails.should.eql([{
        type: RETURN_HINT_NOT_APPLIED,
        title: 'Return hint not applied',
        detail: 'Unknown return hint "test-unknown".'
      }]);
    });

    it('rejects a non-string return hint', async () => {
      let error;
      try {
        await verifyWith({
          options: v1Options({returnHint: 1}),
          verifiableCredential: mockCredentials[0]
        });
      } catch(e) {
        error = e;
      }
      should.exist(error);
      error.status.should.equal(400);
      error.data.name.should.equal('ValidationError');
    });

    it('rejects a non-string presentation return hint', async () => {
      const {challenge, presentation} = await signedPresentation();
      let error;
      try {
        await verifyPresentationWith({
          options: {
            challenge,
            checks: ['proof'],
            responseFormat: 'vcalm-v1',
            returnPresentation: true,
            returnHint: {}
          },
          presentation
        });
      } catch(e) {
        error = e;
      }
      should.exist(error);
      error.status.should.equal(400);
      error.data.name.should.equal('ValidationError');
    });

    it('applies an application/vc matcher to a Data Integrity credential',
      async () => {
        const {data} = await verifyWith({
          options: v1Options({returnHint: 'test-vc-only'}),
          verifiableCredential: mockCredentials[0]
        });
        data.verified.should.equal(true);
        data.credential.returnHintMarker.should.equal('test-vc-only');
      });

    it('does not apply an application/vc matcher to a VC-JWT credential',
      async () => {
        let verifiableCredential = structuredClone(mockCredentials[0]);
        delete verifiableCredential.proof;
        const signer = capabilityAgent.getSigner();
        signer.algorithm = 'Ed25519';
        verifiableCredential.issuer = capabilityAgent.id;
        verifiableCredential = await helpers.envelopeCredential({
          verifiableCredential, signer
        });
        const {data} = await verifyWith({
          options: v1Options({returnHint: 'test-vc-only'}),
          verifiableCredential
        });
        data.verified.should.equal(true);
        data.credential.issuer.should.equal(capabilityAgent.id);
        data.credential.should.not.have.property('returnHintMarker');
        data.should.not.have.property('problemDetails');
      });

    it('applies an application/jwt matcher to a VC-JWT credential',
      async () => {
        let verifiableCredential = structuredClone(mockCredentials[0]);
        delete verifiableCredential.proof;
        const signer = capabilityAgent.getSigner();
        signer.algorithm = 'Ed25519';
        verifiableCredential.issuer = capabilityAgent.id;
        verifiableCredential = await helpers.envelopeCredential({
          verifiableCredential, signer
        });
        const {data} = await verifyWith({
          options: v1Options({returnHint: 'test-jwt-only'}),
          verifiableCredential
        });
        data.verified.should.equal(true);
        data.credential.returnHintMarker.should.equal('test-jwt-only');
      });

    it('rejects an instance w/an unregistered default return hint',
      async () => {
        let error;
        try {
          await helpers.createConfig({
            capabilityAgent, zcaps,
            configOptions: {verifyOptions: {returnHint: 'test-unknown'}}
          });
        } catch(e) {
          error = e;
        }
        should.exist(error);
        error.status.should.equal(400);
        error.data.name.should.equal('DataError');
        error.data.message.should.equal('Configuration validation failed.');
        // the cause is set in `details` by the config route
        error.data.details.cause.message.should.equal(
          'Unknown return hint "test-unknown".');
      });

    it('rejects an instance update to an unregistered default return hint',
      async () => {
        const existingConfig = await helpers.getConfig(
          {id: hintVerifierId, capabilityAgent});
        const newConfig = {
          ...existingConfig,
          sequence: existingConfig.sequence + 1,
          verifyOptions: {
            ...existingConfig.verifyOptions, returnHint: 'test-unknown'
          }
        };
        let error;
        try {
          const zcapClient = helpers.createZcapClient({capabilityAgent});
          await zcapClient.write({url: hintVerifierId, json: newConfig});
        } catch(e) {
          error = e;
        }
        should.exist(error);
        error.status.should.equal(400);
        error.data.name.should.equal('DataError');
        error.data.message.should.equal('Unknown return hint "test-unknown".');

        // a registered hint is accepted
        newConfig.verifyOptions.returnHint = 'test-other-marker';
        const zcapClient = helpers.createZcapClient({capabilityAgent});
        const {data} = await zcapClient.write(
          {url: hintVerifierId, json: newConfig});
        data.verifyOptions.returnHint.should.equal('test-other-marker');
      });

    it('returns the original payload with problemDetails when the ' +
      'mapping fails', async () => {
      const {data, status} = await verifyWith({
        options: v1Options({returnHint: 'test-throws'}),
        verifiableCredential: mockCredentials[0]
      });
      status.should.equal(200);
      data.verified.should.equal(true);
      data.credential.should.eql(mockCredentials[0]);
      data.problemDetails.should.eql([{
        type: RETURN_HINT_NOT_APPLIED,
        title: 'Return hint not applied',
        detail: 'Return hint "test-throws" could not be applied.'
      }]);
    });

    it('does not apply the return hint when verification fails',
      async () => {
        const credential = structuredClone(mockCredentials[0]);
        credential.credentialSubject.degree.name = 'Tampered Degree';
        let error;
        try {
          await verifyWith({
            options: v1Options({returnHint: 'test-marker'}),
            verifiableCredential: credential
          });
        } catch(e) {
          error = e;
        }
        should.exist(error);
        error.status.should.equal(400);
        error.data.verified.should.equal(false);
        // returned unmapped, and the hint is not reported as failed
        error.data.credential.should.eql(credential);
        error.data.problemDetails.map(({type}) => type).should.not.include(
          RETURN_HINT_NOT_APPLIED);
      });

    it('does not apply the return hint to a presentation that fails ' +
      'verification', async () => {
      const {challenge, presentation} = await signedPresentation();
      presentation.holder = 'did:test:tampered';
      let error;
      try {
        await verifyPresentationWith({
          options: {
            challenge,
            checks: ['proof'],
            responseFormat: 'vcalm-v1',
            returnPresentation: true,
            returnHint: 'test-marker'
          },
          presentation
        });
      } catch(e) {
        error = e;
      }
      should.exist(error);
      error.data.verified.should.equal(false);
      error.data.verifiablePresentation.should.eql(presentation);
    });

    it('applies the instance default return hint to a presentation',
      async () => {
        const {challenge, presentation} = await signedPresentation();
        const {data} = await verifyPresentationWith({
          id: hintVerifierId,
          capability: hintRootZcap,
          options: {
            challenge,
            checks: ['proof'],
            responseFormat: 'vcalm-v1',
            returnPresentation: true
          },
          presentation
        });
        data.verified.should.equal(true);
        data.verifiablePresentation.should.eql({
          ...presentation, returnHintMarker: 'test-marker'
        });
      });

    for(const [title, returnHint, detail] of [
      ['an unknown hint', 'test-unknown',
        'Unknown return hint "test-unknown".'],
      ['a failing mapping', 'test-throws',
        'Return hint "test-throws" could not be applied.']
    ]) {
      it(`returns the presentation with problemDetails for ${title}`,
        async () => {
          const {challenge, presentation} = await signedPresentation();
          const {data, status} = await verifyPresentationWith({
            options: {
              challenge,
              checks: ['proof'],
              responseFormat: 'vcalm-v1',
              returnPresentation: true,
              returnHint
            },
            presentation
          });
          status.should.equal(200);
          data.verified.should.equal(true);
          data.verifiablePresentation.should.eql(presentation);
          data.problemDetails.should.eql([{
            type: RETURN_HINT_NOT_APPLIED,
            title: 'Return hint not applied',
            detail
          }]);
        });
    }

    for(const [title, returnHint] of [
      ['an empty', ''], ['a too long', 'x'.repeat(257)]
    ]) {
      it(`rejects ${title} return hint`, async () => {
        let error;
        try {
          await verifyWith({
            options: v1Options({returnHint}),
            verifiableCredential: mockCredentials[0]
          });
        } catch(e) {
          error = e;
        }
        should.exist(error);
        error.status.should.equal(400);
        error.data.name.should.equal('ValidationError');
      });
    }

    it('ignores the return hint in the vcalm-v0 response', async () => {
      const {data: expected} = await verifyWith({
        options: {checks: ['proof'], returnCredential: true},
        verifiableCredential: mockCredentials[0]
      });
      const {data} = await verifyWith({
        options: {
          checks: ['proof'], returnCredential: true, returnHint: 'test-unknown'
        },
        verifiableCredential: mockCredentials[0]
      });
      data.should.eql(expected);
    });

    it('ignores the return hint when returnCredential is false', async () => {
      const {data} = await verifyWith({
        options: v1Options({
          returnHint: 'test-unknown', returnCredential: false
        }),
        verifiableCredential: mockCredentials[0]
      });
      data.verified.should.equal(true);
      data.should.not.have.property('credential');
      data.should.not.have.property('problemDetails');
    });
  });
});
