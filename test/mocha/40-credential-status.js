/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const {config} = bedrock;
const {httpClient} = require('@digitalbazaar/http-client');
const {agent} = require('bedrock-https-agent');
const vc = require('@digitalbazaar/vc');
const statusListCtx = require('vc-status-list-context');
const {_documentLoader: documentLoader} = require('bedrock-vc-verifier');
const {extendContextLoader} = require('jsonld-signatures');
const {Ed25519VerificationKey2020} =
  require('@digitalbazaar/ed25519-verification-key-2020');
const {Ed25519Signature2020} = require('@digitalbazaar/ed25519-signature-2020');

const VC_SL_CONTEXT_URL = statusListCtx.constants.CONTEXT_URL_V1;
const VC_SL_CONTEXT = statusListCtx.contexts.get(VC_SL_CONTEXT_URL);

const documents = new Map();
documents.set(VC_SL_CONTEXT_URL, VC_SL_CONTEXT);

const encodedList100k =
  'H4sIAAAAAAAAA-3BMQEAAADCoPVPbQsvoAAAAAAAAAAAAAAAAP4GcwM92tQwAAA';
const slCredential = {
  '@context': [
    'https://www.w3.org/2018/credentials/v1',
    VC_SL_CONTEXT_URL
  ],
  id: 'https://example.com/status/1',
  issuer: 'did:key:z6Mktpn6cXks1PBKLMgZH2VaahvCtBMF6K8eCa7HzrnuYLZv',
  issuanceDate: '2021-03-10T04:24:12.164Z',
  type: ['VerifiableCredential', 'StatusList2021Credential'],
  credentialSubject: {
    id: `https://example.com/status/1#list`,
    type: 'RevocationList2021',
    encodedList: encodedList100k
  }
};
documents.set(slCredential.id, slCredential);

const docLoader = extendContextLoader(async url => {
  const doc = documents.get(url);
  if(doc) {
    return {
      contextUrl: null,
      documentUrl: url,
      document: doc
    };
  }
  return documentLoader(url);
});
describe('verify API using local DID document loader', () => {
  it.skip('verifies and checks status of a credential', async () => {
    const unsignedCredential = {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        VC_SL_CONTEXT_URL,
        'https://w3id.org/security/suites/ed25519-2020/v1'
      ],
      id: 'urn:uuid:a0418a78-7924-11ea-8a23-10bf48838a41',
      type: ['VerifiableCredential', 'example:TestCredential'],
      credentialSubject: {
        id: 'urn:uuid:4886029a-7925-11ea-9274-10bf48838a41',
        'example:test': 'foo'
      },
      issuanceDate: '2010-01-01T19:23:24Z',
      credentialStatus: {
        id: 'https://example.com/status/1#67342',
        type: 'RevocationList2021Status',
        statusListIndex: '67342',
        statusListCredential: slCredential.id
      },
      issuer: slCredential.issuer,
    };
    const keyData = {
      id: 'did:key:z6Mktpn6cXks1PBKLMgZH2VaahvCtBMF6K8eCa7HzrnuYLZv#' +
        'z6Mktpn6cXks1PBKLMgZH2VaahvCtBMF6K8eCa7HzrnuYLZv',
      controller: 'did:key:z6Mktpn6cXks1PBKLMgZH2VaahvCtBMF6K8eCa7HzrnuYLZv',
      type: 'Ed25519VerificationKey2020',
      publicKeyMultibase: 'z6Mktpn6cXks1PBKLMgZH2VaahvCtBMF6K8eCa7HzrnuYLZv',
      privateKeyMultibase: 'zrv2rP9yjtz3YwCas9m6hnoPxmoqZV72xbCEuomXi4wwSS4S' +
        'hekesADYiAMHoxoqfyBDKQowGMvYx9rp6QGJ7Qbk7Y4'
    };
    const keyPair = await Ed25519VerificationKey2020.from(keyData);

    const suite = new Ed25519Signature2020({key: keyPair});

    const verifiableCredential = await vc.issue({
      credential: unsignedCredential,
      documentLoader: docLoader,
      suite
    });
    console.log(verifiableCredential, '<><><><>verifiableCredential');
    let error;
    let result;
    try {
      result = await httpClient.post(
        `${config.server.baseUri}/verifier/credentials`, {
          agent,
          json: {
            options: {
              checks: ['credentialStatus'],
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
});
