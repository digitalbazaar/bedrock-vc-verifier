/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const {config} = bedrock;
const {httpClient} = require('@digitalbazaar/http-client');
const {loader} = require('bedrock-vc-verifier');
const helpers = require('./helpers');
const https = require('https');
const v1 = require('did-veres-one');
const {CachedResolver} = require('@digitalbazaar/did-io');

const resolver = new CachedResolver();

const options = {
  hostname: config['vc-verifier'].ledgerHostname,
  mode: 'test'
};

const veresDriver = v1.driver(options);
resolver.use(veresDriver);

const strictSSL = false;

const urls = {
  verify: `${config.server.baseUri}/vc/verify`,
  verification({verifierId, referenceId}) {
    return `${config.server.baseUri}/verifiers/${verifierId}/` +
      `verifications/${referenceId}`;
  }
};

describe('verify API using local DID document loader', () => {
  it.only('verifies a valid credential', async () => {
    const {challenge, domain} = helpers;
    let error;
    let result;
    const {
      didDocument,
      methodFor
    } = await veresDriver.generate(
      {didType: 'nym', keyType: 'Ed25519VerificationKey2020'});

    // NOTE: For a Veres One DID that was generated _and registered_, you'd
    // want to use keys for the 'assertionMethod' and 'authentication'
    // purpose. However, for un-registered methods, only the
    // capabilityInvocation key will be used.
    const credentialSigningKey = methodFor({purpose: 'capabilityInvocation'});
    const presentationSigningKey = credentialSigningKey;

    const {presentation} = await helpers.generatePresentation({
      challenge,
      domain,
      credentialSigningKey,
      presentationSigningKey,
      issuer: didDocument.id
    });
    try {
      result = await httpClient.post(urls.verify, {
        agent: new https.Agent({rejectUnauthorized: strictSSL}),
        json: {challenge, domain, presentation},
      });
    } catch(e) {
      console.error(e);
      error = e;
    }
    should.not.exist(error);
    should.exist(result.data);
    const {data} = result;
    should.exist(data);
    data.should.be.an('object');
    should.exist(data.verified);
    data.verified.should.be.a('boolean');
    data.verified.should.be.true;
  });
  it('verifies a credential with a verifierId and a referenceId', async () => {
    const {challenge, domain} = helpers;
    let error;
    let result;
    const {
      v1DidDoc: credentialSignerDid,
      assertionMethodKey: credentialSigningKey
    } = await helpers.generateDid();
    const {
      v1DidDoc: presentationSignerDid,
      authenticationKey: presentationSigningKey
    } = await helpers.generateDid();
    loader.documents.set(credentialSignerDid.id, credentialSignerDid.doc);
    loader.documents.set(presentationSignerDid.id, presentationSignerDid.doc);
    const {presentation} = await helpers.generatePresentation(
      {challenge, domain, credentialSigningKey, presentationSigningKey});
    const url = urls.verification({verifiedId: 'foo', referenceId: 'bar'});
    try {
      result = await httpClient.post(url, {
        agent: new https.Agent({rejectUnauthorized: strictSSL}),
        json: {challenge, domain, presentation},
      });
    } catch(e) {
      error = e;
    }
    should.not.exist(error);
    should.exist(result.data);
    const {data} = result;
    should.exist(data);
    data.should.be.an('object');
    should.exist(data.verified);
    data.verified.should.be.a('boolean');
    data.verified.should.be.true;

  });
});
