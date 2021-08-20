/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const {config} = bedrock;
const {httpClient} = require('@digitalbazaar/http-client');
const helpers = require('./helpers');
const {agent} = require('bedrock-https-agent');
const didVeresOne = require('did-veres-one');

const options = {
  mode: 'test'
};
const veresDriver = didVeresOne.driver(options);

const urls = {
  verify: `${config.server.baseUri}/vc/verify`,
  verification({verifierId, referenceId}) {
    return `${config.server.baseUri}/verifiers/${verifierId}/` +
      `verifications/${referenceId}`;
  }
};

describe('verify API using local DID document loader', () => {
  it.skip('verifies a valid credential', async () => {
    const {challenge, domain} = helpers;
    let error;
    let result;
    const {
      didDocument,
      methodFor
    } = await veresDriver.generate({didType: 'nym'});

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
        agent,
        json: {challenge, domain, presentation},
      });
    } catch(e) {
      error = e;
    }
    should.not.exist(error);
    should.exist(result.data);
    const {data} = result;
    data.should.be.an('object');
    should.exist(data.verified);
    data.verified.should.be.a('boolean');
    data.verified.should.equal(true);
  });
  it('verifies a credential with a verifierId and a referenceId',
    async () => {
      const {challenge, domain} = helpers;
      let error;
      let result;
      const {
        methodFor
      } = await veresDriver.generate(
        {didType: 'nym', keyType: 'Ed25519VerificationKey2020'});
      const credentialSigningKey = methodFor({purpose: 'capabilityInvocation'});
      const presentationSigningKey = credentialSigningKey;
      const {presentation} = await helpers.generatePresentation(
        {challenge, domain, credentialSigningKey, presentationSigningKey});
      const url = urls.verification({verifiedId: 'foo', referenceId: 'bar'});
      try {
        result = await httpClient.post(url, {
          agent,
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
      data.verified.should.equal(true);
    });
});
