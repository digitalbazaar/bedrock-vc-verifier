/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const {config} = bedrock;
const didVeresOne = require('did-veres-one');
const {Ed25519Signature2020} = require('@digitalbazaar/ed25519-signature-2020');
const jsigs = require('jsonld-signatures');
const mockData = require('./mock.data');
const {securityLoader} = require('@digitalbazaar/security-document-loader');
const veresOneCtx = require('veres-one-context');
const webkmsCtx = require('webkms-context');
const zcapCtx = require('zcap-context');

const loader = securityLoader();
loader.addStatic(
  veresOneCtx.constants.VERES_ONE_CONTEXT_V1_URL, veresOneCtx.contexts);
loader.addStatic(zcapCtx.CONTEXT_URL, zcapCtx.CONTEXT);
loader.addStatic(webkmsCtx.CONTEXT_URL, webkmsCtx.CONTEXT);

const options = {
  hostname: config['vc-verifier'].ledgerHostname,
  mode: 'dev'
};

loader.protocolHandlers.get('did').use(didVeresOne.driver(options));

const securityDocumentLoader = loader.build();

const {VeresOneClient} = didVeresOne;
const client = new VeresOneClient(options);
// FIXME: temporary, did-veres-one will be returning a keypair that can be
// used for signing operations

const challenge = 'challengeString';
const domain = 'example.org';
const {sign} = jsigs;
const api = {
  generateCredential,
  generatePresentation,
  waitForConsensus,
  challenge,
  domain
};
module.exports = api;

async function generateCredential({signingKey, issuer}) {
  const mockCredential = bedrock.util.clone(mockData.credentials.alpha);
  mockCredential.issuer = issuer;
  const {AssertionProofPurpose} = jsigs.purposes;
  const credential = await sign(mockCredential, {
    documentLoader: securityDocumentLoader,
    suite: new Ed25519Signature2020({key: signingKey}),
    purpose: new AssertionProofPurpose()
  });
  return {credential};
}

async function generatePresentation(
  {challenge, domain, credentialSigningKey, presentationSigningKey, issuer}) {
  const mockPresentation = bedrock.util.clone(mockData.presentations.alpha);
  const {AuthenticationProofPurpose} = jsigs.purposes;
  const {credential} = await generateCredential(
    {signingKey: credentialSigningKey, issuer});
  mockPresentation.verifiableCredential.push(credential);
  const presentation = await sign(mockPresentation, {
    documentLoader: securityDocumentLoader,
    suite: new Ed25519Signature2020({key: presentationSigningKey}),
    purpose: new AuthenticationProofPurpose({challenge, domain})
  });
  return {presentation};
}

async function waitForConsensus({did}) {
  let found = false;
  let didRecord;
  while(!found) {
    try {
      // using v1.client.get here because v1.get will pull locally created
      // did from local storage as a pairwise did
      didRecord = await client.get({did});
      found = true;
    } catch(e) {
      if(e.response.status !== 404) {
        throw e;
      }
      console.log('Waiting for consensus...');
      await new Promise(resolve => setTimeout(resolve, 1000));
      continue;
    }
  }
  return didRecord;
}
