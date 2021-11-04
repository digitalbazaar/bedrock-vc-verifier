/*!
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const {getAppIdentity} = require('bedrock-app-identity');
const {Ed25519Signature2020} = require('@digitalbazaar/ed25519-signature-2020');
const {httpsAgent} = require('bedrock-https-agent');
const jsigs = require('jsonld-signatures');
const mockData = require('./mock.data');
const {ZcapClient} = require('@digitalbazaar/ezcap');

const {_documentLoader: documentLoader} = require('bedrock-vc-verifier');

exports.challenge = 'challengeString';
exports.domain = 'example.org';

exports.createMeter = async ({controller} = {}) => {
  // create signer using the application's capability invocation key
  const {keys: {capabilityInvocationKey}} = getAppIdentity();

  const zcapClient = new ZcapClient({
    agent: httpsAgent,
    invocationSigner: capabilityInvocationKey.signer(),
    SuiteClass: Ed25519Signature2020
  });
  // create a meter
  const meterService = `${bedrock.config.server.baseUri}/meters`;
  let meter = {
    controller,
    product: {
      // mock ID for verifier service product
      id: 'urn:uuid:275e0194-3da5-11ec-a574-10bf48838a41'
    }
  };
  ({data: {meter}} = await zcapClient.write({url: meterService, json: meter}));

  // return full meter ID
  const {id} = meter;
  return {id: `${meterService}/${id}`};
};

exports.createInstance = async ({
  capabilityAgent, ipAllowList, referenceId, meterId
}) => {
  if(!meterId) {
    // create a meter for the keystore
    ({id: meterId} = await exports.createMeter(
      {controller: capabilityAgent.id}));
  }

  // create instance config
  let config = {
    sequence: 0,
    controller: capabilityAgent.id,
    meterId
  };
  if(referenceId) {
    config.referenceId = referenceId;
  }
  if(ipAllowList) {
    config.ipAllowList = ipAllowList;
  }

  const zcapClient = new ZcapClient({
    agent: httpsAgent,
    invocationSigner: capabilityAgent.getSigner(),
    SuiteClass: Ed25519Signature2020
  });
  // create an instance
  const verifierService = `${bedrock.config.server.baseUri}/verifiers`;
  ({data: {config}} = await zcapClient.write(
    {url: verifierService, json: config}));

  // return full instance ID
  const {id} = config;
  return {id: `${verifierService}/${id}`};
};

exports.generateCredential = async function({signingKey, issuer}) {
  const mockCredential = bedrock.util.clone(mockData.credentials.alpha);
  mockCredential.issuer = issuer;
  const {AssertionProofPurpose} = jsigs.purposes;
  const credential = await jsigs.sign(mockCredential, {
    documentLoader,
    suite: new Ed25519Signature2020({key: signingKey}),
    purpose: new AssertionProofPurpose()
  });
  return {credential};
};

exports.generatePresentation = async function(
  {challenge, domain, credentialSigningKey, presentationSigningKey, issuer}) {
  const mockPresentation = bedrock.util.clone(mockData.presentations.alpha);
  const {AuthenticationProofPurpose} = jsigs.purposes;
  const {credential} = await exports.generateCredential(
    {signingKey: credentialSigningKey, issuer});
  mockPresentation.verifiableCredential.push(credential);
  const presentation = await jsigs.sign(mockPresentation, {
    documentLoader,
    suite: new Ed25519Signature2020({key: presentationSigningKey}),
    purpose: new AuthenticationProofPurpose({challenge, domain})
  });
  return {presentation};
};
