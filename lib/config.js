/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
import bedrock from 'bedrock';

const {config} = bedrock;

const cfg = config['vc-verifier'] = {};

cfg.challenges = {
  // by default, challenges must be used within 15 minutes
  ttl: 1000 * 60 * 15
};

// document loader configuration for the verifier; all verifier instances
// will securely load DID documents using `bedrock-did-io` and any contexts
// that have been specifically added to them; these config options below
// also allow any verifier instance to optionally load `http` and `https`
// documents directly from the Web -- which is not considered secure and
// should only be used for development purposes
cfg.documentLoader = {
  // `true` enables all verifiers to fetch `http` documents from the Web
  http: false,
  // `true` enables all verifiers to fetch `https` documents from the Web
  https: false
};

cfg.supportedSuites = ['Ed25519Signature2018', 'Ed25519Signature2020'];

cfg.routes = {
  challenges: '/challenges',
  credentialsVerify: '/credentials/verify',
  presentationsVerify: '/presentations/verify'
};
