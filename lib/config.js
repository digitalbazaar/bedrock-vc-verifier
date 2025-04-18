/*!
 * Copyright (c) 2019-2025 Digital Bazaar, Inc. All rights reserved.
 */
import {config} from '@bedrock/core';
import '@bedrock/app-identity';

const cfg = config['vc-verifier'] = {};

cfg.challenges = {
  // by default, challenges must be used within 15 minutes
  ttl: 1000 * 60 * 15
};

// document loader configuration for the verifier; all verifier instances
// will securely load DID documents using `bedrock-did-io` and any contexts
// that have been specifically added to them; these config options below
// also allow any verifier instance to optionally load `http` and `https`
// documents directly from the Web
cfg.documentLoader = {
  // `true` enables all verifier instances that do not have document loader
  // instance-specific constraints to fetch `http` documents from the Web
  http: false,
  // `true` enables all verifier instances that do not have document loader
  // instance-specific constraints to fetch `https` documents from the Web
  https: true
};

cfg.supportedSuites = [
  'bbs-2023',
  'Ed25519Signature2018',
  'Ed25519Signature2020',
  'eddsa-2022',
  'ecdsa-2019',
  'ecdsa-rdfc-2019',
  'eddsa-rdfc-2022',
  'ecdsa-jcs-2019',
  'eddsa-jcs-2022',
  'ecdsa-sd-2023',
  'ecdsa-xi-2023'
];

cfg.routes = {
  challenges: '/challenges',
  credentialsVerify: '/credentials/verify',
  presentationsVerify: '/presentations/verify'
};

// create dev application identity for vc-verifier (must be overridden in
// deployments) ...and `ensureConfigOverride` has already been set via
// `bedrock-app-identity` so it doesn't have to be set here
config['app-identity'].seeds.services['vc-verifier'] = {
  id: 'did:key:z6Mkff1TPyQ7nh3qXYGe3gJn26aaLX5ACJBi7s6Ei6MW3qAc',
  seedMultibase: 'z1AYfdySL6F2wHarpfjSo1GaMaCW11TWbKyTP4eKBosmiDw',
  serviceType: 'vc-verifier'
};
