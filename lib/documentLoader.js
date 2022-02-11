/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const {
  jsonLdDocumentLoader,
  httpClientHandler
} = require('bedrock-jsonld-document-loader');

const {didIo} = require('bedrock-did-io');

const {config} = bedrock;

const api = {};

const {'vc-verifier': cfg} = config;

jsonLdDocumentLoader.setDidResolver(didIo);

if(cfg.documentLoader.mode === 'web') {
  jsonLdDocumentLoader.setProtocolHandler({
    protocol: 'http', handler: httpClientHandler});
  jsonLdDocumentLoader.setProtocolHandler({
    protocol: 'https', handler: httpClientHandler});
}

api.documentLoader = jsonLdDocumentLoader.build();
module.exports = api;
