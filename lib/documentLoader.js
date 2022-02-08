/*!
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {agent} = require('bedrock-https-agent');
const bedrock = require('bedrock');
const {didIo} = require('bedrock-did-io');
const {
  documentLoader: bedrockLoader
} = require('bedrock-jsonld-document-loader');
const {httpClient} = require('@digitalbazaar/http-client');
const jsonld = require('jsonld');
const {constants: {DID_CONTEXT_URL}} = require('did-context');
const {constants: {VERES_ONE_CONTEXT_V1_URL}} = require('veres-one-context');

const {config} = bedrock;

const api = {};

module.exports = api;

bedrock.events.on('bedrock.start', () => {
  const {'vc-verifier': cfg} = config;
  api.loaders.push(bedrockLoader);
  // FIXME: use computed config API instead of eventing this
  api.loaders.push(_didLoader);

  // if enabled, add loader for remote documents
  if(cfg.documentLoader.mode === 'web') {
    api.loaders.push(_webLoader);
  }
});

api.documents = new Map();

api.documentLoader = async url => {
  let result;

  for(const loader of api.loaders) {
    try {
      result = await loader(url);
    } catch(e) {
      // this loader failed move on to the next
      continue;
    }
    if(result) {
      return result;
    }
  }
  // failure, throw
  throw new Error(`Document not found: ${url}`);
};

// delimiters for a DID URL
const splitRegex = /[;\/\?#]/;
// this loader is intended for dids
api.documentCache = async url => {
  if(!url.startsWith('did:')) {
    throw new Error('NotFoundError');
  }
  const [did] = url.split(splitRegex);
  let didDocument;
  if(api.documents.has(did)) {
    didDocument = bedrock.util.clone(api.documents.get(did));
  } else {
    throw new Error('NotFoundError');
  }
  if(!url.includes('#')) {
    return {
      contextUrl: null,
      document: didDocument,
      documentUrl: url
    };
  }
  // try to find the specific object in the DID document
  const document = await _pluckDidNode(did, url, didDocument);
  return {
    contextUrl: null,
    document,
    documentUrl: url
  };
};

api.loaders = [api.documentCache];

async function _didLoader(url) {
  if(!url.startsWith('did:')) {
    throw new Error('NotFoundError');
  }
  let document;
  try {
    document = await didIo.get({did: url});
  } catch(e) {
    throw new Error('NotFoundError');
  }
  return {
    contextUrl: null,
    documentUrl: url,
    document
  };
}

async function _pluckDidNode(did, target, didDocument) {
  // flatten to isolate target
  const flattened = await jsonld.flatten(didDocument);
  // filter out non-DID nodes and find target
  let found = false;
  const filtered = [];
  for(const node of flattened) {
    const id = node['@id'];
    if(id === target) {
      filtered.push(node);
      found = true;
      break;
    }
  }
  // target not found
  if(!found) {
    const err = new Error('Not Found');
    err.httpStatusCode = 404;
    err.status = 404;
    throw err;
  }

  const context = [DID_CONTEXT_URL, VERES_ONE_CONTEXT_V1_URL];
  // frame target
  const framed = await jsonld.frame(
    filtered, {'@context': context, id: target}, {embed: '@always'});
  return Object.assign({'@context': context}, framed['@graph'][0]);
}

/**
 * Remote contexts might not return responses with json content types.
 * In those cases we will need to parse the string or binary stream.
 *
 * @param {object} result - The response.
 *
 * @returns {Promise<object> - The resulting jsonld document.
 */
async function _getDocument(result) {
  try {
    // if the response data is a string assume
    // it is json and parse it
    if(typeof result.data === 'string') {
      return JSON.parse(result.data);
    }
    // if the resulting data was already parsed by http-client
    // then return it as is
    if(result.data) {
      return result.data;
    }
    // in the case were http-client could not safely
    // assume the response data is json (the content-type did
    // not contain json) we will try to turn the stream
    // into json
    return result.json();
  } catch(e) {
    console.error('failed to get json', e);
    throw e;
  }
}

async function _webLoader(url) {
  if(!url.startsWith('http')) {
    throw new Error('NotFoundError');
  }
  let data;
  try {
    const result = await httpClient.get(url, {agent});
    data = await _getDocument(result);
  } catch(e) {
    throw new Error('NotFoundError');
  }

  return {
    contextUrl: null,
    document: data,
    documentUrl: url
  };
}
