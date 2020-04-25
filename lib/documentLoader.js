/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const axios = require('axios');
const bedrock = require('bedrock');
const brHttpsAgent = require('bedrock-https-agent');
const jsonld = require('jsonld');
const {
  documentLoader: bedrockLoader
} = require('bedrock-jsonld-document-loader');
const {config} = bedrock;
const {config: {constants}} = bedrock;
const didKeyDriver = require('did-method-key').driver();

const {'vc-verifier': cfg} = config;

const api = {};
module.exports = api;

bedrock.events.on('bedrock.start', () => {
  api.loaders.push(bedrockLoader);
  // FIXME: use computed config API instead of eventing this
  if(cfg.ledgerHostname && cfg.mode) {
    // push a v1 ledger loader
    api.loaders.push(_createV1Loader({
      hostname: cfg.ledgerHostname,
      mode: cfg.mode,
    }));
  }
  // add loader for `did:key:`
  api.loaders.push(_didKeyLoader);

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
const splitRegex = /[;|\/|\?|#]/;
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
  throw new Error('NotFoundError');
};

api.loaders = [api.documentCache];

function _createV1Loader({hostname, mode}) {
  const v1 = new (require('did-veres-one')).VeresOne({hostname, mode});
  return async url => {
    if(!url.startsWith('did:v1:')) {
      throw new Error('NotFoundError');
    }
    let result;
    try {
      result = await v1.get({did: url});
    } catch(e) {
      throw new Error('NotFoundError');
    }
    return {
      contextUrl: null,
      // toJSON() returns just the `doc` portion of the instance
      document: result.toJSON(),
      documentUrl: url
    };
  };
}

async function _didKeyLoader(url) {
  if(!url.startsWith('did:key:')) {
    throw new Error('NotFoundError');
  }
  let result;
  try {
    result = await didKeyDriver.get({url});
  } catch(e) {
    throw new Error('NotFoundError');
  }
  return {
    contextUrl: null,
    document: result,
    documentUrl: url
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

  const context = [
    constants.DID_CONTEXT_URL,
    constants.VERES_ONE_CONTEXT_V1_URL
  ];
  // frame target
  const framed = await jsonld.frame(
    filtered, {'@context': context, id: target}, {embed: '@always'});
  return Object.assign({'@context': context}, framed['@graph'][0]);
}

async function _webLoader(url) {
  if(!url.startsWith('http')) {
    throw new Error('NotFoundError');
  }
  let result;
  try {
    const {httpsAgent} = brHttpsAgent;
    const instance = axios.create({httpsAgent});
    result = await instance(url);
  } catch(e) {
    throw new Error('NotFoundError');
  }

  return {
    contextUrl: null,
    document: result.data,
    documentUrl: url
  };
}
