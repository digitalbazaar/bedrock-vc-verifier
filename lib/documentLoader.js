/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const {config, jsonld} = bedrock;
const {config: {constants}} = bedrock;
const v1 = new (require('did-veres-one')).VeresOne({
  hostname: '127.0.0.1:8888',
  mode: 'dev'
});

const {'vc-verifier': cfg} = config;

const api = {};
module.exports = api;

bedrock.events.on('bedrock.start', () => {
  api.loaders.push(jsonld.documentLoader);
  // FIXME: use computed config API instead of eventing this
  if(cfg.ledgerHostname && config.mode) {
    // push a v1 ledger loader
    api.loaders.push(_createV1Loader({
      hostname: cfg.ledgerHostname,
      mode: cfg.mode,
    }));
  }
});

api.documents = new Map();

api.documentLoader = async (url) => {
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
  throw new Error('NotFoundError');
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
      document: result.record,
      documentUrl: url
    };
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
    constants.VERES_ONE_CONTEXT_URL
  ];
  // frame target
  const framed = await jsonld.frame(
    filtered, {'@context': context, id: target}, {embed: '@always'});

  return Object.assign({'@context': context}, framed['@graph'][0]);
}
