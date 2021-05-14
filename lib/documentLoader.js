/*!
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {agent} = require('bedrock-https-agent');
const bedrock = require('bedrock');
const credContext = require('credentials-context');
const {didIo} = require('bedrock-did-io');
const didVeresOne = require('did-veres-one');
const {
  documentLoader: bedrockLoader
} = require('bedrock-jsonld-document-loader');
const {httpClient} = require('@digitalbazaar/http-client');
const jsonld = require('jsonld');
const {securityLoader} = require('@digitalbazaar/security-document-loader');
const veresOneCtx = require('veres-one-context');
const webkmsCtx = require('webkms-context');
const zcapCtx = require('zcap-context');

const {config} = bedrock;
const {config: {constants}} = bedrock;
const {
  contexts: credentialsContext,
  constants: {
    CREDENTIALS_CONTEXT_V1_URL
  }
} = credContext;
const options = {
  hostname: config['vc-verifier'].ledgerHostname,
  mode: 'test'
};

const loader = securityLoader();
loader.addStatic(
  veresOneCtx.constants.VERES_ONE_CONTEXT_V1_URL,
  veresOneCtx.contexts.get(veresOneCtx.constants.VERES_ONE_CONTEXT_V1_URL));
loader.addStatic(CREDENTIALS_CONTEXT_V1_URL,
  credentialsContext.get(CREDENTIALS_CONTEXT_V1_URL));
loader.addStatic(zcapCtx.CONTEXT_URL, zcapCtx.CONTEXT);
loader.addStatic(webkmsCtx.CONTEXT_URL, webkmsCtx.CONTEXT);

loader.protocolHandlers.get('did').use(didVeresOne.driver(options));

const api = {};

api.loader = loader;

module.exports = api;

bedrock.events.on('bedrock.start', () => {
  const {'vc-verifier': cfg} = config;
  api.loaders.push(bedrockLoader);
  // FIXME: use computed config API instead of eventing this
  api.loaders.push(_createDidLoader({
    hostname: cfg.ledgerHostname,
    mode: cfg.mode,
  }));

  // if enabled, add loader for remote documents
  if(cfg.documentLoader.mode === 'web') {
    api.loaders.push(_webLoader);
  }
});

api.documents = new Map();

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

function _createDidLoader({hostname, mode = 'test'}) {
  didIo.use(didVeresOne.driver({hostname, mode}));

  return async url => {
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
    result = await httpClient.get(url, {agent});
  } catch(e) {
    throw new Error('NotFoundError');
  }

  return {
    contextUrl: null,
    document: result.data,
    documentUrl: url
  };
}
