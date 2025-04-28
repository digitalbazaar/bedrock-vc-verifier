/*!
 * Copyright (c) 2019-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {
  documentLoader as brDocLoader,
  httpClientHandler,
  JsonLdDocumentLoader
} from '@bedrock/jsonld-document-loader';
import {createContextDocumentLoader} from '@bedrock/service-context-store';
import {didIo} from '@bedrock/did-io';
import '@bedrock/credentials-context';
import '@bedrock/data-integrity-context';
import '@bedrock/did-context';
import '@bedrock/did-io';
import '@bedrock/multikey-context';
import '@bedrock/security-context';
import '@bedrock/vc-barcodes-context';
import '@bedrock/vc-revocation-list-context';
import '@bedrock/vc-status-list-context';
import '@bedrock/veres-one-context';

const serviceType = 'vc-verifier';
let webLoader;

bedrock.events.on('bedrock.init', () => {
  // build web loader if configuration calls for it
  const cfg = bedrock.config['vc-verifier'];
  if(cfg.documentLoader.http || cfg.documentLoader.https) {
    const jdl = new JsonLdDocumentLoader();

    if(cfg.documentLoader.http) {
      jdl.setProtocolHandler({protocol: 'http', handler: httpClientHandler});
    }
    if(cfg.documentLoader.https) {
      jdl.setProtocolHandler({protocol: 'https', handler: httpClientHandler});
    }

    webLoader = jdl.build();
  }
});

/**
 * Creates a document loader for the verifier instance identified via the
 * given config.
 *
 * @param {object} options - The options to use.
 * @param {object} options.config - The verifier instance config.
 * @param {Set} [options.remoteUrlAllowList] - Remote URLs that are
 *   specifically allowed to be loaded (used for status list checks).
 *
 * @returns {Promise<Function>} The document loader.
 */
export async function createDocumentLoader({config, remoteUrlAllowList} = {}) {
  const contextDocumentLoader = await createContextDocumentLoader(
    {config, serviceType});

  return async function documentLoader(url) {
    // handle DID URLs...
    if(url.startsWith('did:')) {
      let document;
      if(config.verifyOptions?.didResolver) {
        // resolve via configured DID resolver
        const {verifyOptions: {didResolver}} = config;
        document = await _resolve({didResolver, didUrl: url});
      } else {
        // resolve via did-io
        document = await didIo.get({url});
      }
      return {
        contextUrl: null,
        documentUrl: url,
        document
      };
    }

    try {
      // try to resolve URL through built-in doc loader
      return await brDocLoader(url);
    } catch(e) {
      // FIXME: improve to check for `NotFoundError` once `e.name`
      // supports it
    }

    try {
      // try to resolve URL through context doc loader
      return await contextDocumentLoader(url);
    } catch(e) {
      // use web loader if configured and instance config allows it (or it is
      // allowed by an allow list) and the url starts with `http` (and the core
      // config allows it, i.e., `webLoader` exists)
      const allowRemoteContexts = !config.verifyOptions?.documentLoader ||
        config.verifyOptions.documentLoader.allowRemoteContexts ||
        remoteUrlAllowList?.has(url);
      if(allowRemoteContexts &&
        url.startsWith('http') && e.name === 'NotFoundError' && webLoader) {
        return webLoader(url);
      }
      throw e;
    }
  };
}

async function _resolve({didResolver, didUrl}) {
  // split on `?` query or `#` fragment
  const [did] = didUrl.split(/(?=[\?#])/);

  // fetch DID document using DID resolver, assume DID param is prepended
  const url = didResolver.url.endsWith('/') ?
    `${didResolver.url}${encodeURIComponent(did)}` :
    `${didResolver.url}/${encodeURIComponent(did)}`;
  const data = await httpClientHandler.get({url});

  if(data?.didDocument?.id !== did) {
    throw new Error(`DID document for DID "${did}" not found.`);
  }

  // FIXME: perform DID document validation
  // FIXME: handle URL query param / services
  const {didDocument} = data;

  // if a fragment was found use the fragment to dereference a subnode
  // in the did doc
  const [, fragment] = didUrl.split('#');
  if(fragment) {
    const id = `${didDocument.id}#${fragment}`;
    return _getNode({didDocument, id});
  }
  // resolve the full DID Document
  return didDocument;
}

function _getNode({didDocument, id}) {
  // do verification method search first
  let match = didDocument?.verificationMethod?.find(vm => vm?.id === id);
  if(!match) {
    // check other top-level nodes
    for(const [key, value] of Object.entries(didDocument)) {
      if(key === '@context' || key === 'verificationMethod') {
        continue;
      }
      if(Array.isArray(value)) {
        match = value.find(e => e?.id === id);
      } else if(value?.id === id) {
        match = value;
      }
      if(match) {
        break;
      }
    }
  }

  if(!match) {
    throw new Error(`DID document entity with id "${id}" not found.`);
  }

  return {
    '@context': structuredClone(didDocument['@context']),
    ...structuredClone(match)
  };
}
