/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
import bedrock from 'bedrock';
import {didIo} from 'bedrock-did-io';
import {
  JsonLdDocumentLoader,
  httpClientHandler
} from 'bedrock-jsonld-document-loader';
import {createContextDocumentLoader} from 'bedrock-service-context-storage';

const serviceType = 'vc-verifier';
let webLoader;

bedrock.on('bedrock-init', () => {
  // build web loader if configuration calls for it
  const {config: {'vc-verifier': cfg}} = bedrock;
  if(cfg.documentLoader.http || cfg.documentLoader.https) {
    const jdl = new JsonLdDocumentLoader();

    const {'vc-verifier': cfg} = config;
    if(cfg.documentLoader.http) {
      jsonLdDocumentLoader.setProtocolHandler({
        protocol: 'http', handler: httpClientHandler});
    }
    if(cfg.documentLoader.https) {
      jsonLdDocumentLoader.setProtocolHandler({
        protocol: 'https', handler: httpClientHandler});
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
 *
 * @returns {Promise<Function>} The document loader.
 */
export async function createDocumentLoader({config} = {}) {
  const contextDocumentLoader = await createContextDocumentLoader(
    {config, serviceType});

  return async function documentLoader(url) {
    // resolve all DID URLs through did-io
    if(url.startsWith('did:')) {
      return didIo.get({url});
    }

    // try to resolve URL through context doc loader
    try {
      return await contextDocumentLoader(url);
    } catch(e) {
      // use web loader if configured
      if(url.startsWith('http') && e.name === 'NotFoundError' && webLoader) {
        return webLoader(url);
      }
      throw e;
    }
  }
}
