/*
 * Copyright (c) 2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {addDocumentRoutes, documentStores} from '@bedrock/service-agent';
import {
  createMdlCAStoreBody, updateMdlCAStoreBody
} from '../schemas/bedrock-vc-verifier.js';
import {DataItem, Verifier} from '@auth0/mdl';

const {util: {BedrockError}} = bedrock;

const VC_CONTEXT_2 = 'https://www.w3.org/ns/credentials/v2';

const MDL_NAMESPACE = 'org.iso.18013.5.1';
const MDOC_TYPE_MDL = `${MDL_NAMESPACE}.mDL`;
const MDL_CA_STORE_TYPE = 'MdlCAStore';

const serviceType = 'vc-verifier';

export async function addCAStoreRoutes({app, service} = {}) {
  const cfg = bedrock.config['vc-verifier'];
  const basePath = `${cfg.routes.mdl}/ca-stores`;
  addDocumentRoutes({
    app, service,
    type: MDL_CA_STORE_TYPE,
    typeName: 'mDL Certificate Authority Store',
    contentProperty: 'trustedCertificates',
    basePath,
    pathParam: 'caStoreId',
    createBodySchema: createMdlCAStoreBody(),
    updateBodySchema: updateMdlCAStoreBody()
  });
}

export async function verifyEnvelopedPresentation({
  config, contents, format, challenge, domain, options
} = {}) {
  // base64 encoding must NOT be used; vp token is `base64url` encoded
  if(format.parameters.has('base64')) {
    throw new BedrockError(
      `Unknown envelope format "${format.mediaType}".`, {
        name: 'DataError',
        details: {
          httpStatusCode: 400,
          public: true
        },
      });
  }

  // decoded `contents` is the mDL device response
  const deviceResponse = Buffer.from(contents, 'base64url');

  // session transcription must be provided modulo:
  // `domain` which is used as the `responseUri`
  // `challenge` which is used as the `verifierGeneratedNonce`
  const sessionTranscript = {
    ...options.mdl?.sessionTranscript,
    responseUri: domain,
    verifierGeneratedNonce: challenge
  };

  // fetch CA store(s)
  const {documentStore} = await documentStores.get({config, serviceType});
  const caStoreIds = config.verifyOptions?.mdl?.caStores;
  const caStore = new Set();
  // FIXME: implement parallel lookup w/limits, for now one CA store is
  // expected and multiples will be slow, discouraging too many from being used
  for(const url of caStoreIds) {
    const doc = await _getCAStoreDocument({documentStore, url});
    doc.content.trustedCertificates.forEach(caStore.add, caStore);
  }

  return verifyPresentation({
    deviceResponse, sessionTranscript, trustedCertificates: [...caStore]
  });
}

export async function verifyPresentation({
  deviceResponse, sessionTranscript, trustedCertificates
} = {}) {
  try {
    const verifier = new Verifier(trustedCertificates);
    const encodedSessionTranscript = _encodeSessionTranscript(
      sessionTranscript);

    // uncomment to debug
    /*
    const diagnostic = await verifier.getDiagnosticInformation(
      deviceResponse, {encodedSessionTranscript});
    console.debug('Diagnostic information:', diagnostic);
    */

    // verify device response and get selectively disclosed mdoc result
    const mdoc = await verifier.verify(deviceResponse, {
      encodedSessionTranscript
    });

    // ensure `mdoc` has one document and its `type` is `MDOC_TYPE_MDL`
    if(!(mdoc.documents?.length === 1 &&
      mdoc.documents[0].docType === MDOC_TYPE_MDL)) {
      throw new BedrockError(
        `Unknown mdoc document type "${mdoc.documents[0].docType}"; ` +
        `expecting "${MDOC_TYPE_MDL}".`, {
          name: 'NotSupportedError',
          details: {
            httpStatusCode: 400,
            public: true
          }
        });
    }

    // express CBOR-encoded mdoc as an enveloped VC in a VP
    const cborMdoc = mdoc.encode();
    const b64Mdl = Buffer.from(cborMdoc).toString('base64');
    const presentation = {
      '@context': [VC_CONTEXT_2],
      type: 'VerifiablePresentation',
      verifiableCredential: {
        id: `data:application/mdl;base64,${b64Mdl}`,
        type: 'EnvelopedVerifiableCredential'
      }
    };
    return {verified: true, presentation};
  } catch(err) {
    // capture `err` mesasge, name, and code
    const cause = new Error(err.message);
    cause.name = err.name;
    cause.code = err.code;
    const error = new Error('Verification error.');
    error.name = 'VerificationError';
    error.errors = [cause];
    return {verified: false, error};
  }
}

function _encodeSessionTranscript(sessionTranscript) {
  const {
    mdocGeneratedNonce,
    clientId,
    responseUri,
    verifierGeneratedNonce
  } = sessionTranscript;
  const encoded = DataItem.fromData([
    // deviceEngagementBytes
    null,
    // eReaderKeyBytes
    null,
    [mdocGeneratedNonce, clientId, responseUri, verifierGeneratedNonce],
  ]);
  return DataItem.fromData(encoded).buffer;
}

async function _getCAStoreDocument({documentStore, url}) {
  const doc = await documentStore.get({id: url});
  if(doc.meta.type !== MDL_CA_STORE_TYPE) {
    // wrong meta type; treat as not found error
    throw new BedrockError(`Document "${url}" not found.`, {
      name: 'NotFoundError',
      details: {
        url,
        httpStatusCode: 404,
        public: true
      }
    });
  }
  return doc;
}
