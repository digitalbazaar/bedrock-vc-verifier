/*
 * Copyright (c) 2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {
  createMdlCAStoreBody, updateMdlCAStoreBody
} from '../schemas/bedrock-vc-verifier.js';
import {
  DataItem, DeviceResponse, Document, MDoc, Verifier
} from '@auth0/mdl';
import {addDocumentRoutes} from '@bedrock/service-agent';

const {util: {BedrockError}} = bedrock;

const VC_CONTEXT_2 = 'https://www.w3.org/ns/credentials/v2';

const MDL_NAMESPACE = 'org.iso.18013.5.1';
const MDOC_TYPE_MDL = `${MDL_NAMESPACE}.mDL`;

// FIXME: remove; use definition from exchange
const PRESENTATION_DEFINITION_1 = {
  id: 'mdl-test-age-over-21',
  input_descriptors: [
    {
      id: MDOC_TYPE_MDL,
      format: {
        mso_mdoc: {
          alg: ['ES256']
        }
      },
      constraints: {
        limit_disclosure: 'required',
        fields: [
          {
            // eslint-disable-next-line quotes
            path: ["$['org.iso.18013.5.1']['age_over_21']"],
            intent_to_retain: false
          }
        ]
      }
    }
  ]
};

export async function addCAStoreRoutes({app, service} = {}) {
  const cfg = bedrock.config['vc-verifier'];
  const basePath = `${cfg.routes.mdl}/ca-stores`;
  addDocumentRoutes({
    app, service,
    type: 'MdlCAStore',
    typeName: 'mDL Certificate Authority Store',
    contentProperty: 'trustedCertificates',
    basePath,
    pathParam: 'caStoreId',
    createBodySchema: createMdlCAStoreBody(),
    updateBodySchema: updateMdlCAStoreBody()
  });
}

export async function verifyEnvelopedPresentation({
  config, contents, format, challenge, checks, options
} = {}) {
  // FIXME: note: OID4VP format (different from `format` here) should say
  // `mso_mdoc` to trigger getting to this point

  // handle base64 encoding
  if(!format.parameters.has('base64')) {
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
  const deviceResponse = new Uint8Array(Buffer.from(contents, 'base64'));
  console.log('device response', deviceResponse);

  // FIXME:
  const sessionTranscript = {
    // mdocGeneratedNonce: randomUUID(),
    // clientId: randomUUID(),
    // // FIXME: replace with OID4VP exchange URL
    // responseUri: 'https://test.example',
    // `challenge` is the "verifier generated nonce"
    verifierGeneratedNonce: challenge
  };

  // FIXME: look up trusted certificate based on mdoc issuer

  return verifyPresentation({
    deviceResponse, sessionTranscript, trustedCertificates
  });
}

export async function verifyPresentation({
  deviceResponse, sessionTranscript, trustedCertificates
} = {}) {
  try {
    const verifier = new Verifier(trustedCertificates);
    const encodedSessionTranscript = _encodeSessionTranscript(
      sessionTranscript);

    // const diagnostic = await verifier.getDiagnosticInformation(
    //   deviceResponse, {encodedSessionTranscript});
    // console.debug('Diagnostic information:', diagnostic);

    // verify device response and get selectively disclosed mdoc result
    const mdoc = await verifier.verify(deviceResponse, {
      encodedSessionTranscript
    });

    // express CBOR-encoded mdoc as an enveloped VC in a VP
    const cborMdoc = mdoc.encode();
    const b64Mdl = Buffer.from(cborMdoc).toString('base64');
    const presentation = {
      '@context': [VC_CONTEXT_2],
      type: ['VerifiablePresentation'],
      verifiableCredential: {
        id: `data:application/mdl;base64,${b64Mdl}`,
        type: ['EnvelopedVerifiableCredential']
      }
    };
    return {verified: true, presentation};
  } catch(err) {
    console.error('Verification failed:', err);
    return {verified: false, error: err};
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
