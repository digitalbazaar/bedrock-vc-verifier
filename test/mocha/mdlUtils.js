/*
 * Copyright (c) 2025-2026 Digital Bazaar, Inc.
 */
import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey';
import {
  CoseKey, DeviceKey, DeviceRequest, DocRequest, Holder, ItemsRequest,
  Issuer as MDocIssuer, SessionTranscript, SignatureAlgorithm
} from '@owf/mdoc';
import {DeviceResponse, Document, MDoc, /*parse,*/ Verifier} from '@auth0/mdl';
import {oid4vp} from '@digitalbazaar/oid4-client';
import {X509Certificate} from 'node:crypto';

const VC_CONTEXT_2 = 'https://www.w3.org/ns/credentials/v2';

const MDOC_TYPE_MDL = 'org.iso.18013.5.1';
const MDL_NAMESPACE = `${MDOC_TYPE_MDL}.mDL`;

const {encodeSessionTranscript} = oid4vp.mdl;

export async function createDerivedCredential({
  presentationDefinition,
  mdoc, handover, devicePrivateJwk
} = {}) {
  const {id} = await createPresentation({
    presentationDefinition,
    mdoc,
    handover,
    devicePrivateJwk
  });
  return {
    '@context': VC_CONTEXT_2,
    id,
    type: 'EnvelopedVerifiableCredential'
  };
}

export async function createDerivedCredentialWithOwf({
  presentationDefinition,
  issuerSigned, handover, devicePrivateJwk
} = {}) {
  const {id} = await createPresentationWithOwf({
    presentationDefinition,
    issuerSigned,
    handover,
    devicePrivateJwk
  });
  return {
    '@context': VC_CONTEXT_2,
    id,
    type: 'EnvelopedVerifiableCredential'
  };
}

export async function createPresentation({
  presentationDefinition,
  mdoc, handover, devicePrivateJwk
} = {}) {
  // pick input_descriptor w/ID: `MDL_NAMESPACE` as needed by auth0 lib
  presentationDefinition = {
    ...presentationDefinition,
    input_descriptors: presentationDefinition.input_descriptors.filter(
      e => e.id === MDL_NAMESPACE)
  };
  const encodedSessionTranscript = await encodeSessionTranscript({handover});
  const deviceResponse = await DeviceResponse.from(mdoc)
    .usingPresentationDefinition(presentationDefinition)
    .usingSessionTranscriptBytes(encodedSessionTranscript)
    .authenticateWithSignature(devicePrivateJwk, 'ES256')
    .sign();
  //console.log('Device response', deviceResponse);

  // FIXME: define a base64url-encoded mdl vp token mime type?
  const encodedDeviceResponse = deviceResponse.encode();
  const vpToken = Buffer.from(encodedDeviceResponse).toString('base64url');
  // console.log('device side: device response cbor', encodedDeviceResponse);
  // console.log(vpToken, 'vpToken');

  return {
    '@context': [VC_CONTEXT_2],
    id: `data:application/mdl-vp-token,${vpToken}`,
    type: 'EnvelopedVerifiablePresentation'
  };
}

export async function createPresentationWithOwf({
  /*presentationDefinition,*/
  issuerSigned, handover, devicePrivateJwk
} = {}) {
  // FIXME: parse or not do not use presentation exchange
  /*
  presentationDefinition = {
    ...presentationDefinition,
    input_descriptors: presentationDefinition.input_descriptors.filter(
      e => e.id === MDL_NAMESPACE)
  };*/

  // prepare device request
  const deviceRequest = DeviceRequest.create({
    docRequests: [DocRequest.create({
      itemsRequest: ItemsRequest.create({
        docType: MDOC_TYPE_MDL,
        namespaces: {
          [MDL_NAMESPACE]: {
            // FIXME: parse from presentation definition/other query param
            age_over_21: true
          }
        }
      })
    })]
  });

  // create transcript
  const encodedSessionTranscript = await encodeSessionTranscript({handover});
  const sessionTranscript = SessionTranscript.decode(encodedSessionTranscript);

  // create device response
  const deviceKeyPair = await EcdsaMultikey.fromJwk({
    jwk: devicePrivateJwk, secretKey: true
  });
  const signer = deviceKeyPair.signer();
  const mdocContext = _createMdocContext({signer});
  const deviceResponse = await Holder.createDeviceResponseForDeviceRequest({
    deviceRequest,
    issuerSigned: [issuerSigned],
    sessionTranscript,
    signature: {signingKey: CoseKey.fromJwk(devicePrivateJwk)}
  }, mdocContext);

  //console.log('Device response', deviceResponse);

  // FIXME: define a base64url-encoded mdl vp token mime type?
  const vpToken = deviceResponse.encodedForOid4Vp;
  // console.log(vpToken, 'vpToken');

  return {
    '@context': [VC_CONTEXT_2],
    id: `data:application/mdl-vp-token,${vpToken}`,
    type: 'EnvelopedVerifiablePresentation'
  };
}

export async function generateDeviceKeyPair() {
  // FIXME: generate new key pair each time
  const publicJwk = {
    alg: 'ES256',
    kty: 'EC',
    x: 'QiUaYhZak1NubJEphQWmafykivrD80D2IpwqkkCU0oQ',
    y: 'sdNfR3813hzaUqF3-kWWOjI1xtSEqb93-graWFK-bA4',
    crv: 'P-256'
  };
  const privateJwk = {
    ...publicJwk,
    d: 'V729tbSdAGAL34Gqt2lGFM0Y9qrxILDUVheFduEkgFU'
  };
  return {publicJwk, privateJwk};
}

export async function issue({
  issuerPrivateJwk, issuerCertificate,
  devicePublicJwk
} = {}) {
  // FIXME: doc type and namespace are reversed w/`@auth0/mdl` lib
  const document = await new Document(MDL_NAMESPACE)
    .addIssuerNameSpace(MDOC_TYPE_MDL, {
      family_name: 'FamilyName',
      given_name: 'GivenName',
      birth_date: '1990-01-01',
      age_over_21: true
    })
    .useDigestAlgorithm('SHA-256')
    .addValidityInfo({signed: new Date()})
    .addDeviceKeyInfo({deviceKey: devicePublicJwk})
    .sign({
      issuerPrivateKey: issuerPrivateJwk,
      issuerCertificate,
      kid: issuerPrivateJwk.kid,
      alg: 'ES256'
    });
  return new MDoc([document]);
}

export async function issueWithOwf({
  issuerPrivateJwk, issuerCertificate,
  devicePublicJwk
} = {}) {
  const issuerKeyPair = await EcdsaMultikey.fromJwk({
    jwk: issuerPrivateJwk, secretKey: true
  });
  const signer = issuerKeyPair.signer();

  // set validity period to certificate period if given
  const validityInfo = {};
  const certificate = new X509Certificate(issuerCertificate);
  validityInfo.validFrom = certificate.validFromDate;
  validityInfo.validUntil = certificate.validToDate;

  // construct and sign mDL
  const mdocContext = _createMdocContext({signer});
  const mdocIssuer = new MDocIssuer(MDOC_TYPE_MDL, mdocContext);
  mdocIssuer.addIssuerNamespace(MDL_NAMESPACE, {
    family_name: 'FamilyName',
    given_name: 'GivenName',
    birth_date: '1990-01-01',
    age_over_21: true
  });
  const issuerSigned = await mdocIssuer.sign({
    // `signingKey` intentionally includes no key material, only type
    // information; `signer` API is used to provide signature via `mdocContext`
    signingKey: CoseKey.fromJwk({
      kid: signer.id,
      kty: 'EC',
      crv: 'P-256'
    }),
    certificates: [certificate.raw],
    algorithm: SignatureAlgorithm.ES256,
    digestAlgorithm: 'SHA-256',
    deviceKeyInfo: {deviceKey: DeviceKey.fromJwk(devicePublicJwk)},
    validityInfo: {
      signed: new Date(),
      ...validityInfo
    }
  });

  return issuerSigned;
}

export async function verifyPresentation({
  deviceResponse, handover, trustedCertificates
} = {}) {
  // uncomment to debug:
  /*const parsed = parse(deviceResponse);
  const issuerCertificate = parsed.documents?.[0]
    .issuerSigned?.issuerAuth?.certificate;
  console.log('issuer certificate', issuerCertificate);*/

  // produced on the verifier side
  const encodedSessionTranscript = await encodeSessionTranscript({handover});

  const verifier = new Verifier(trustedCertificates);
  // console.log('Getting diagnostic information...');
  // const diagnostic = await verifier.getDiagnosticInformation(
  //   deviceResponse, {encodedSessionTranscript});
  // console.debug('Diagnostic information:', diagnostic);

  try {
    const mdoc = await verifier.verify(deviceResponse, {
      encodedSessionTranscript
    });
    // console.log('Verification succeeded!');
    // console.log('Verified mdoc', mdoc);
    // console.log('DeviceSignedDocument', mdoc.documents[0]);

    // express cbor-encoded mdoc as an enveloped VC in a VP
    const encodedMdoc = mdoc.encode();
    const b64Mdl = Buffer.from(encodedMdoc).toString('base64');
    return {
      '@context': [VC_CONTEXT_2],
      type: 'VerifiablePresentation',
      verifiableCredential: {
        id: `data:application/mdl;base64,${b64Mdl}`,
        type: 'EnvelopedVerifiableCredential'
      }
    };
  } catch/*(err)*/ {
    //console.error('Verification failed:', err);
    return;
  }
}

// constructs an "mdoc context" based on the given `signer` and that implements
// the other necessary `digest` and `random` functions
function _createMdocContext({signer}) {
  const crypto = globalThis.crypto;
  return {
    crypto: {
      async digest({digestAlgorithm, bytes}) {
        const digest = await crypto.subtle.digest(digestAlgorithm, bytes);
        return new Uint8Array(digest);
      },
      random(length) {
        return crypto.getRandomValues(new Uint8Array(length));
      }
    },
    cose: {
      sign1: {
        async sign(input) {
          const {toBeSigned} = input;
          return signer.sign({data: toBeSigned});
        }
      }
    }
  };
}
