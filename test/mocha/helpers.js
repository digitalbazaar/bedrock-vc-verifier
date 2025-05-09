/*
 * Copyright (c) 2019-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {importJWK, SignJWT} from 'jose';
import {KeystoreAgent, KmsClient} from '@digitalbazaar/webkms-client';
import {didIo} from '@bedrock/did-io';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {EdvClient} from '@digitalbazaar/edv-client';
import {getAppIdentity} from '@bedrock/app-identity';
import {httpClient} from '@digitalbazaar/http-client';
import {httpsAgent} from '@bedrock/https-agent';
import {ZcapClient} from '@digitalbazaar/ezcap';

import {mockData} from './mock.data.js';

const edvBaseUrl = `${mockData.baseUrl}/edvs`;
const kmsBaseUrl = `${mockData.baseUrl}/kms`;

const SUPPORTED_ECDSA_ALGORITHMS = new Map([
  ['zDna', 'P-256'],
  ['z82L', 'P-384']
]);

const FIVE_MINUTES = 1000 * 60 * 5;

const TEXT_ENCODER = new TextEncoder();
const ENCODED_PERIOD = TEXT_ENCODER.encode('.');

const VC_CONTEXT_2 = 'https://www.w3.org/ns/credentials/v2';

export async function createMeter({capabilityAgent, serviceType} = {}) {
  // create signer using the application's capability invocation key
  const {keys: {capabilityInvocationKey}} = getAppIdentity();

  const zcapClient = new ZcapClient({
    agent: httpsAgent,
    invocationSigner: capabilityInvocationKey.signer(),
    SuiteClass: Ed25519Signature2020
  });

  // create a meter
  const meterService = `${bedrock.config.server.baseUri}/meters`;
  let meter = {
    controller: capabilityAgent.id,
    product: {
      // mock ID for service type
      id: mockData.productIdMap.get(serviceType)
    }
  };
  ({data: {meter}} = await zcapClient.write({url: meterService, json: meter}));

  // return full meter ID
  const {id} = meter;
  return {id: `${meterService}/${id}`};
}

export async function createConfig({
  capabilityAgent, ipAllowList, meterId, zcaps, configOptions, oauth2 = false
} = {}) {
  if(!meterId) {
    // create a meter for the keystore
    ({id: meterId} = await createMeter({
      capabilityAgent, serviceType: 'vc-verifier'
    }));
  }

  // create service object
  const config = {
    sequence: 0,
    controller: capabilityAgent.id,
    meterId,
    ...configOptions
  };
  if(ipAllowList) {
    config.ipAllowList = ipAllowList;
  }
  if(zcaps) {
    config.zcaps = zcaps;
  }
  if(oauth2) {
    const {baseUri} = bedrock.config.server;
    config.authorization = {
      oauth2: {
        issuerConfigUrl: `${baseUri}${mockData.oauth2IssuerConfigRoute}`
      }
    };
  }

  const zcapClient = createZcapClient({capabilityAgent});
  const url = `${mockData.baseUrl}/verifiers`;
  const response = await zcapClient.write({url, json: config});
  return response.data;
}

export async function getConfig({id, capabilityAgent, accessToken}) {
  if(accessToken) {
    // do OAuth2
    const {data} = await httpClient.get(id, {
      agent: httpsAgent,
      headers: {authorization: `Bearer ${accessToken}`}
    });
    return data;
  }
  // do zcap
  const zcapClient = createZcapClient({capabilityAgent});
  const {data} = await zcapClient.read({url: id});
  return data;
}

export async function getOAuth2AccessToken({
  configId, action, target, exp, iss, nbf, typ = 'at+jwt'
}) {
  const scope = `${action}:${target}`;
  const builder = new SignJWT({scope})
    .setProtectedHeader({alg: 'EdDSA', typ})
    .setIssuer(iss ?? mockData.oauth2Config.issuer)
    .setAudience(configId);
  if(exp !== undefined) {
    builder.setExpirationTime(exp);
  } else {
    // default to 5 minute expiration time
    builder.setExpirationTime('5m');
  }
  if(nbf !== undefined) {
    builder.setNotBefore(nbf);
  }
  const key = await importJWK({...mockData.ed25519KeyPair, alg: 'EdDSA'});
  return builder.sign(key);
}

export async function createChallenge({
  capabilityAgent, capability, verifierId, accessToken
}) {
  if(accessToken) {
    // do OAuth2
    const url = `${verifierId}/challenges`;
    return httpClient.post(url, {
      agent: httpsAgent,
      headers: {authorization: `Bearer ${accessToken}`},
      json: {}
    });
  }
  // do zcap
  const zcapClient = createZcapClient({capabilityAgent});
  return zcapClient.write({
    url: `${verifierId}/challenges`,
    capability: capability ||
      `urn:zcap:root:${encodeURIComponent(verifierId)}`,
    json: {}
  });
}

export async function createEdv({
  capabilityAgent, keystoreAgent, keyAgreementKey, hmac, meterId
}) {
  if(!meterId) {
    // create a meter for the keystore
    ({id: meterId} = await createMeter({
      capabilityAgent, serviceType: 'edv'
    }));
  }

  if(!(keyAgreementKey && hmac) && keystoreAgent) {
    // create KAK and HMAC keys for edv config
    ([keyAgreementKey, hmac] = await Promise.all([
      keystoreAgent.generateKey({type: 'keyAgreement'}),
      keystoreAgent.generateKey({type: 'hmac'})
    ]));
  }

  // create edv
  const newEdvConfig = {
    sequence: 0,
    controller: capabilityAgent.id,
    keyAgreementKey: {id: keyAgreementKey.id, type: keyAgreementKey.type},
    hmac: {id: hmac.id, type: hmac.type},
    meterId
  };

  const edvConfig = await EdvClient.createEdv({
    config: newEdvConfig,
    httpsAgent,
    invocationSigner: capabilityAgent.getSigner(),
    url: edvBaseUrl
  });

  const edvClient = new EdvClient({
    id: edvConfig.id,
    keyResolver,
    keyAgreementKey,
    hmac,
    httpsAgent
  });

  return {edvClient, edvConfig, hmac, keyAgreementKey};
}

export async function createKeystore({
  capabilityAgent, ipAllowList, meterId,
  kmsModule = 'ssm-v1'
}) {
  if(!meterId) {
    // create a meter for the keystore
    ({id: meterId} = await createMeter(
      {capabilityAgent, serviceType: 'webkms'}));
  }

  // create keystore
  const config = {
    sequence: 0,
    controller: capabilityAgent.id,
    meterId,
    kmsModule
  };
  if(ipAllowList) {
    config.ipAllowList = ipAllowList;
  }

  return KmsClient.createKeystore({
    url: `${kmsBaseUrl}/keystores`,
    config,
    invocationSigner: capabilityAgent.getSigner(),
    httpsAgent
  });
}

export async function createKeystoreAgent({capabilityAgent, ipAllowList}) {
  let err;
  let keystore;
  try {
    keystore = await createKeystore({capabilityAgent, ipAllowList});
  } catch(e) {
    err = e;
  }
  assertNoError(err);

  // create kmsClient only required because we need to use httpsAgent
  // that accepts self-signed certs used in test suite
  const kmsClient = new KmsClient({httpsAgent});
  const keystoreAgent = new KeystoreAgent({
    capabilityAgent,
    keystoreId: keystore.id,
    kmsClient
  });

  return keystoreAgent;
}

export function createZcapClient({
  capabilityAgent, delegationSigner, invocationSigner
}) {
  const signer = capabilityAgent && capabilityAgent.getSigner();
  return new ZcapClient({
    agent: httpsAgent,
    invocationSigner: invocationSigner || signer,
    delegationSigner: delegationSigner || signer,
    SuiteClass: Ed25519Signature2020
  });
}

export async function delegate({
  capability, controller, invocationTarget, expires, allowedActions,
  delegator
}) {
  const zcapClient = createZcapClient({capabilityAgent: delegator});
  expires = expires || (capability && capability.expires) ||
    new Date(Date.now() + FIVE_MINUTES).toISOString().slice(0, -5) + 'Z';
  return zcapClient.delegate({
    capability, controller, expires, invocationTarget, allowedActions
  });
}

export async function revokeDelegatedCapability({
  serviceObjectId, capabilityToRevoke, invocationSigner
}) {
  const url = `${serviceObjectId}/zcaps/revocations/` +
    encodeURIComponent(capabilityToRevoke.id);
  const zcapClient = createZcapClient({invocationSigner});
  return zcapClient.write({url, json: capabilityToRevoke});
}

async function keyResolver({id}) {
  // support DID-based keys only
  if(id.startsWith('did:')) {
    return didIo.get({url: id});
  }
  // support HTTP-based keys; currently a requirement for WebKMS
  const {data} = await httpClient.get(id, {agent: httpsAgent});
  return data;
}

export function getEcdsaAlgorithms({credential, presentation} = {}) {
  let vc = presentation ? presentation.verifiableCredential : credential;
  vc = Array.isArray(vc) ? vc : [vc];
  const ecdsaAlgorithms = [];
  vc.forEach(credential => {
    const proofs = Array.isArray(credential.proof) ? credential.proof :
      [credential.proof];
    for(const proof of proofs) {
      if(proof.cryptosuite === 'ecdsa-2019' ||
        proof.cryptosuite === 'ecdsa-rdfc-2019' ||
        proof.cryptosuite === 'ecdsa-jcs-2019' ||
        proof.cryptosuite === 'ecdsa-sd-2023') {
        const {verificationMethod} = proof;
        const multibaseMultikeyHeader =
          verificationMethod.substring('did:key:'.length).slice(0, 4);
        const ecdsaAlgorithm =
          SUPPORTED_ECDSA_ALGORITHMS.get(multibaseMultikeyHeader);
        if(!ecdsaAlgorithms.includes(ecdsaAlgorithm)) {
          ecdsaAlgorithms.push(ecdsaAlgorithm);
        }
      }
    }
  });
  return ecdsaAlgorithms;
}

export function getDidParts({did}) {
  const [scheme, method] = did.split(':');
  return {scheme, method};
}

// produce VC-JWT-enveloped VC
export async function envelopeCredential({
  verifiableCredential, signer, options = {}
} = {}) {
  /* Example:
  {
    "alg": <signer.algorithm>,
    "kid": <signer.id>
  }.
  {
    "iss": <verifiableCredential.issuer>,
    "jti": <verifiableCredential.id>
    "sub": <verifiableCredential.credentialSubject>
    "nbf": <verifiableCredential.[issuanceDate | validFrom]>
    "exp": <verifiableCredential.[expirationDate | validUntil]>
    "vc": <verifiableCredential>
  }
  */
  const {
    id, issuer, credentialSubject,
    issuanceDate, expirationDate, validFrom, validUntil
  } = verifiableCredential;

  const payload = {
    iss: issuer?.id ?? issuer
  };

  if(id !== undefined) {
    payload.jti = id;
  }

  // use `id` property of (first) credential subject
  let sub = Array.isArray(credentialSubject) ?
    credentialSubject[0] : credentialSubject;
  sub = sub?.id ?? sub;
  if(typeof sub === 'string') {
    payload.sub = sub;
  }

  let nbf = issuanceDate ?? validFrom;
  if(nbf !== undefined) {
    nbf = Date.parse(nbf);
    if(!isNaN(nbf)) {
      payload.nbf = Math.floor(nbf / 1000);
    }
  }

  let exp = expirationDate ?? validUntil;
  if(exp !== undefined) {
    exp = Date.parse(exp);
    if(!isNaN(exp)) {
      payload.exp = Math.floor(exp / 1000);
    }
  }

  payload.vc = verifiableCredential;

  const {id: kid} = signer;
  const alg = options.alg ?? _curveToAlg(signer.algorithm);
  const protectedHeader = {alg, kid};

  const jwt = await signJWT({payload, protectedHeader, signer});
  return {
    '@context': [VC_CONTEXT_2],
    id: `data:application/jwt,${jwt}`,
    type: 'EnvelopedVerifiableCredential'
  };
}

export async function envelopePresentation({
  verifiablePresentation, challenge, domain, signer, options = {}
} = {}) {
  /* Example:
  {
    "alg": <signer.algorithm>,
    "kid": <signer.id>
  }.
  {
    "iss": <verifiablePresentation.holder>,
    "aud": <verifiablePresentation.domain>,
    "nonce": <verifiablePresentation.nonce>,
    "jti": <verifiablePresentation.id>
    "nbf": <verifiablePresentation.[validFrom]>
    "exp": <verifiablePresentation.[validUntil]>
    "vp": <verifiablePresentation>
  }
  */
  const {id, holder, validFrom, validUntil} = verifiablePresentation;

  const payload = {
    iss: holder?.id ?? holder,
    aud: domain,
    nonce: challenge
  };

  if(id !== undefined) {
    payload.jti = id;
  }

  let nbf = validFrom;
  if(nbf !== undefined) {
    nbf = Date.parse(nbf);
    if(!isNaN(nbf)) {
      payload.nbf = Math.floor(nbf / 1000);
    }
  }

  let exp = validUntil;
  if(exp !== undefined) {
    exp = Date.parse(exp);
    if(!isNaN(exp)) {
      payload.exp = Math.floor(exp / 1000);
    }
  }

  payload.vp = verifiablePresentation;

  const {id: kid} = signer;
  const alg = options.alg ?? _curveToAlg(signer.algorithm);
  const protectedHeader = {alg, kid};

  const jwt = await signJWT({payload, protectedHeader, signer});
  return {
    '@context': VC_CONTEXT_2,
    id: `data:application/jwt,${jwt}`,
    type: 'EnvelopedVerifiablePresentation'
  };
}

export async function signJWT({payload, protectedHeader, signer} = {}) {
  // encode payload and protected header
  const b64Payload = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const b64ProtectedHeader = Buffer.from(
    JSON.stringify(protectedHeader)).toString('base64url');
  payload = TEXT_ENCODER.encode(b64Payload);
  protectedHeader = TEXT_ENCODER.encode(b64ProtectedHeader);

  // concatenate
  const data = new Uint8Array(
    protectedHeader.length + ENCODED_PERIOD.length + payload.length);
  data.set(protectedHeader);
  data.set(ENCODED_PERIOD, protectedHeader.length);
  data.set(payload, protectedHeader.length + ENCODED_PERIOD.length);

  // sign
  const signature = await signer.sign({data});

  // create JWS
  const jws = {
    signature: Buffer.from(signature).toString('base64url'),
    payload: b64Payload,
    protected: b64ProtectedHeader
  };

  // create compact JWT
  return `${jws.protected}.${jws.payload}.${jws.signature}`;
}

function _curveToAlg(crv) {
  if(crv === 'Ed25519' || crv === 'Ed448') {
    return 'EdDSA';
  }
  if(crv?.startsWith('P-')) {
    return `ES${crv.slice(2)}`;
  }
  if(crv === 'secp256k1') {
    return 'ES256K';
  }
  return crv;
}
