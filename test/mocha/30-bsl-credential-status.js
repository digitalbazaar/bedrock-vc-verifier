/*!
 * Copyright (c) 2019-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from './helpers.js';
import * as vc from '@digitalbazaar/vc';
import {agent} from '@bedrock/https-agent';
import {documentLoader as brDocLoader} from '@bedrock/jsonld-document-loader';
import {CapabilityAgent} from '@digitalbazaar/webkms-client';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {
  Ed25519VerificationKey2020
} from '@digitalbazaar/ed25519-verification-key-2020';
import express from 'express';
import {fileURLToPath} from 'node:url';
import fs from 'node:fs';
import {httpClient} from '@digitalbazaar/http-client';
import https from 'node:https';
import path from 'node:path';

import {mockData} from './mock.data.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const {baseUrl} = mockData;
const serviceType = 'vc-verifier';

const VC_V2_CONTEXT_URL = 'https://www.w3.org/ns/credentials/v2';
const VC_BARCODES_V1_CONTEXT_URL = 'https://w3id.org/vc-barcodes/v1';

const encodedList100k =
  'uH4sIAAAAAAAAA-3BMQEAAADCoPVPbQsvoAAAAAAAAAAAAAAAAP4GcwM92tQwAAA';
const encodedList100KWith50KthRevoked =
  'uH4sIAAAAAAAAA-3OMQ0AAAgDsElHOh72EJJWQRMAAAAAAIDWXAcAAAAAAIDHFvRitn7UMAAA';
const key = fs.readFileSync(__dirname + '/key.pem');
const cert = fs.readFileSync(__dirname + '/cert.pem');

let slcRevocation;
let slcSuspension;
let unsignedCredentialStatusPurposeRevocation;
let unsignedCredentialStatusPurposeSuspension;
let unsignedCredentialWithUnmatchingStatusPurpose;
let revokedSlc;
let revokedUnsignedCredential;

// load docs from test server (e.g., load SL VCs)
let testServerBaseUrl;
async function _documentLoader(url) {
  if(url.startsWith(testServerBaseUrl)) {
    const response = await httpClient.get(url, {agent});
    return {
      contextUrl: null,
      documentUrl: url,
      document: response.data
    };
  }
  return brDocLoader(url);
}

function _startServer({app}) {
  return new Promise(resolve => {
    const server = https.createServer({key, cert}, app);
    server.listen(() => {
      const {port} = server.address();
      const BASE_URL = `https://localhost:${port}`;
      testServerBaseUrl = BASE_URL;
      console.log(`Test server listening at ${BASE_URL}`);

      // SLC with statusPurpose `revocation`
      slcRevocation = {
        '@context': [
          VC_V2_CONTEXT_URL
        ],
        id: `${BASE_URL}/status/748a7d8e-9111-11ec-a934-10bf48838a41`,
        issuer: 'did:key:z6Mktpn6cXks1PBKLMgZH2VaahvCtBMF6K8eCa7HzrnuYLZv',
        validFrom: '2022-01-10T04:24:12.164Z',
        type: ['VerifiableCredential', 'BitstringStatusListCredential'],
        credentialSubject: {
          id: `${BASE_URL}/status/748a7d8e-9111-11ec-a934-10bf48838a41#list`,
          type: 'BitstringStatusList',
          statusPurpose: 'revocation',
          encodedList: encodedList100k
        }
      };

      // unsigned VC with "credentialStatus.statusPurpose" `revocation`
      unsignedCredentialStatusPurposeRevocation = {
        '@context': [
          VC_V2_CONTEXT_URL,
          'https://w3id.org/security/suites/ed25519-2020/v1'
        ],
        id: 'urn:uuid:a0418a78-7924-11ea-8a23-10bf48838a41',
        type: ['VerifiableCredential', 'example:TestCredential'],
        credentialSubject: {
          id: 'urn:uuid:4886029a-7925-11ea-9274-10bf48838a41',
          'example:test': 'foo'
        },
        credentialStatus: {
          id: `${BASE_URL}/status/748a7d8e-9111-11ec-a934-10bf48838a41#67342`,
          type: 'BitstringStatusListEntry',
          statusPurpose: 'revocation',
          statusListIndex: '67342',
          statusListCredential: slcRevocation.id
        },
        issuer: slcRevocation.issuer,
      };

      // SLC with statusPurpose `suspension`
      slcSuspension = {
        '@context': [
          VC_V2_CONTEXT_URL
        ],
        id: `${BASE_URL}/status/5d3e7a97-1121-11ec-9b38-10bf48838a41`,
        issuer: 'did:key:z6Mktpn6cXks1PBKLMgZH2VaahvCtBMF6K8eCa7HzrnuYLZv',
        validFrom: '2022-01-10T04:24:12.164Z',
        type: ['VerifiableCredential', 'BitstringStatusListCredential'],
        credentialSubject: {
          id: `${BASE_URL}/status/5d3e7a97-1121-11ec-9b38-10bf48838a41#list`,
          type: 'BitstringStatusList',
          statusPurpose: 'suspension',
          encodedList: encodedList100k
        }
      };

      // unsigned VC with "credentialStatus.statusPurpose" `suspension`
      unsignedCredentialStatusPurposeSuspension = {
        '@context': [
          VC_V2_CONTEXT_URL,
          'https://w3id.org/security/suites/ed25519-2020/v1'
        ],
        id: 'urn:uuid:a0418a78-7924-11ea-8a23-10bf48838a41',
        type: ['VerifiableCredential', 'example:TestCredential'],
        credentialSubject: {
          id: 'urn:uuid:4886029a-7925-11ea-9274-10bf48838a41',
          'example:test': 'foo'
        },
        credentialStatus: {
          id: `${BASE_URL}/status/5d3e7a97-1121-11ec-9b38-10bf48838a41#67342`,
          type: 'BitstringStatusListEntry',
          statusPurpose: 'suspension',
          statusListIndex: '67342',
          statusListCredential: slcSuspension.id
        },
        issuer: slcSuspension.issuer,
      };

      // unsigned VC with unmatching status purpose
      unsignedCredentialWithUnmatchingStatusPurpose = {
        '@context': [
          VC_V2_CONTEXT_URL,
          'https://w3id.org/security/suites/ed25519-2020/v1'
        ],
        id: 'urn:uuid:a0418a78-7924-11ea-8a23-10bf48838a41',
        type: ['VerifiableCredential', 'example:TestCredential'],
        credentialSubject: {
          id: 'urn:uuid:4886029a-7925-11ea-9274-10bf48838a41',
          'example:test': 'foo'
        },
        credentialStatus: {
          id: `${BASE_URL}/status/748a7d8e-9111-11ec-a934-10bf48838a41#67342`,
          type: 'BitstringStatusListEntry',
          // intentionally set status purpose that does not match status purpose
          // of sl credential that it fetches.
          statusPurpose: 'suspension',
          statusListIndex: '67342',
          // intentionally point `statusListCredential` to a sl credential
          // with status purpose `revocation`.
          statusListCredential: slcRevocation.id
        },
        issuer: slcRevocation.issuer,
      };

      // revoked SLC
      revokedSlc = structuredClone(slcRevocation);

      revokedSlc.id =
        `${BASE_URL}/status/8ec30054-9111-11ec-9ab5-10bf48838a41`,
      revokedSlc.credentialSubject.encodedList =
        encodedList100KWith50KthRevoked;
      revokedSlc.credentialSubject.id =
        `${BASE_URL}/status/8ec30054-9111-11ec-9ab5-10bf48838a41#list`;

      // revoked unsigned SLC
      revokedUnsignedCredential = structuredClone(
        unsignedCredentialStatusPurposeRevocation);
      revokedUnsignedCredential.credentialStatus.id =
        `${revokedSlc.id}#50000`;
      revokedUnsignedCredential.credentialStatus.statusListIndex = 50000;
      revokedUnsignedCredential.credentialStatus.statusListCredential =
        `${revokedSlc.id}`;
      revokedUnsignedCredential.issuer = revokedSlc.issuer;

      return resolve(server);
    });
  });
}

const app = express();
app.use(express.json());

// mount the test routes
app.get('/status/748a7d8e-9111-11ec-a934-10bf48838a41',
  // eslint-disable-next-line no-unused-vars
  (req, res, next) => {
    // responds with a valid SLC
    res.json(slcRevocation);
  });
app.get('/status/5d3e7a97-1121-11ec-9b38-10bf48838a41',
  // eslint-disable-next-line no-unused-vars
  (req, res, next) => {
    // responds with a valid SLC
    res.json(slcSuspension);
  });
app.get('/status/8ec30054-9111-11ec-9ab5-10bf48838a41',
  // eslint-disable-next-line no-unused-vars
  (req, res, next) => {
    // responds with SLC w/a revoked bit in it
    res.json(revokedSlc);
  });
// route for terse SLC
app.get('/status-lists/revocation/0',
  // eslint-disable-next-line no-unused-vars
  (req, res, next) => {
    // responds with SLC w/a revoked bit in it
    res.json(revokedSlc);
  });
// routes for terse SLC w/both revocation and suspension
app.get('/both/status-lists/revocation/0',
  // eslint-disable-next-line no-unused-vars
  (req, res, next) => {
    // responds with a valid SLC
    res.json(slcRevocation);
  });
app.get('/both/status-lists/suspension/0',
  // eslint-disable-next-line no-unused-vars
  (req, res, next) => {
    // responds with a valid SLC
    res.json(slcSuspension);
  });

let server;
before(async () => {
  server = await _startServer({app});
});
after(async () => {
  server.close();
});

describe('verify BitstringStatusList credential status', () => {
  let keyData;
  let keyPair;
  let suite;
  before(async () => {
    keyData = {
      id: 'did:key:z6Mktpn6cXks1PBKLMgZH2VaahvCtBMF6K8eCa7HzrnuYLZv#' +
        'z6Mktpn6cXks1PBKLMgZH2VaahvCtBMF6K8eCa7HzrnuYLZv',
      controller: 'did:key:z6Mktpn6cXks1PBKLMgZH2VaahvCtBMF6K8eCa7HzrnuYLZv',
      type: 'Ed25519VerificationKey2020',
      publicKeyMultibase: 'z6Mktpn6cXks1PBKLMgZH2VaahvCtBMF6K8eCa7HzrnuYLZv',
      privateKeyMultibase: 'zrv2rP9yjtz3YwCas9m6hnoPxmoqZV72xbCEuomXi4wwSS' +
        '4ShekesADYiAMHoxoqfyBDKQowGMvYx9rp6QGJ7Qbk7Y4'
    };
    keyPair = await Ed25519VerificationKey2020.from(keyData);
    suite = new Ed25519Signature2020({key: keyPair});
  });
  let capabilityAgent;
  let verifierConfig;
  let verifierId;
  let rootZcap;
  const zcaps = {};
  beforeEach(async () => {
    const secret = '53ad64ce-8e1d-11ec-bb12-10bf48838a41';
    const handle = 'test';
    capabilityAgent = await CapabilityAgent.fromSecret({secret, handle});

    // create keystore for capability agent
    const keystoreAgent = await helpers.createKeystoreAgent(
      {capabilityAgent});

    // create EDV for storage (creating hmac and kak in the process)
    const {
      edvConfig,
      hmac,
      keyAgreementKey
    } = await helpers.createEdv({capabilityAgent, keystoreAgent});

    // get service agent to delegate to
    const serviceAgentUrl =
      `${baseUrl}/service-agents/${encodeURIComponent(serviceType)}`;
    const {data: serviceAgent} = await httpClient.get(serviceAgentUrl, {
      agent
    });

    // delegate edv, hmac, and key agreement key zcaps to service agent
    const {id: edvId} = edvConfig;
    zcaps.edv = await helpers.delegate({
      controller: serviceAgent.id,
      delegator: capabilityAgent,
      invocationTarget: edvId
    });
    const {keystoreId} = keystoreAgent;
    zcaps.hmac = await helpers.delegate({
      capability: `urn:zcap:root:${encodeURIComponent(keystoreId)}`,
      controller: serviceAgent.id,
      invocationTarget: hmac.id,
      delegator: capabilityAgent
    });
    zcaps.keyAgreementKey = await helpers.delegate({
      capability: `urn:zcap:root:${encodeURIComponent(keystoreId)}`,
      controller: serviceAgent.id,
      invocationTarget: keyAgreementKey.kmsId,
      delegator: capabilityAgent
    });

    // create verifier instance
    verifierConfig = await helpers.createConfig({capabilityAgent, zcaps});
    verifierId = verifierConfig.id;
    rootZcap = `urn:zcap:root:${encodeURIComponent(verifierId)}`;
  });
  it('should verify VC w/ "statusPurpose" revocation', async () => {
    // only reissue if not already issued
    if(!slcRevocation.proof) {
      slcRevocation = await vc.issue({
        credential: structuredClone(slcRevocation),
        documentLoader: _documentLoader,
        suite
      });
    }
    const verifiableCredential = await vc.issue({
      credential: structuredClone(unsignedCredentialStatusPurposeRevocation),
      documentLoader: _documentLoader,
      suite
    });
    let error;
    let result;
    try {
      const zcapClient = helpers.createZcapClient({capabilityAgent});
      result = await zcapClient.write({
        url: `${verifierId}/credentials/verify`,
        capability: rootZcap,
        json: {
          options: {
            checks: ['proof', 'credentialStatus'],
          },
          verifiableCredential
        }
      });
    } catch(e) {
      error = e;
    }
    assertNoError(error);
    should.exist(result.data.verified);
    result.data.verified.should.be.a('boolean');
    result.data.verified.should.equal(true);
    const {checks, statusResult} = result.data;
    checks.should.be.an('array');
    checks.should.have.length(2);
    checks.should.be.an('array');
    checks.should.eql(['proof', 'credentialStatus']);
    should.exist(result.data.results);
    result.data.results.should.be.an('array');
    result.data.results.should.have.length(1);
    {
      const [r] = result.data.results;
      r.verified.should.be.a('boolean');
      r.verified.should.equal(true);
    }
    {
      should.exist(statusResult);
      statusResult.should.be.an('object');
      should.exist(statusResult.results);
      statusResult.results.should.be.an('array');
      statusResult.results.should.have.length(1);
      const [r] = statusResult.results;
      r.verified.should.be.a('boolean');
      r.verified.should.equal(true);
      r.status.should.equal(false);
    }
  });
  it('should verify VC w/ "statusPurpose" suspension', async () => {
    // only reissue if not already issued
    if(!slcSuspension.proof) {
      slcSuspension = await vc.issue({
        credential: structuredClone(slcSuspension),
        documentLoader: _documentLoader,
        suite
      });
    }
    const verifiableCredential = await vc.issue({
      credential: structuredClone(unsignedCredentialStatusPurposeSuspension),
      documentLoader: _documentLoader,
      suite
    });
    let error;
    let result;
    try {
      const zcapClient = helpers.createZcapClient({capabilityAgent});
      result = await zcapClient.write({
        url: `${verifierId}/credentials/verify`,
        capability: rootZcap,
        json: {
          options: {
            checks: ['proof', 'credentialStatus'],
          },
          verifiableCredential
        }
      });
    } catch(e) {
      error = e;
    }
    assertNoError(error);
    should.exist(result.data.verified);
    result.data.verified.should.be.a('boolean');
    result.data.verified.should.equal(true);
    const {checks, statusResult} = result.data;
    checks.should.be.an('array');
    checks.should.have.length(2);
    checks.should.be.an('array');
    checks.should.eql(['proof', 'credentialStatus']);
    should.exist(result.data.results);
    result.data.results.should.be.an('array');
    result.data.results.should.have.length(1);
    {
      const [r] = result.data.results;
      r.verified.should.be.a('boolean');
      r.verified.should.equal(true);
    }
    {
      should.exist(statusResult);
      statusResult.should.be.an('object');
      should.exist(statusResult.results);
      statusResult.results.should.be.an('array');
      statusResult.results.should.have.length(1);
      const [r] = statusResult.results;
      r.verified.should.be.a('boolean');
      r.verified.should.equal(true);
      r.status.should.equal(false);
    }
  });
  it('should verify VC w/ terse "statusPurpose" revocation', async () => {
    // only reissue if not already issued
    if(!revokedSlc.proof) {
      revokedSlc = await vc.issue({
        credential: structuredClone(revokedSlc),
        documentLoader: _documentLoader,
        suite
      });
    }
    const c = structuredClone(unsignedCredentialStatusPurposeRevocation);
    c['@context'].push(VC_BARCODES_V1_CONTEXT_URL);
    c.credentialStatus = {
      type: 'TerseBitstringStatusListEntry',
      terseStatusListBaseUrl: `${testServerBaseUrl}/status-lists`,
      terseStatusListIndex: 67342
    };
    const verifiableCredential = await vc.issue({
      credential: c,
      documentLoader: _documentLoader,
      suite
    });
    let error;
    let result;
    try {
      const zcapClient = helpers.createZcapClient({capabilityAgent});
      result = await zcapClient.write({
        url: `${verifierId}/credentials/verify`,
        capability: rootZcap,
        json: {
          options: {
            checks: ['proof', 'credentialStatus'],
          },
          verifiableCredential
        }
      });
    } catch(e) {
      error = e;
    }
    assertNoError(error);
    should.exist(result.data.verified);
    result.data.verified.should.be.a('boolean');
    result.data.verified.should.equal(true);
    const {checks, statusResult} = result.data;
    checks.should.be.an('array');
    checks.should.have.length(2);
    checks.should.be.an('array');
    checks.should.eql(['proof', 'credentialStatus']);
    should.exist(result.data.results);
    result.data.results.should.be.an('array');
    result.data.results.should.have.length(1);
    {
      const [r] = result.data.results;
      r.verified.should.be.a('boolean');
      r.verified.should.equal(true);
    }
    {
      should.exist(statusResult);
      statusResult.should.be.an('object');
      should.exist(statusResult.results);
      statusResult.results.should.be.an('array');
      statusResult.results.should.have.length(1);
      const [r] = statusResult.results;
      r.verified.should.be.a('boolean');
      r.verified.should.equal(true);
      r.status.should.equal(false);
    }
  });
  it('should verify VC w/ terse w/ both statuses', async () => {
    // only reissue if not already issued
    if(!slcRevocation.proof) {
      slcRevocation = await vc.issue({
        credential: structuredClone(slcRevocation),
        documentLoader: _documentLoader,
        suite
      });
    }
    // only reissue if not already issued
    if(!slcSuspension.proof) {
      slcSuspension = await vc.issue({
        credential: structuredClone(slcSuspension),
        documentLoader: _documentLoader,
        suite
      });
    }
    const c = structuredClone(unsignedCredentialStatusPurposeRevocation);
    c['@context'].push(VC_BARCODES_V1_CONTEXT_URL);
    c.credentialStatus = {
      type: 'TerseBitstringStatusListEntry',
      // note "/both/" in URL to map to mocks with "/both/" routes
      terseStatusListBaseUrl: `${testServerBaseUrl}/both/status-lists`,
      terseStatusListIndex: 67342
    };
    const verifiableCredential = await vc.issue({
      credential: c,
      documentLoader: _documentLoader,
      suite
    });
    let error;
    let result;
    try {
      const zcapClient = helpers.createZcapClient({capabilityAgent});
      result = await zcapClient.write({
        url: `${verifierId}/credentials/verify`,
        capability: rootZcap,
        json: {
          options: {
            checks: ['proof', 'credentialStatus'],
          },
          verifiableCredential
        }
      });
    } catch(e) {
      error = e;
    }
    assertNoError(error);
    should.exist(result.data.verified);
    result.data.verified.should.be.a('boolean');
    result.data.verified.should.equal(true);
    const {checks, statusResult} = result.data;
    checks.should.be.an('array');
    checks.should.have.length(2);
    checks.should.be.an('array');
    checks.should.eql(['proof', 'credentialStatus']);
    should.exist(result.data.results);
    result.data.results.should.be.an('array');
    result.data.results.should.have.length(1);
    {
      const [r] = result.data.results;
      r.verified.should.be.a('boolean');
      r.verified.should.equal(true);
    }
    {
      should.exist(statusResult);
      statusResult.should.be.an('object');
      should.exist(statusResult.results);
      statusResult.results.should.be.an('array');
      statusResult.results.should.have.length(2);
      for(const r of statusResult.results) {
        r.verified.should.be.a('boolean');
        r.verified.should.equal(true);
        r.status.should.equal(false);
      }
    }
  });
  it('should fail if "statusPurpose" of the SLC does not match', async () => {
    slcRevocation = await vc.issue({
      credential: structuredClone(slcRevocation),
      documentLoader: _documentLoader,
      suite
    });
    const verifiableCredential = await vc.issue({
      credential: structuredClone(
        unsignedCredentialWithUnmatchingStatusPurpose),
      documentLoader: _documentLoader,
      suite
    });
    let error;
    let result;
    try {
      const zcapClient = helpers.createZcapClient({capabilityAgent});
      result = await zcapClient.write({
        url: `${verifierId}/credentials/verify`,
        capability: rootZcap,
        json: {
          options: {
            checks: ['proof', 'credentialStatus'],
          },
          verifiableCredential
        }
      });
    } catch(e) {
      error = e;
    }
    should.exist(error);
    should.not.exist(result);
    error.data.verified.should.equal(false);
    const {error: {cause: errorCause}} = error.data;
    errorCause.should.equal(
      'The status purpose "revocation" of the status list credential ' +
      'does not match the status purpose "suspension" in the credential.');
  });
  it('should fail to verify revoked VC', async () => {
    // only reissue SLC w/revoked bit if not already issued
    if(!revokedSlc.proof) {
      revokedSlc = await vc.issue({
        credential: structuredClone(revokedSlc),
        documentLoader: _documentLoader,
        suite
      });
    }
    const verifiableCredential = await vc.issue({
      credential: structuredClone(revokedUnsignedCredential),
      documentLoader: _documentLoader,
      suite
    });
    let error;
    let result;
    try {
      const zcapClient = helpers.createZcapClient({capabilityAgent});
      result = await zcapClient.write({
        url: `${verifierId}/credentials/verify`,
        capability: rootZcap,
        json: {
          options: {
            checks: ['proof', 'credentialStatus'],
          },
          verifiableCredential
        }
      });
    } catch(e) {
      error = e;
    }
    assertNoError(error);
    should.exist(result.data.verified);
    result.data.verified.should.be.a('boolean');
    result.data.verified.should.equal(true);
    const {checks, statusResult} = result.data;
    checks.should.be.an('array');
    checks.should.have.length(2);
    checks.should.be.an('array');
    checks.should.eql(['proof', 'credentialStatus']);
    should.exist(statusResult);
    statusResult.should.be.an('object');
    should.exist(statusResult.results);
    statusResult.results.should.be.an('array');
    statusResult.results.should.have.length(1);
    const [r] = statusResult.results;
    r.verified.should.be.a('boolean');
    r.verified.should.equal(true);
    r.status.should.equal(true);
  });
  it('should fail to verify revoked terse VC', async () => {
    // only reissue SLC w/revoked bit if not already issued
    if(!revokedSlc.proof) {
      revokedSlc = await vc.issue({
        credential: structuredClone(revokedSlc),
        documentLoader: _documentLoader,
        suite
      });
    }
    const c = structuredClone(revokedUnsignedCredential);
    c['@context'].push(VC_BARCODES_V1_CONTEXT_URL);
    c.credentialStatus = {
      type: 'TerseBitstringStatusListEntry',
      terseStatusListBaseUrl: `${testServerBaseUrl}/status-lists`,
      terseStatusListIndex: 50000
    };
    const verifiableCredential = await vc.issue({
      credential: c,
      documentLoader: _documentLoader,
      suite
    });
    let error;
    let result;
    try {
      const zcapClient = helpers.createZcapClient({capabilityAgent});
      result = await zcapClient.write({
        url: `${verifierId}/credentials/verify`,
        capability: rootZcap,
        json: {
          options: {
            checks: ['proof', 'credentialStatus'],
          },
          verifiableCredential
        }
      });
    } catch(e) {
      error = e;
    }
    assertNoError(error);
    should.exist(result.data.verified);
    result.data.verified.should.be.a('boolean');
    result.data.verified.should.equal(true);
    const {checks, statusResult} = result.data;
    checks.should.be.an('array');
    checks.should.have.length(2);
    checks.should.be.an('array');
    checks.should.eql(['proof', 'credentialStatus']);
    should.exist(statusResult);
    statusResult.should.be.an('object');
    should.exist(statusResult.results);
    statusResult.results.should.be.an('array');
    statusResult.results.should.have.length(1);
    const [r] = statusResult.results;
    r.verified.should.be.a('boolean');
    r.verified.should.equal(true);
    r.status.should.equal(true);
  });
});
