/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const {config} = bedrock;
const axios = require('axios');
const https = require('https');
const jsigs = require('jsonld-signatures');
const mockData = require('./mock.data');
const v1 = new (require('did-veres-one')).VeresOne({env: 'dev'});

const strictSSL = false;
const url = `${config.server.baseUri}/vc/verify`;

describe('verify API', () => {
  it('', async () => {
    let error;
    let result;
    const {credential} = await _generate();
    try {
      result = await axios({
        httpsAgent: new https.Agent({rejectUnauthorized: strictSSL}),
        data: {credential},
        method: 'POST',
        url,
      });
    } catch(e) {
      error = e;
    }
    should.not.exist(error);
    should.exist(result.data);
    const {data} = result;
    console.log('RRRRRRR', data);
  });
});

function _createDocumentLoader() {
  return async url => {
    console.log('1111111111111', url);
    let document;
    try {
      ({document} = await bedrock.jsonld.documentLoader(url));
    } catch(e) {
      console.log('UUUUUU', url);
    }
    if(!document) {
      throw new Error('NotFoundError');
    }
    return {
      contextUrl: null,
      document,
      documentUrl: url
    };
  };
}

async function _generate() {
  const v1DidDoc = await v1.generate();
  const aKey = v1DidDoc.suiteKeyNode({suiteId: 'authentication'});
  const authenticationKey = v1DidDoc.keys[aKey.id];
  const key = await authenticationKey.export();
  console.log('ppppppppp', key);
  // console.log('DDDDDDD', aKey.export());
  // console.log('DDDDDDD', v1);
  const mockCredential = bedrock.util.clone(mockData.credentials.alpha);
  const {Ed25519Signature2018} = jsigs.suites;
  const {AuthenticationProofPurpose} = jsigs.purposes;
  const credential = await jsigs.sign(mockCredential, {
    // FIXME: `sec` terms are not in the vc-v1 context, should they be?
    compactProof: true,
    documentLoader: _createDocumentLoader(),
    suite: new Ed25519Signature2018({key}),
    purpose: new AuthenticationProofPurpose({
      challenge: 'foo'
    })
  });
  return {credential};
}
