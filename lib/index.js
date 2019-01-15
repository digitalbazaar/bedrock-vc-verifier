/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const brRest = require('bedrock-rest');
const {asyncHandler} = require('bedrock-express');
const {config} = bedrock;
const loader = require('./documentLoader');
const v1 = new (require('did-veres-one')).VeresOne({
  hostname: '127.0.0.1:8888',
  mode: 'dev'
});
const vc = require('vc-js');

// load module config
require('./config');
const {'vc-verifier': cfg} = config;

const api = {loader};
module.exports = api;

// add routes
bedrock.events.on('bedrock-express.configure.routes', addRoutes);

function addRoutes(app) {
  app.post(cfg.routes.verify, brRest.when.prefers.ld,
    asyncHandler(async (req, res) => {
      const {credential} = req.body;
      let result;
      try {
        result = await vc.verify({
          credential,
          documentLoader: _documentLoader,
        });
      } catch(e) {
        console.log('VC.VERIFY ERROR', e);
        throw e;
      }
      res.json(result);
    }));
}

async function _documentLoader(url) {
  let document;
  try {
    ({document} = await bedrock.jsonld.documentLoader(url));
  } catch(e) {
    let r;
    if(cfg.mode === 'dev') {
      return loader.documentLoader(url);
    }
    try {
      r = await v1.get({did: url});
      // r.record should be the did document in this case
      document = r.record;
    } catch(e) {
      console.log('VCDL Client error', e);
    }
  }
  if(!document) {
    throw new Error('NotFoundError');
  }
  return {
    contextUrl: null,
    document,
    documentUrl: url
  };
}
