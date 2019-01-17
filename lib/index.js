/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const brRest = require('bedrock-rest');
const {asyncHandler} = require('bedrock-express');
const {config} = bedrock;
const serializeError = require('serialize-error');
const vc = require('vc-js');
require('bedrock-credentials-context');

// load module config
require('./config');
const {'vc-verifier': cfg} = config;

// must be loaded after the module config
const loader = require('./documentLoader');

const api = {loader};
module.exports = api;

// add routes
bedrock.events.on('bedrock-express.configure.routes', addRoutes);

function addRoutes(app) {
  app.post(cfg.routes.verify, brRest.when.prefers.ld,
    asyncHandler(async (req, res) => {
      const {challenge, domain, presentation} = req.body;
      let result;
      try {
        result = await vc.verifyPresentation({
          challenge,
          documentLoader: loader.documentLoader,
          domain,
          presentation,
        });
      } catch(e) {
        console.log('VC.VERIFY ERROR', e);
        throw e;
      }
      // iterate the results and serialize errors
      result.credentialResult.forEach(r => {
        if(!r.error) {
          return;
        }
        r.error = _serializeError(r.error);
        r.results.forEach(p => {
          if(p.error) {
            p.error = _serializeError(p.error);
          }
        });
      });
      if(result.presentationResult.error) {
        result.presentationResult.error = _serializeError(
          result.presentationResult.error);
        result.presentationResult.results.forEach(p => {
          if(p.error) {
            p.error = _serializeError(p.error);
          }
        });
      }
      res.json(result);
    }));
}

function _serializeError(error) {
  if(Array.isArray(error)) {
    return error.map(e => {
      return _serializeError(e);
    });
  }
  const t = serializeError(error);
  delete t.stack;
  return t;
}
