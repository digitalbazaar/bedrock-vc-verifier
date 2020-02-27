/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const brRest = require('bedrock-rest');
const jsigs = require('jsonld-signatures');
const {asyncHandler} = require('bedrock-express');
const {config} = bedrock;
const vc = require('vc-js');
require('bedrock-credentials-context');

const {
  suites: {Ed25519Signature2018},
} = jsigs;
// load module config
require('./config');
const {serializeReport} = require('./utils');

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
      let _report;
      try {
        _report = await vc.verify({
          documentLoader: loader.documentLoader,
          challenge,
          domain,
          suite: new Ed25519Signature2018(),
          presentation,
        });
      } catch(e) {
        console.log('VC.VERIFY ERROR', e);
        throw e;
      }
      const report = serializeReport(_report);
      if(report.error === true) {
        return res.status(400).json(report);
      }
      res.json(report);
    }));
  // FIXME this is mock route that needs to be implemented.
  app.post(cfg.routes.verification, asyncHandler(async (req, res) => {
    // FIXME use verifierId & referenceId
    const {verifierId, referenceId} = req.params;
    // FIXME use these to actually verify
    const {
      options = {},
      credential,
      presentation
    } = req.body;
    res.json({verified: true});
  }));
}
