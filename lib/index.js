/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const brRest = require('bedrock-rest');
const {asyncHandler} = require('bedrock-express');
const {config} = bedrock;

// load module config
require('./config');
const {'vc-verifier': cfg} = config;

// add routes
bedrock.events.on('bedrock-express.configure.routes', addRoutes);

function addRoutes(app) {
  app.post(cfg.routes.verify, brRest.when.prefers.ld,
    asyncHandler(async (req, res) => {
      console.log('888888888', req.body);
      res.json({valid: true});
    }));
}
