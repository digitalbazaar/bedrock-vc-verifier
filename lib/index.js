/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const {asyncHandler} = require('bedrock-express');
const {config} = bedrock;

// load module config
require('./config');
const {'vc-verifier': cfg} = config;

// add routes
bedrock.events.on('bedrock-express.configure.routes', addRoutes);

function addRoutes(app) {
  app.post(cfg.routes.verify, asyncHandler(async (req, res) => {
    res.json({valid: true});
  }));
}
