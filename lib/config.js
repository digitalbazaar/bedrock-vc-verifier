/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {config} = require('bedrock');

const cfg = config['vc-verifier'] = {};

cfg.routes = {
  verify: "/vc/verify"
};
