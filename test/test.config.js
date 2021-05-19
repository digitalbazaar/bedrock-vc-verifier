/*!
 * Copyright (c) 2012-2020 Digital Bazaar, Inc. All rights reserved.
 */
const {config} = require('bedrock');
const path = require('path');

config.mocha.tests.push(path.join(__dirname, 'mocha'));

const cfg = config['vc-verifier'];
cfg.mode = 'test';

config['https-agent'].rejectUnauthorized = false;
