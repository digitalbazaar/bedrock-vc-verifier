/*!
 * Copyright (c) 2012-2019 Digital Bazaar, Inc. All rights reserved.
 */
const {config} = require('bedrock');
const path = require('path');

config.mocha.tests.push(path.join(__dirname, 'mocha'));

const cfg = config['vc-verifier'];
cfg.ledgerHostname = 'genesis.veres.one.localhost:42443';
