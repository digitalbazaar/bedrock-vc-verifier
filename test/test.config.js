/*!
 * Copyright (c) 2012-2020 Digital Bazaar, Inc. All rights reserved.
 */
const {config} = require('bedrock');
const path = require('path');
require('bedrock-did-io');

config.mocha.tests.push(path.join(__dirname, 'mocha'));

config['https-agent'].rejectUnauthorized = false;
