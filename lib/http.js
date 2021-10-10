/*!
 * Copyright (c) 2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
require('bedrock-express');
const {config} = bedrock;
const helpers = require('./helpers');
const {meters} = require('bedrock-meter-usage-reporter');

require('./http/instances.js');
require('./http/revocations.js');

// configure usage aggregator for verifier instance meters
const {SERVICE_TYPE} = helpers;
meters.setAggregator({serviceType: SERVICE_TYPE, handler: _aggregateUsage});

// FIXME: aggregating usage will only involve operations not storage, which
// is externalized (and metered elsewhere)

async function _aggregateUsage({/*meter, signal*/} = {}) {
  //const {id: meterId} = meter;
  const [usage, revocationCount] = await Promise.all([
    // FIXME: implement `storage.getUsage()`
    //storage.getStorageUsage({meterId, signal}),
    {storage: 0},
    // FIXME: get zcap revocation count associated with this meter
    // https://github.com/digitalbazaar/bedrock-kms-http/issues/55
    0
  ]);

  // FIXME: needs adjustment? consider how revocations will occur for user
  // management

  // add revocation storage
  const {storageCost} = config['vc-verifier'];
  usage.storage += revocationCount * storageCost.revocation;

  return usage;
}
