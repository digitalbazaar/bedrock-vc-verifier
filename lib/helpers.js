/*!
 * Copyright (c) 2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const base58 = require('base58-universal');
const bedrock = require('bedrock');
const {config, util: {BedrockError}} = bedrock;
const crypto = require('crypto');
const instances = require('./storage/instances.js');
const logger = require('./logger');
const {meters} = require('bedrock-meter-usage-reporter');
const {promisify} = require('util');
const getRandomBytes = promisify(crypto.randomBytes);

exports.SERVICE_TYPE = 'vc-verifier';

exports.assert128BitId = id => {
  try {
    // verify ID is base58-encoded multibase multicodec encoded 16 bytes
    const buf = base58.decode(id.substr(1));
    // multibase base58 (starts with 'z')
    // 128-bit random number, multicodec encoded
    // 0x00 = identity tag, 0x10 = length (16 bytes) + 16 random bytes
    if(!(id.startsWith('z') &&
      buf.length === 18 && buf[0] === 0x00 && buf[1] === 0x10)) {
      throw new Error('Invalid identifier.');
    }
  } catch(e) {
    throw new BedrockError(
      `Identifier "${id}" must be base58-encoded multibase, ` +
      'multicodec array of 16 random bytes.',
      'SyntaxError',
      {public: true, httpStatusCode: 400});
  }
};

exports.getInstanceId = ({localId} = {}) => {
  exports.assert128BitId(localId);
  const {baseUri} = config.server;
  const baseStorageUrl = `${baseUri}${config['vc-verifier'].routes.basePath}`;
  return `${baseStorageUrl}/${localId}`;
};

exports.getRoutes = () => {
  const cfg = config['vc-verifier'];

  // Note: instance routes are fixed off of the base path
  const routes = {...cfg.routes};
  routes.instances = routes.basePath;
  routes.instance = `${routes.instances}/:instanceId`;
  routes.revocations = `${routes.instance}/revocations/:zcapId`;
  routes.verifyCredential = `${routes.instance}/vc/verify/credential`;
  routes.verifyPresentation = `${routes.instance}/vc/verify/presentation`;

  return routes;
};

exports.generateRandom = async () => {
  // 128-bit random number, multibase encoded
  // 0x00 = identity tag, 0x10 = length (16 bytes)
  const buf = Buffer.concat([
    Buffer.from([0x00, 0x10]),
    await getRandomBytes(16)
  ]);
  // multibase encoding for base58 starts with 'z'
  return `z${base58.encode(buf)}`;
};

exports.reportOperationUsageWithoutWaiting = ({instanceId}) => {
  // do not await
  _reportOperationUsage({instanceId}).catch();
};

exports.parseLocalId = ({id}) => {
  // format: <base>/<localId>
  const idx = id.lastIndexOf('/');
  const localId = id.substr(idx + 1);
  return {
    base: id.substring(0, idx),
    localId: exports.decodeLocalId({localId})
  };
};

exports.decodeLocalId = ({localId}) => {
  // convert to `Buffer` for storage savings (`z<base58-encoded ID>`)
  // where the ID is multicodec encoded 16 byte random value
  // 0x00 = identity tag, 0x10 = length (16 bytes) header
  return Buffer.from(base58.decode(localId.slice(1)).slice(2));
};

async function _reportOperationUsage({instanceId}) {
  let meterId;
  try {
    const {config} = await instances.get({id: instanceId});
    meterId = config.meterId;
    await meters.use({id: meterId, operations: 1});
  } catch(error) {
    let message = 'Meter ';
    if(meterId) {
      message += `(${meterId}) `;
    }
    message += `usage error for instance "${instanceId}".`;
    logger.error(message, {error});
  }
}
