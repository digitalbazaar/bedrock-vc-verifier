/*!
 * Copyright (c) 2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const assert = require('assert-plus');
const bedrock = require('bedrock');
const {util: {BedrockError}} = bedrock;

// module API
const api = {};
module.exports = api;

/**
 * Establishes a new instance by inserting its configuration into storage.
 *
 * @param {Object} config the instance configuration.
 *
 * @return {Promise<Object>} resolves to the database record.
 */
api.insert = async ({config}) => {
  assert.object(config, 'config');
  assert.string(config.id, 'config.id');
  assert.string(config.controller, 'config.controller');
  assert.string(config.meterId, 'config.meterId');

  // FIXME: does `sequence` from EDV doc suffice?

  // require starting sequence to be 0
  if(config.sequence !== 0) {
    throw new BedrockError(
      'Configuration sequence must be "0".',
      'DataError', {
        public: true,
        httpStatusCode: 400
      });
  }

  // FIXME: use `Collection` API
  throw new Error('Not implemented');
};

/**
 * Retrieves all instance configs matching the given query.
 *
 * @param {string} controller the controller for the instances to retrieve.
 * @param {Object} [query={}] the optional query to use.
 * @param {Object} [options={}] options (eg: 'sort', 'limit').
 *
 * @return {Promise<Array>} resolves to the records that matched the query.
 */
api.find = async ({controller, query = {}, options = {}}) => {
  // FIXME: use `Collection` API
  throw new Error('Not implemented');
};

/**
 * Updates an instance config if its sequence number is next.
 *
 * @param {Object} config the instance configuration.
 *
 * @return {Promise<Object>} resolves to the database record.
 */
api.update = async ({config}) => {
  assert.object(config, 'config');
  assert.string(config.id, 'config.id');
  assert.number(config.sequence, config.sequence);
  assert.string(config.controller, 'config.controller');

  // FIXME: use `Collection` API
  throw new Error('Not implemented');

  return true;
};

/**
 * Gets an instance configuration.
 *
 * @param {string} id the ID of the instance.
 *
 * @return {Promise<Object>} resolves to `{config, meta}`.
 */
api.get = async ({id}) => {
  assert.string(id, 'id');

  // FIXME: use `Collection` API
  throw new Error('Not implemented');
};
