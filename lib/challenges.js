/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as database from '@bedrock/mongodb';
import assert from 'assert-plus';
import {createRequire} from 'node:module';
const require = createRequire(import.meta.url);
const {generateId, decodeId} = require('bnid');

const {util: {BedrockError}} = bedrock;

const COLLECTION_NAME = 'vc-verifier-challenge';

bedrock.events.on('bedrock-mongodb.ready', async () => {
  await database.openCollections([COLLECTION_NAME]);

  await database.createIndexes([{
    collection: COLLECTION_NAME,
    fields: {'challenge.value': 1},
    options: {unique: true, background: false}
  }, {
    // automatically expire challenges
    collection: COLLECTION_NAME,
    fields: {'challenge.expires': 1},
    options: {
      unique: false,
      background: false,
      expireAfterSeconds: 0
    }
  }]);
});

/**
 * Generates and stores a challenge to be used within the configured time
 * frame.
 *
 * @param {object} options - The options to use.
 * @param {object} options.verifierId - The verifier instance ID.
 *
 * @returns {Promise<string>} The challenge.
 */
export async function createChallenge({verifierId}) {
  // generate challenge
  const challenge = await _generateChallenge();
  // insert and return challenge
  const {ttl} = bedrock.config['vc-verifier'].challenges;
  await _insert({challenge, verifierId, ttl});
  return challenge;
}

/**
 * Verifies that a challenge has not expired.
 *
 * @param {object} options - The options to use.
 * @param {object} options.verifierId - The verifier instance ID.
 * @param {string} options.challenge - The challenge to verify.
 *
 * @returns {Promise<object>} `{verified: <boolean>, uses, error?}`.
 */
export async function verifyChallenge({verifierId, challenge} = {}) {
  try {
    // try to use challenge
    const record = await _use({challenge, verifierId});
    return {verified: true, uses: record.challenge.uses};
  } catch(error) {
    return {verified: false, error};
  }
}

async function _generateChallenge() {
  // 128-bit random number, base58 multibase + multihash encoded
  return generateId({
    bitLength: 128,
    encoding: 'base58',
    multibase: true,
    multihash: true
  });
}

function _decodeChallenge({challenge}) {
  // convert to `Buffer` for database storage savings
  try {
    return Buffer.from(decodeId({
      id: challenge,
      encoding: 'base58',
      multibase: true,
      multihash: true,
      expectedSize: 16
    }));
  } catch(e) {
    throw new BedrockError(
      'Invalid challenge.', 'DataError', {
        httpStatusCode: 400,
        public: true
      });
  }
}

/**
 * Inserts a new challenge into storage.
 *
 * @param {object} options - The options to use.
 * @param {string} options.challenge - The challenge to upsert.
 * @param {number} options.ttl - The time to live for the challenge.
 *
 * @returns {Promise<object>} Resolves with an object representing the
 *   challenge record.
 */
async function _insert({challenge, ttl} = {}) {
  assert.string(challenge, 'challenge');
  assert.number(ttl, 'ttl');
  challenge = _decodeChallenge({challenge});

  // insert the configuration and get the updated record
  const now = Date.now();
  const meta = {created: now, updated: now};
  const expires = new Date(now + ttl);
  const record = {
    challenge: {
      value: challenge,
      expires,
      uses: 0
    },
    meta
  };
  try {
    const collection = database.collections[COLLECTION_NAME];
    const result = await collection.insertOne(record);
    return result.ops[0];
  } catch(e) {
    if(!database.isDuplicateError(e)) {
      throw e;
    }
    // should never happen; challenge values are sufficiently large and random
    throw new BedrockError(
      'Duplicate challenge.',
      'DuplicateError', {
        public: true,
        httpStatusCode: 409
      }, e);
  }
}

/**
 * Finds and updates a challenge's `uses`.
 *
 * @param {object} options - Options to use.
 * @param {string} options.challenge - The challenge to mark as used.
 * @param {boolean} [options.explain] - An optional explain boolean.
 *
 * @returns {Promise<object | ExplainObject>} Resolves with an object
 *   representing the challenge record or an ExplainObject if `explain=true`.
 */
async function _use({challenge, explain = false} = {}) {
  assert.string(challenge, 'challenge');
  assert.bool(explain, 'explain');
  challenge = _decodeChallenge({challenge});

  const collection = database.collections[COLLECTION_NAME];
  const query = {'challenge.value': challenge};
  const $inc = {
    'challenge.uses': 1,
  };
  const $set = {
    'meta.updated': Date.now()
  };
  const options = {
    ...database.writeOptions,
    // return document after the update
    returnDocument: 'after'
  };

  if(explain) {
    // 'find().limit(1)' is used here because 'updateOne()' doesn't return a
    // cursor which allows the use of the explain function.
    const cursor = await collection.find(query).limit(1);
    return cursor.explain('executionStats');
  }

  // this upsert cannot trigger duplicate error; no try/catch needed
  const result = await collection.findOneAndUpdate(
    query, {$inc, $set}, options);

  if(!result.value) {
    // no document found, challenge invalid or expired
    throw new BedrockError(
      'Invalid or expired challenge.', 'DataError', {
        httpStatusCode: 400,
        public: true
      });
  }

  return result.value;
}

/**
 * @typedef ExplainObject - MongoDB explain object.
 */
