/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
import base58 from 'base58-universal';
import LRU from 'lru-cache';
import {promisify} from 'util';
import {randomBytes, timingSafeEqual} from 'crypto';
import {serviceAgents} from 'bedrock-service-agent';

const getRandomBytes = promisify(randomBytes);

const serviceType = 'vc-verifier';

// 60 minutes in seconds
const ONE_HOUR = 60 * 60;

/* This cache is used to store used challenges. It doesn't need to be an LRU
cache for any particular reason, but `lru-cache` is commonly used in the
bedrock stack and provides the needed features. */
let CHALLENGE_CACHE;

bedrock.on('init', () => {


});

/**
 * Generates a challenge to be used within the configured time frame.
 *
 * @param {object} options - The options to use.
 * @param {object} config - The verifier instance config.
 *
 * @returns {Promise<string>} The challenge.
 */
export async function generateChallenge({config}) {
  /* The process for generating a challenge and keep its size down to 48 bytes
  (plus base58-encoding) is:

  1. Get the challenge delta, `delta`, from the bedrock configuration. Note: In
    the future, we may allow per-verifier instance challenge delta settings.
  2. Get a 32 byte timestamp (seconds) for the challenge expiration time,
    `expires`, by rounding the current time to the next `delta` in the current
    hour + `delta`. So, for example, if `delta` = 15 minutes, and
    `now = 5:04pm`, then round `now` to `5:15pm` and add `delta` to get an
    expiration time of `5:30pm` (translated into seconds since the epoch). This
    means that a challenge will always expire within `2 * delta` minutes. In
    this way, any challenge created from `5:00pm` through `5:14:59pm` will
    expire at `5:30pm` and any challenge created from `5:15pm` through
    `5:29:59pm` will expire at `5:45pm`. When verifying a challenge any time
    between `5:00pm` and `5:14:59pm`, the valid expiration times will be
    `5:15pm` and `5:30pm`. When verifying a challenge any time between
    `5:15pm` and `5:29:59pm`, the valid expiration times will be `5:30pm` and
    `5:45pm`.
  3. Generate a 16 byte random value, `random`.
  4. Get a 32 byte signature, `signature`, by computing
    `hmac(random + expires + config.id)`.
  5. Return `base58.encode(random + signature)` as the generated `challenge`.
  */

  // get hmac key
  const {serviceAgent} = await serviceAgents.get({serviceType});
  const hmac = await serviceAgents.getHmac({serviceAgent});

  // get `delta` and compute `expires`
  const {timeDelta: delta} = bedrock.config['vc-verifier'].challenges;
  const expires = _computeChallengeExpiration({delta});

  // generate 16 byte random
  const random = await getRandomBytes(16);

  // concatenate random, expires, config.id
  const data = _buildChallengeVerifyData({random, expires, config});
  const signature = await hmac.sign({data});

  // concatenate random and signature and encode to produce challenge
  const challenge = new Uint8Array(48);
  challenge.set(random);
  challenge.set(signature, 16);
  return base58.encode(challenge);
}

/**
 * Upserts a new entity. If the entity already exists, its time to live will be
 * updated, but its `minAssuranceForResolution` will not be changed. To change
 * the entity's `minAssuranceForResolution`, call
 * `setMinAssuranceForResolution`.
 *
 * @param {object} options - Options to use.
 * @param {Buffer} options.internalId - The internal ID for the entity.
 * @param {number} options.ttl - The number of milliseconds until the
 *   entity should expire.
 * @param {number} [options.minAssuranceForResolution] - Minimum level of
 *   identity assurance required for token resolution. This will default to
 *   `2` for new entities.
 * @param {boolean} [options.explain] - An optional explain boolean.
 *
 * @returns {Promise<object | ExplainObject>} Resolves with an object
 *   representing the entity record or an ExplainObject if `explain=true`.
 */
export async function _upsert({
  internalId, ttl, minAssuranceForResolution, explain = false
} = {}) {
  assert.buffer(internalId, 'internalId');
  assert.number(ttl, 'ttl');
  assert.optionalNumber(minAssuranceForResolution, 'minAssuranceForResolution');

  const now = Date.now();
  const collection = database.collections['tokenization-entity'];
  const meta = {created: now, updated: now};
  const expires = new Date(now + ttl);
  const entity = {
    internalId,
    batchInvalidationCount: 0,
    openBatch: {},
    // default `minAssuranceForResolution=2`
    minAssuranceForResolution:
      minAssuranceForResolution === undefined ? 2 : minAssuranceForResolution,
    expires
  };
  const query = {'entity.internalId': entity.internalId};
  // only update ttl on update
  const $set = {
    'entity.expires': entity.expires,
    'meta.updated': meta.updated
  };
  // include all other entity properties on insert
  const $setOnInsert = {
    'entity.internalId': entity.internalId,
    'entity.batchInvalidationCount': entity.batchInvalidationCount,
    'entity.openBatch': {},
    'entity.minAssuranceForResolution': entity.minAssuranceForResolution,
    'meta.created': meta.created
  };
  const record = {entity, meta};
  const upsertOptions = {...database.writeOptions, upsert: true};

  if(explain) {
    // 'find().limit(1)' is used here because 'updateOne()' doesn't return a
    // cursor which allows the use of the explain function.
    const cursor = await collection.find(query).limit(1);
    return cursor.explain('executionStats');
  }

  // this upsert cannot trigger duplicate error; no try/catch needed
  const result = await collection.updateOne(
    query, {$set, $setOnInsert}, upsertOptions);
  if(result.result.upserted) {
    // return full record when upserted
    return {_id: result.result.upserted[0]._id, ...record};
  }
  // return true/false on update
  return result.result.n !== 0;
}

/**
 * Verifies that a challenge has not expired and has not been verified too many
 * times already.
 *
 * @param {object} options - The options to use.
 * @param {object} config - The verifier instance config.
 * @param {string} challenge - The challenge to verify.
 *
 * @returns {Promise<object>} `{verified: <boolean>, error?}`.
 */
 export async function verifyChallenge({config, challenge}) {
  /* The process for verifying a challenge is:

  1. `base58.decode(challenge)` and split the result to get a 16 byte random
    value, `random`, and a 32 byte signature, `expectedSignature`.
  2. Get the challenge delta, `delta`, from the bedrock configuration. Note: In
    the future, we may allow per-verifier instance challenge delta settings.
  3. Get two 32 byte timestamps (seconds) for valid challenge expiration
    times by rounding the current time to the next `delta` in the current hour
    + `delta` to get `expiresLow` and setting `expiresHigh` to
    `expiresLow + delta`.
  4. Get two possible 32 byte signatures, `signature1` and `signature2`, by
    computing `hmac(random + expiresLow + config.id)` and
    `hmac(random + expiresHigh + config.id)`, respectively.
  5. Do a constant time comparison between `signature1` and `expectedSignature`
    and `signature2` and `expectedSignature`. If either is true return
    `verified=true`, otherwise return `verified=false`.
  */

  // decode and split challenge
  const decoded = base58.decode(challenge);
  if(decoded.length !== 48) {
    // invalid challenge length
    return {
      verified: false,
      error: new Error('Challenge is invalid.')
    };
  }
  const random = decoded.slice(0, 16);
  const expectedSignature = decoded.slice(16, 48);

  // get hmac key
  const {serviceAgent} = await serviceAgents.get({serviceType});
  const hmac = await serviceAgents.getHmac({serviceAgent});

  // get `delta` and compute `expires1` and `expires2`
  const {timeDelta: delta} = bedrock.config['vc-verifier'].challenges;
  const expires1 = _computeChallengeExpiration({delta});
  const expires2 = expires1 + delta;

  // concatenate random, expires, config.id
  const data1 = _buildChallengeVerifyData({random, expires: expires1, config});
  const data2 = _buildChallengeVerifyData({random, expires: expires2, config});

  const [signature1, signature2] = await Promise.all([
    hmac.sign({data: data1}),
    hmac.sign({data: data2})
  ]);

  // constant time compare both signatures
  const equal1 = timingSafeEqual(signature, signature1);
  const equal2 = timingSafeEqual(signature, signature2);

  // no short-circuit/timing issues here because if either of these is
  // successful, an acceptable value has already been determined -- otherwise,
  // both are invalid and no side channel information is learned
  const verified = equal1 || equal2;
  if(verified) {
    return {verified}
  }
  return {verified, error: new Error('Invalid or expired challenge.')}
}

function _computeChallengeExpiration({delta}) {
  // get `now` in seconds and current `hour`
  const now = Math.ceil(Date.now() / 1000);
  const secondsPastHour = now % ONE_HOUR;
  const hour = now - secondsPastHour;

  // compute expires
  const expires = hour + (Math.floor(secondsPastHour / delta) + 1) * delta;
  return expires;
}

function _buildChallengeVerifyData({random, expires, config}) {
  // concatenate random, expires, config.id
  const configIdBytes = (new TextEncoder()).encode(config.id);
  const buffer = new Uint8Array(48 + configIdBytes.length);
  buffer.set(random);
  const dv = new DataView(buffer);
  dv.setUint32(16, expires);
  buffer.set(configIdBytes, 48);
  return buffer;
}
