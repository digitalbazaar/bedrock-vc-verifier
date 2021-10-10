/*!
 * Copyright (c) 2018-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {
  authorizeZcapInvocation, authorizeZcapRevocation
} = require('@digitalbazaar/ezcap-express');
const bedrock = require('bedrock');
const brZCapStorage = require('bedrock-zcap-storage');
const {config, util: {BedrockError}} = bedrock;
const {documentLoader} = require('../documentLoader');
const {Ed25519Signature2020} = require('@digitalbazaar/ed25519-signature-2020');
const instances = require('../storage/instances.js');
const {instanceId} = require('../helpers');

exports.authorizeInstanceZcapInvocation = () => {
  // authz for instance endpoints
  return exports.authorizeZcapInvocation({
    getExpectedTarget: _getExpectedInstanceTarget
  });
};

exports.authorizeZcapInvocation = ({
  getExpectedTarget, getRootController = exports.getRootController,
  expectedAction, getExpectedAction, onError = exports.onError
} = {}) => {
  return authorizeZcapInvocation({
    expectedHost: config.server.host,
    getRootController,
    documentLoader,
    getExpectedTarget,
    expectedAction,
    getExpectedAction,
    inspectCapabilityChain: exports.inspectCapabilityChain,
    onError
  });
};

exports.authorizeZcapRevocation = () => {
  return authorizeZcapRevocation({
    expectedHost: config.server.host,
    getRootController: exports.getRootController,
    documentLoader,
    async getExpectedTarget({req}) {
      const instanceId = getInstanceId({localId: req.params.instanceId});
      // ensure instance can be retrieved
      await instances.get({id: instanceId, req});
      // allow target to be root instance, main revocations endpoint, *or*
      // zcap-specific revocation endpoint; see ezcap-express for more
      const revocations = `${instanceId}/revocations`;
      const revokeZcap = `${revocations}/` +
        encodeURIComponent(req.params.zcapId);
      return {expectedTarget: [instanceId, revocations, revokeZcap]};
    },
    suiteFactory() {
      return new Ed25519Signature2020();
    },
    inspectCapabilityChain: exports.inspectCapabilityChain,
    onError: exports.onError
  });
};

exports.inspectCapabilityChain = async ({
  capabilityChain, capabilityChainMeta
}) => {
  // collect the capability IDs and delegators for the capabilities in the chain
  const capabilities = [];
  for(const [i, capability] of capabilityChain.entries()) {
    const [{purposeResult}] = capabilityChainMeta[i].verifyResult.results;
    if(purposeResult && purposeResult.delegator) {
      capabilities.push({
        capabilityId: capability.id,
        delegator: purposeResult.delegator.id,
      });
    }
  }
  const revoked = await brZCapStorage.revocations.isRevoked({capabilities});

  if(revoked) {
    return {
      valid: false,
      error: new Error(
        'One or more capabilities in the chain have been revoked.')
    };
  }

  return {valid: true};
};

exports.getRootController = async ({
  req, rootCapabilityId, rootInvocationTarget
}) => {
  const instanceBaseUrl = req.protocol + '://' + req.get('host') +
    config['vc-verifier'].routes.basePath;

  // get controller for the entire verifier service
  if(rootInvocationTarget === instanceBaseUrl) {
    throw new Error(`Invalid root invocation target "${instanceBaseUrl}".`);
  }

  // get controller for an individual instance
  let controller;
  try {
    const record = await instances.get({id: rootInvocationTarget, req});
    ({config: {controller}} = record);
  } catch(e) {
    if(e.type === 'NotFoundError') {
      const url = req.protocol + '://' + req.get('host') + req.url;
      throw new Error(
        `Invalid capability identifier "${rootCapabilityId}" ` +
        `for URL "${url}".`);
    }
    throw e;
  }
  return controller;
};

exports.onError = ({error}) => {
  // cause must be a public BedrockError to be surfaced to the HTTP client
  let cause;
  if(error instanceof BedrockError) {
    cause = error;
  } else {
    cause = new BedrockError(
      error.message,
      error.name || 'NotAllowedError', {
        ...error.details,
        public: true,
      });
  }
  throw new BedrockError(
    'Authorization error.', 'NotAllowedError', {
      httpStatusCode: 403,
      public: true,
    }, cause);
};

// FIXME: needs adjustment
async function _getExpectedInstanceTarget({req}) {
  // expected target is the instance itself
  const instanceId = getInstanceId({localId: req.params.instanceId});
  return {
    expectedTarget: instanceId
  };
}
