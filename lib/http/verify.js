/*!
 * Copyright (c) 2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {asyncHandler} = require('bedrock-express');
const authz = require('./authz.js');
const bedrock = require('bedrock');
require('bedrock-express');
const {config, util: {BedrockError}} = bedrock;
const cors = require('cors');
const helpers = require('../helpers');
const {meters} = require('bedrock-meter-usage-reporter');
const {SERVICE_TYPE} = helpers;
const instances = require('../storage/instances.js');
const {
  postVerifyCredentialBody, postVerifyPresentationBody
} = require('../../schemas/bedrock-vc-verifer');
const {validate} = require('../validator.js');

bedrock.events.on('bedrock-express.configure.routes', app => {
  const cfg = config['vc-verifier'];

  const routes = helpers.getRoutes();
  const {baseUri} = config.server;
  const instanceRoot = `${baseUri}${routes.instances}`;

  /* Note: CORS is used on all endpoints. This is safe because authorization
  uses HTTP signatures + capabilities, not cookies; CSRF is not possible. */

  // verify a credential
  app.options(routes.verifyCredential, cors());
  app.post(
    routes.verifyCredential,
    // FIXME: enable
    //validate({bodySchema: postVerifyCredentialBody}),
    authz.authorizeZcapInvocation({
      // FIXME: make helper?
      async getExpectedTarget({req}) {
        // expected target is full instance URL or that + this route
        let {expectedTarget} = await _getExpectedConfigTarget({req});
        expectedTarget = [
          expectedTarget, `${expectedTarget}/vc/verify/credential`
        ];
        return {expectedTarget};
      }
    }),
    asyncHandler(async (req, res) => {
      // get config to use for verification
      const id = helpers.getInstanceId({localId: req.params.instanceId});
      const {config} = await instances.get({id});

      // FIXME: perform verification of VC
      throw new Error('Not implemented');

      // meter operation usage
      helpers.reportOperationUsageWithoutWaiting({instanceId: id});
    }));

  // verify a presentation
  app.options(routes.verifyPresentation, cors());
  app.post(
    routes.verifyPresentation,
    // FIXME: enable
    //validate({bodySchema: postVerifyPresentationBody}),
    authz.authorizeZcapInvocation({
      // FIXME: make helper?
      async getExpectedTarget({req}) {
        // expected target is full instance URL or that + this route
        let {expectedTarget} = await _getExpectedConfigTarget({req});
        expectedTarget = [
          expectedTarget, `${expectedTarget}/vc/verify/presentation`
        ];
        return {expectedTarget};
      }
    }),
    asyncHandler(async (req, res) => {
      // get config to use for verification
      const id = helpers.getInstanceId({localId: req.params.instanceId});
      const {config} = await instances.get({id});

      // FIXME: perform verification of VP
      throw new Error('Not implemented');

      // meter operation usage
      helpers.reportOperationUsageWithoutWaiting({instanceId: id});
    }));
});

// FIXME: make helper?
async function _getExpectedConfigTarget({req}) {
  // ensure the `configId` matches the request URL (i.e., that the caller
  // POSTed a config with an ID that matches up with the URL to which they
  // POSTed); this is not a security issue if this check is not performed,
  // however, it can help clients debug errors on their end
  const {body: {id: configId}} = req;
  const requestUrl = `${req.protocol}://${req.get('host')}${req.url}`;
  if(configId !== requestUrl) {
    throw new BedrockError(
      'The request URL does not match the configuration ID.',
      'URLMismatchError', {
        // this error will be a `cause` in the onError handler;
        // this httpStatusCode is not operative
        httpStatusCode: 400,
        public: true,
        configId,
        requestUrl,
      });
  }
  return {expectedTarget: configId};
}
