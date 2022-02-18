/*
 * Copyright (c) 2016-2020 Digital Bazaar, Inc. All rights reserved.
 */
const bedrock = require('bedrock');
const {getServiceIdentities} = require('bedrock-app-identity');
require('bedrock-edv-storage');
require('bedrock-https-agent');
require('bedrock-kms');
require('bedrock-kms-http');
require('bedrock-meter');
require('bedrock-meter-usage-reporter');
const {handlers} = require('bedrock-meter-http');
require('bedrock-server');
const {initializeServiceAgent} = require('bedrock-service-agent');
require('bedrock-ssm-mongodb');
require('bedrock-test');
const {addRoutes} = require('bedrock-service-context-store');
const {createService} = require('bedrock-service-core');
require('bedrock-vc-verifier');

const mockData = require('./mocha/mock.data');

bedrock.events.on('bedrock.init', async () => {
  /* Handlers need to be added before `bedrock.start` is called. These are
  no-op handlers to enable meter usage without restriction */
  handlers.setCreateHandler({
    handler({meter} = {}) {
      // use configured meter usage reporter as service ID for tests
      const clientName = mockData.productIdMap.get(meter.product.id);
      const serviceIdentites = getServiceIdentities();
      const serviceIdentity = serviceIdentites.get(clientName);
      if(!serviceIdentity) {
        throw new Error(`Could not find identity "${clientName}".`);
      }
      meter.serviceId = serviceIdentity.id;
      return {meter};
    }
  });
  handlers.setUpdateHandler({handler: ({meter} = {}) => ({meter})});
  handlers.setRemoveHandler({handler: ({meter} = {}) => ({meter})});
  handlers.setUseHandler({handler: ({meter} = {}) => ({meter})});
});

bedrock.start();
