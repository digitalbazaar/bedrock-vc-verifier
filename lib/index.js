/*!
 * Copyright (c) 2021-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {
  addCborldRoutes, addContextRoutes
} from '@bedrock/service-context-store';
import {createService, schemas} from '@bedrock/service-core';
import {addRoutes} from './http.js';
import {initializeServiceAgent} from '@bedrock/service-agent';
import {verifyOptions} from '../schemas/bedrock-vc-verifier.js';

// load config defaults
import './config.js';

const serviceType = 'vc-verifier';

bedrock.events.on('bedrock.init', async () => {
  // add customizations to config validators...
  const createConfigBody = structuredClone(schemas.createConfigBody);
  const updateConfigBody = structuredClone(schemas.updateConfigBody);
  const schemasToUpdate = [createConfigBody, updateConfigBody];
  for(const schema of schemasToUpdate) {
    schema.properties.verifyOptions = verifyOptions;
  }

  // create `vc-verifier` service
  const service = await createService({
    serviceType,
    routePrefix: '/verifiers',
    storageCost: {
      config: 1,
      revocation: 1
    },
    validation: {
      createConfigBody,
      updateConfigBody,
      validateConfigFn,
      // require these zcaps (by reference ID)
      zcapReferenceIds: [{
        referenceId: 'edv',
        required: true
      }, {
        referenceId: 'hmac',
        required: true
      }, {
        referenceId: 'keyAgreementKey',
        required: true
      }]
    }
  });

  bedrock.events.on('bedrock-express.configure.routes', async app => {
    await addCborldRoutes({app, service});
    await addContextRoutes({app, service});
    await addRoutes({app, service});
  });

  // initialize vc-verifier service agent early (after database is ready) if
  // KMS system is externalized; otherwise we must wait until KMS system
  // is ready
  const externalKms = !bedrock.config['service-agent'].kms.baseUrl.startsWith(
    bedrock.config.server.baseUri);
  const event = externalKms ? 'bedrock-mongodb.ready' : 'bedrock.ready';
  bedrock.events.on(event, async () => {
    await initializeServiceAgent({serviceType});
  });
});

async function validateConfigFn({config} = {}) {
  try {
    // set default `verifyOptions` if not given
    const {verifyOptions} = config;
    if(verifyOptions === undefined) {
      config.verifyOptions = {
        documentLoader: {
          allowRemoteContexts: false
        }
      };
    }
  } catch(error) {
    return {valid: false, error};
  }
  return {valid: true};
}
