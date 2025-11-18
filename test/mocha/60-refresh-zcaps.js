/*!
 * Copyright (c) 2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from './helpers.js';
import {agent} from '@bedrock/https-agent';
import {CapabilityAgent} from '@digitalbazaar/webkms-client';
import {httpClient} from '@digitalbazaar/http-client';
import {mockData} from './mock.data.js';
import {verifierService} from '@bedrock/vc-verifier';

const {baseUrl} = mockData;
const serviceType = 'vc-verifier';

describe('refresh zcaps', () => {
  let capabilityAgent;
  const zcaps = {};
  before(async () => {
    // enable refresh handler
    verifierService._disableRefreshHandler = false;

    const secret = '53ad64ce-8e1d-11ec-bb12-10bf48838a41';
    const handle = 'test';
    capabilityAgent = await CapabilityAgent.fromSecret({secret, handle});

    // create keystore for capability agent
    const keystoreAgent = await helpers.createKeystoreAgent(
      {capabilityAgent});

    // create EDV for storage (creating hmac and kak in the process)
    const {
      edvConfig,
      hmac,
      keyAgreementKey
    } = await helpers.createEdv({capabilityAgent, keystoreAgent});

    // get service agent to delegate to
    const serviceAgentUrl =
      `${baseUrl}/service-agents/${encodeURIComponent(serviceType)}`;
    const {data: serviceAgent} = await httpClient.get(serviceAgentUrl, {
      agent
    });

    // delegate edv, hmac, and key agreement key zcaps to service agent
    const {id: edvId} = edvConfig;
    zcaps.edv = await helpers.delegate({
      controller: serviceAgent.id,
      delegator: capabilityAgent,
      invocationTarget: edvId
    });
    const {keystoreId} = keystoreAgent;
    zcaps.hmac = await helpers.delegate({
      capability: `urn:zcap:root:${encodeURIComponent(keystoreId)}`,
      controller: serviceAgent.id,
      invocationTarget: hmac.id,
      delegator: capabilityAgent
    });
    zcaps.keyAgreementKey = await helpers.delegate({
      capability: `urn:zcap:root:${encodeURIComponent(keystoreId)}`,
      controller: serviceAgent.id,
      invocationTarget: keyAgreementKey.kmsId,
      delegator: capabilityAgent
    });
    // delegate refresh zcap to service agent; this zcap must not be expired
    const profilePath =
      `${baseUrl}/profiles/${encodeURIComponent(capabilityAgent.id)}`;
    const refreshUrl =
      `${profilePath}/zcaps` +
      `/policies/${encodeURIComponent(serviceAgent.id)}/refresh`;
    zcaps.refresh = await helpers.delegate({
      controller: serviceAgent.id,
      capability: `urn:zcap:root:${encodeURIComponent(profilePath)}`,
      delegator: capabilityAgent,
      invocationTarget: refreshUrl
    });
  });
  after(() => {
    // disable refresh handler
    verifierService._disableRefreshHandler = true;
  });
  it('should refresh zcaps in a config', async () => {
    const {id: meterId} = await helpers.createMeter({
      capabilityAgent, serviceType: 'vc-verifier'
    });
    const originalConfig = await helpers.createConfig({
      capabilityAgent, meterId, zcaps
    });

    const expectedAfter = Date.now();

    // wait sufficient time for refresh to occur
    await new Promise(r => setTimeout(r, 300));

    // fetch config
    const updatedConfig = await helpers.getConfig({
      id: originalConfig.id, capabilityAgent
    });

    // config should be updated
    updatedConfig.sequence.should.be.gte(1);

    // get config record directly to check meta
    const record = await verifierService.configStorage.get({
      id: originalConfig.id
    });

    record.meta.refresh.enabled.should.equal(true);
    record.meta.refresh.after.should.be.gte(expectedAfter);

    // ensure zcaps changed
    for(const [key, value] of Object.entries(zcaps)) {
      updatedConfig.zcaps[key].should.not.deep.equal(value);
      record.config.zcaps[key].should.not.deep.equal(value);
    }
  });
});
