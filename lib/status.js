/*!
 * Copyright (c) 2019-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {
  checkStatus as bitstringStatusListCheckStatus,
  statusTypeMatches as bitstringStatusListStatusTypeMatches
} from '@digitalbazaar/vc-bitstring-status-list';
import {
  checkStatus as revocationListCheckStatus,
  statusTypeMatches as revocationListStatusTypeMatches
} from '@digitalbazaar/vc-revocation-list';
import {
  checkStatus as statusList2020CheckStatus,
  statusTypeMatches as statusList2020StatusTypeMatches
} from '@digitalbazaar/vc-status-list';
import assert from 'assert-plus';
import {createDocumentLoader} from './documentLoader.js';

const handlerMap = new Map();
handlerMap.set('BitstringStatusListEntry', {
  checkStatus: bitstringStatusListCheckStatus,
  statusTypeMatches: bitstringStatusListStatusTypeMatches
});
handlerMap.set('RevocationList2020Status', {
  checkStatus: revocationListCheckStatus,
  statusTypeMatches: revocationListStatusTypeMatches
});
handlerMap.set('StatusList2021Entry', {
  checkStatus: statusList2020CheckStatus,
  statusTypeMatches: statusList2020StatusTypeMatches
});

export function createCheckStatus({config} = {}) {
  return async function checkStatus(options = {}) {
    assert.object(options, 'options');
    assert.object(options.credential, 'options.credential');

    try {
      const {credential} = options;
      const {credentialStatus} = credential;
      if(!credentialStatus) {
        // no status to check
        return {verified: true};
      }

      const handlers = handlerMap.get(credentialStatus.type);
      if(!(handlers && handlers.statusTypeMatches({credential}))) {
        throw new Error(
          `Unsupported credentialStatus type "${credentialStatus.type}".`);
      }

      // document loader needs to only allow web loading of status
      // list VCs, nothing else
      const documentLoader = await createDocumentLoader({
        config,
        remoteUrlAllowList: new Set([
          credentialStatus.statusListCredential ??
          credentialStatus.revocationListCredential
        ])
      });
      options = {
        ...options,
        documentLoader
      };
      return await handlers.checkStatus(options);
    } catch(error) {
      return {verified: false, error};
    }
  };
}
