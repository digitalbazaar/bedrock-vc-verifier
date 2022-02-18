/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
import assert from 'assert-plus';
import {
  checkStatus as statusListCheckStatus,
  statusTypeMatches as statusListStatusTypeMatches
} from 'vc-status-list';
import {
  checkStatus as revocationListCheckStatus,
  statusTypeMatches as revocationListStatusTypeMatches
} from 'vc-revocation-list';

const handlerMap = new Map();
handlerMap.set('RevocationList2020Status', {
  checkStatus: revocationListCheckStatus,
  statusTypeMatches: revocationListStatusTypeMatches
});
handlerMap.set('RevocationList2021Status', {
  checkStatus: statusListCheckStatus,
  statusTypeMatches: statusListStatusTypeMatches
});
handlerMap.set('SuspensionList2021Status', {
  checkStatus: statusListCheckStatus,
  statusTypeMatches: statusListStatusTypeMatches
});

export async function checkStatus(options = {}) {
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

    return await handlers.checkStatus(options);
  } catch(error) {
    return {verified: false, error};
  }
};
