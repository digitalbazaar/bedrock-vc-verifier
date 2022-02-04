/*!
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {checkStatus: slCheckStatus, statusTypeMatches: slStatusTypeMatches} =
  require('vc-status-list');
const {checkStatus: rlCheckStatus, statusTypeMatches: rlStatusTypeMatches} =
  require('vc-revocation-list');

const checkStatus = new Map();
const statusTypeMatches = new Map();

checkStatus.set('RevocationList2020Status', rlCheckStatus);
checkStatus.set('RevocationList2021Status', slCheckStatus);
checkStatus.set('SuspensionList2021Status', slCheckStatus);
statusTypeMatches.set('RevocationList2020Status', rlStatusTypeMatches);
statusTypeMatches.set('RevocationList2021Status', slStatusTypeMatches);
statusTypeMatches.set('SuspensionList2021Status', slStatusTypeMatches);

exports.checkStatus = async function(options = {}) {
  if(!(options && typeof options === 'object')) {
    throw new TypeError('"options" must be an object.');
  }

  const {credential} = options;
  if(!(credential && typeof credential === 'object')) {
    throw new TypeError('"credential" must be an object.');
  }

  let result;
  try {
    const {credentialStatus} = credential;
    if(!credentialStatus) {
      // no status to check
      return {verified: true};
    }
    const credentialStatusTypeMatches =
      statusTypeMatches.get(credentialStatus.type);
    if(credentialStatusTypeMatches({credential})) {
      const credentialCheckStatus = checkStatus.get(credentialStatus.type);
      result = await credentialCheckStatus(options);
    } else {
      const error = new Error(
        `Unsupported credentialStatus type "${credentialStatus.type}".`);
      throw error;
    }
  } catch(error) {
    result = {
      verified: false,
      error
    };
  }
  return result;
};
