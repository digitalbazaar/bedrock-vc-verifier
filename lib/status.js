/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {checkStatus, statusTypeMatches} = require('vc-revocation-list');

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

    if(statusTypeMatches({credential})) {
      result = await checkStatus(options);
    } else {
      throw new Error(
        `Unsupported credentialStatus type "${credentialStatus.type}".`);
    }
  } catch(error) {
    result = {
      verified: false,
      error
    };
  }
  return result;
};
