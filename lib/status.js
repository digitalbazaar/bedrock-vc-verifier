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
      const error = new Error(
        `Unsupported credentialStatus type "${credentialStatus.type}".`);
      // throw error;
      console.error(error);
      // FIXME: Throw error instead of returning verified
      return {verified: true};
    }
  } catch(error) {
    result = {
      verified: false,
      error
    };
  }
  return result;
};
