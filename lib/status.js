/*!
 * Copyright (c) 2019-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {
  checkStatus as bitstringStatusListCheckStatus,
  statusTypeMatches as bitstringStatusListStatusTypeMatches
} from '@digitalbazaar/vc-bitstring-status-list';
import {createDocumentLoader, webLoader} from './documentLoader.js';
import {
  checkStatus as revocationListCheckStatus,
  statusTypeMatches as revocationListStatusTypeMatches
} from '@digitalbazaar/vc-revocation-list';
import {
  checkStatus as statusList2020CheckStatus,
  statusTypeMatches as statusList2020StatusTypeMatches
} from '@digitalbazaar/vc-status-list';
import assert from 'assert-plus';

const {util: {BedrockError}} = bedrock;

const TERSE_BITSTRING_STATUS_LIST_ENTRY = 'TerseBitstringStatusListEntry';
// always 2^26 = 67108864 per vc-barcodes spec
const TERSE_BITSTRING_STATUS_LIST_LENGTH = 67108864;
const TERSE_STATUS_PURPOSES = ['revocation', 'suspension'];
const VC_BARCODES_V1_CONTEXT_URL = 'https://w3id.org/vc-barcodes/v1';

const handlerMap = new Map();
handlerMap.set('BitstringStatusListEntry', {
  checkStatus: bitstringStatusListCheckStatus,
  statusTypeMatches: bitstringStatusListStatusTypeMatches
});
// legacy status entry types
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
      if(!options.credential.credentialStatus) {
        // no status to check
        return {verified: true};
      }

      // expand every `TerseBitstringStatusListEntry`
      const cache = new Map();
      const credential = await _expandAllTerseEntries({
        credential: options.credential, cache
      });
      const {credentialStatus} = credential;

      // normalize credential status to an array
      const credentialStatuses = Array.isArray(credentialStatus) ?
        credentialStatus : [credentialStatus];

      // combination of different status types not supported at this time
      const expectedType = credentialStatuses?.[0]?.type;
      if(credentialStatuses.some(({type}) => type !== expectedType)) {
        throw new BedrockError(
          'Combinations of different credential status types are not ' +
          'presently supported.', {
            name: 'NotSupportedError',
            details: {
              httpStatusCode: 400,
              public: true
            }
          });
      }

      // get handlers for `expectedType`
      const handlers = handlerMap.get(expectedType);
      if(!(handlers && handlers.statusTypeMatches({credential}))) {
        throw new BedrockError(
          `Unsupported credentialStatus type "${expectedType}".`, {
            name: 'NotSupportedError',
            details: {
              httpStatusCode: 400,
              public: true
            }
          });
      }

      // create remote URL allow list from status lists
      const remoteUrlAllowList = new Set();
      for(const cs of credentialStatuses) {
        const url = cs.statusListCredential ?? cs.revocationListCredential;
        if(url) {
          remoteUrlAllowList.add(url);
        }
      }

      // document loader needs to only allow web loading of status
      // list VCs, nothing else
      const documentLoader = await createDocumentLoader({
        config, remoteUrlAllowList, cache
      });
      options = {
        ...options,
        credential,
        documentLoader
      };
      return await handlers.checkStatus(options);
    } catch(error) {
      return {verified: false, error};
    }
  };
}

async function _expandAllTerseEntries({credential, cache} = {}) {
  try {
    // check for any terse entries
    let hasTerseEntries = false;
    const {credentialStatus} = credential;
    if(Array.isArray(credentialStatus)) {
      hasTerseEntries = credentialStatus.some(
        cs => cs?.type === TERSE_BITSTRING_STATUS_LIST_ENTRY);
    } else if(credentialStatus?.type === TERSE_BITSTRING_STATUS_LIST_ENTRY) {
      hasTerseEntries = true;
    }

    if(!hasTerseEntries) {
      return credential;
    }

    // check for expected context
    const {'@context': contexts} = credential;
    if(!Array.isArray(contexts)) {
      throw new TypeError('"@context" must be an array.');
    }
    if(!contexts.includes(VC_BARCODES_V1_CONTEXT_URL)) {
      throw new TypeError(
        `The "@context" array must include "${VC_BARCODES_V1_CONTEXT_URL}".`);
    }

    // expand any `TerseBitstringStatusListEntry` to `BitstringStatusListEntry`
    credential = structuredClone(credential);
    if(Array.isArray(credentialStatus)) {
      credential.credentialStatus = (await Promise.all(
        credentialStatus.map(
          async credentialStatus => _expandIfTerseEntry({
            credentialStatus, cache
          })))).flat();
    } else {
      credential.credentialStatus = await _expandIfTerseEntry({
        credentialStatus, cache
      });
    }
    return credential;
  } catch(cause) {
    throw new BedrockError(
      `Could not expand terse bitstring status list entries: ${cause.message}`,
      {
        name: 'DataError',
        cause,
        details: {
          httpStatusCode: 400,
          public: true
        }
      });
  }
}

async function _expandIfTerseEntry({credentialStatus, cache}) {
  if(credentialStatus?.type !== TERSE_BITSTRING_STATUS_LIST_ENTRY) {
    // nothing to expand
    return credentialStatus;
  }

  if(!webLoader) {
    throw new BedrockError(
      `Web loader disabled; cannot load credential status list(s) for `
      `status type "${credentialStatus.type}".`, {
        name: 'NotSupportedError',
        details: {
          httpStatusCode: 400,
          public: true
        }
      });
  }

  // compute two possible expanded statuses, for purposes `revocation` and
  // `suspension`...
  const credentialStatuses = (await Promise.all(
    TERSE_STATUS_PURPOSES.map(async statusPurpose => {
      const expanded = _expandTerseEntry({credentialStatus, statusPurpose});
      const exists = await _fetchStatusListIfExists({expanded, cache});
      return exists ? expanded : undefined;
    }))).filter(cs => !!cs);

  return credentialStatuses;
}

function _expandTerseEntry({credentialStatus, statusPurpose}) {
  // compute `statusListCredential` from other params
  const listIndex = Math.floor(
    credentialStatus.terseStatusListIndex / TERSE_BITSTRING_STATUS_LIST_LENGTH);
  const statusListIndex = credentialStatus.terseStatusListIndex %
    TERSE_BITSTRING_STATUS_LIST_LENGTH;
  const {terseStatusListBaseUrl} = credentialStatus;
  const statusListCredential =
    `${terseStatusListBaseUrl}/${statusPurpose}/${listIndex}`;
  return {
    type: 'BitstringStatusListEntry',
    statusListCredential,
    statusListIndex: `${statusListIndex}`,
    statusPurpose
  };
}

async function _fetchStatusListIfExists({expanded, cache}) {
  try {
    const {statusListCredential} = expanded;
    if(cache.has(statusListCredential)) {
      return true;
    }
    const {document} = await webLoader(statusListCredential);
    cache.set(statusListCredential, document);
    return true;
  } catch(e) {
    if(e.message === 'NotFoundError') {
      // ok for a terse bitstring list to not exist
      return false;
    }
    throw e;
  }
}
