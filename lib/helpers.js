/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
import serializeError from 'serialize-error';

export function serializeReport(report) {
  // a report can have no results
  // if an error occurred before the credentials were checked
  if(!report.results) {
    return report;
  }
  // iterate the results and serialize errors
  report.results.forEach(r => {
    if(!r.error) {
      return;
    }
    r.error = _serializeError(r.error);
    r.results.forEach(p => {
      if(p.error) {
        p.error = _serializeError(p.error);
      }
    });
  });
  return report;
}

function _serializeError(error) {
  if(Array.isArray(error)) {
    return error.map(e => _serializeError(e));
  }
  const t = serializeError(error);
  delete t.stack;
  return t;
}
