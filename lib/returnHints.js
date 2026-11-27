/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import {logger} from './logger.js';
import {problemDetails} from './problemDetails.js';

// registered return hints, keyed by hint name
const RETURN_HINTS = new Map();

/**
 * Registers a return hint. A return hint names a mapping that is applied to
 * the credential or presentation returned by a verify request.
 *
 * @param {object} options - Options.
 * @param {string} options.hint - The hint name, as given in
 *   `options.returnHint` or `verifyOptions.returnHint`.
 * @param {Array|Function} options.appliesTo - Either a list of matchers
 *   `{kind, mediaType}`, where an omitted field matches anything and a
 *   payload matches if any matcher matches; or a function
 *   `({payload, kind, mediaType}) => boolean` that returns `true` (not just
 *   a truthy value) when the hint applies.
 * @param {Function} options.map - An async function
 *   `({payload, kind, mediaType}) => newPayload`; it receives a copy of the
 *   payload, and must return an object. Returning anything else counts as a
 *   failed mapping. To report why a mapping failed, throw an error with
 *   `details.public: true`, such as a public BedrockError; its message is
 *   returned to the client. Any other error is only logged, by name and
 *   message.
 */
export function registerReturnHint({hint, appliesTo, map} = {}) {
  if(!(typeof hint === 'string' && hint.length > 0)) {
    throw new TypeError('"hint" must be a non-empty string.');
  }
  if(!(Array.isArray(appliesTo) || typeof appliesTo === 'function')) {
    throw new TypeError('"appliesTo" must be an array or a function.');
  }
  if(typeof map !== 'function') {
    throw new TypeError('"map" must be a function.');
  }
  if(RETURN_HINTS.has(hint)) {
    throw new Error(`Return hint "${hint}" is already registered.`);
  }
  RETURN_HINTS.set(hint, {hint, appliesTo, map});
}

/**
 * Checks whether a return hint is registered.
 *
 * @param {object} options - Options.
 * @param {string} options.hint - The hint name.
 *
 * @returns {boolean} `true` if the hint is registered.
 */
export function isReturnHintRegistered({hint} = {}) {
  return RETURN_HINTS.has(hint);
}

/**
 * Gets the return hint for a verify request; the request option overrides
 * the verifier instance default.
 *
 * @param {object} options - Options.
 * @param {object} options.config - The verifier instance config.
 * @param {object} options.options - The verify request options.
 *
 * @returns {string|undefined} The return hint, if any.
 */
export function resolveReturnHint({config, options} = {}) {
  return options?.returnHint ?? config?.verifyOptions?.returnHint;
}

/**
 * Applies a return hint to a payload. A payload the hint does not apply to
 * is returned unchanged. If the hint is unknown or the mapping fails, the
 * payload is returned unchanged with a problem details entry describing why
 * the hint was not applied.
 *
 * @param {object} options - Options.
 * @param {string} options.hint - The return hint.
 * @param {object|string} options.payload - The credential or presentation.
 * @param {string} options.kind - `credential` or `presentation`.
 * @param {string} [options.mediaType] - The payload media type: the
 *   envelope media type for an enveloped payload, else `application/vc` or
 *   `application/vp`.
 *
 * @returns {Promise<object>} `{payload, problemDetails}`; `problemDetails`,
 *   a problem details entry, is set only when the hint was not applied
 *   because it is unknown or the mapping failed.
 */
export async function applyReturnHint({
  hint, payload, kind, mediaType
} = {}) {
  const entry = RETURN_HINTS.get(hint);
  if(!entry) {
    return _notApplied({payload, detail: `Unknown return hint "${hint}".`});
  }
  try {
    if(!_appliesTo({entry, payload, kind, mediaType})) {
      return {payload};
    }
    const mapped = await entry.map({
      payload: structuredClone(payload), kind, mediaType
    });
    if(!(mapped !== null && typeof mapped === 'object')) {
      return _notApplied({
        payload, detail: `"${hint}": mapping returned no payload.`
      });
    }
    return {payload: mapped};
  } catch(e) {
    // only an error marked public is shown to the client; any other error
    // may carry internal details, so a generic message is returned; only its
    // name and message are logged, as other error details may hold personal
    // data from the payload
    if(e?.details?.public === true) {
      return _notApplied({payload, detail: `"${hint}": ${e.message}`});
    }
    logger.error(`Return hint "${hint}" failed.`, {
      error: {name: e?.name, message: e?.message}
    });
    return _notApplied({
      payload, detail: `Return hint "${hint}" could not be applied.`
    });
  }
}

function _notApplied({payload, detail}) {
  return {
    payload,
    problemDetails: problemDetails({
      problemType: 'RETURN_HINT_NOT_APPLIED', detail
    })
  };
}

function _appliesTo({entry, payload, kind, mediaType}) {
  const {appliesTo} = entry;
  if(typeof appliesTo === 'function') {
    return appliesTo({payload, kind, mediaType}) === true;
  }
  return appliesTo.some(matcher =>
    (matcher.kind === undefined || matcher.kind === kind) &&
    (matcher.mediaType === undefined || matcher.mediaType === mediaType));
}
