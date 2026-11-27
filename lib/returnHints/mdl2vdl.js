/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import * as bedrock from '@bedrock/core';
import {parse} from '@auth0/mdl';
import {registerReturnHint} from '../returnHints.js';

const {util: {BedrockError}} = bedrock;

/* The `mdl2vdl` return hint maps a verified mdoc mDL to an unsigned vDL
(`Iso18013DriversLicenseCredential`), a JSON-LD view of the same data. The
vDL is not signed; it is returned only because the mdoc was verified. */

export const HINT = 'mdl2vdl';

const VC_CONTEXT_2 = 'https://www.w3.org/ns/credentials/v2';
const VDL_CONTEXT = 'https://w3id.org/vdl/v1';
const VDL_AAMVA_CONTEXT = 'https://w3id.org/vdl/aamva/v1';

const MDL_NAMESPACE = 'org.iso.18013.5.1';
const AAMVA_NAMESPACE = `${MDL_NAMESPACE}.aamva`;
const MDOC_TYPE_MDL = `${MDL_NAMESPACE}.mDL`;

// mdoc data elements in the `org.iso.18013.5.1` namespace that the vDL
// context defines; other elements are dropped, as an undefined term would
// fail JSON-LD processing
const ISO_TERMS = new Set([
  'administrative_number', 'age_birth_year', 'age_in_years', 'age_over_18',
  'age_over_21', 'age_over_25', 'age_over_62', 'age_over_65', 'birth_date',
  'birth_place', 'document_number', 'driving_privileges', 'expiry_date',
  'eye_colour', 'family_name', 'family_name_national_character', 'given_name',
  'given_name_national_character', 'hair_colour', 'height', 'issue_date',
  'issuing_authority', 'issuing_country', 'issuing_jurisdiction',
  'nationality', 'portrait', 'portrait_capture_date', 'resident_address',
  'resident_city', 'resident_country', 'resident_postal_code',
  'resident_state', 'sex', 'signature_usual_mark', 'un_distinguishing_sign',
  'weight'
]);

// mdoc data elements in the `org.iso.18013.5.1.aamva` namespace, mapped to
// the terms the vDL AAMVA context defines for them; other elements are dropped
const AAMVA_TERMS = new Map([
  ['aka_family_name.v2', 'aamva_aka_family_name_v2'],
  ['aka_given_name.v2', 'aamva_aka_given_name_v2'],
  ['aka_suffix', 'aamva_aka_suffix'],
  ['CDL_indicator', 'aamva_cdl_indicator'],
  ['DHS_compliance', 'aamva_dhs_compliance'],
  ['DHS_compliance_text', 'aamva_dhs_compliance_text'],
  ['DHS_temporary_lawful_status', 'aamva_dhs_temporary_lawful_status'],
  ['domestic_driving_privileges', 'aamva_domestic_driving_privileges'],
  ['EDL_credential', 'aamva_edl_credential'],
  ['family_name_truncation', 'aamva_family_name_truncation'],
  ['given_name_truncation', 'aamva_given_name_truncation'],
  ['hazmat_endorsement_expiration_date',
    'aamva_hazmat_endorsement_expiration_date'],
  ['name_suffix', 'aamva_name_suffix'],
  ['organ_donor', 'aamva_organ_donor'],
  ['race_ethnicity', 'aamva_race_ethnicity'],
  ['resident_county', 'aamva_resident_county'],
  ['sex', 'aamva_sex'],
  ['veteran', 'aamva_veteran'],
  ['weight_range', 'aamva_weight_range']
]);

// vDL terms typed `xsd:dateTime` whose mdoc values may be date-only
const DATE_TIME_TERMS = new Set([
  'birth_date', 'issue_date', 'expiry_date', 'portrait_capture_date',
  'aamva_hazmat_endorsement_expiration_date'
]);

// vDL terms typed `@id` whose mdoc values are image bytes
const IMAGE_TERMS = new Set(['portrait', 'signature_usual_mark']);

const DATE_ONLY = /^\d{4}-\d{2}-\d{2}$/;

// JWK members WebCrypto adds on export that do not describe the key itself
const JWK_METADATA = new Set(['alg', 'ext', 'key_ops', 'use']);

registerReturnHint({
  hint: HINT,
  // mdoc envelopes, whether sent as a credential or a presentation
  appliesTo: [
    {mediaType: 'application/mdoc'},
    {mediaType: 'application/mdl-vp-token'}
  ],
  map: mdl2vdl
});

/**
 * Maps an enveloped mdoc mDL to an unsigned vDL.
 *
 * @param {object} options - Options.
 * @param {object} options.payload - The `EnvelopedVerifiableCredential` or
 *   `EnvelopedVerifiablePresentation` holding the mdoc device response.
 * @param {string} options.kind - `credential` or `presentation`.
 *
 * @returns {Promise<object>} The vDL, or for a presentation, a
 *   `VerifiablePresentation` whose `verifiableCredential` is the vDL.
 */
export async function mdl2vdl({payload, kind} = {}) {
  const document = _getMdlDocument({payload});
  const credential = await _createVdl({document});
  if(kind === 'presentation') {
    return {
      '@context': [VC_CONTEXT_2],
      type: ['VerifiablePresentation'],
      verifiableCredential: [credential]
    };
  }
  return credential;
}

function _getMdlDocument({payload}) {
  const {mediaType, parameters, contents} = _parseDataUrl({url: payload?.id});
  // `application/mdoc` may be base64-encoded; otherwise the device response
  // is base64url-encoded, as in the verifier's envelope handling
  let encoding;
  if(mediaType === 'application/mdoc' && parameters.includes('base64')) {
    encoding = 'base64';
  } else if(!parameters.includes('base64')) {
    encoding = 'base64url';
  } else {
    _throwNotSupported(`Unknown mdoc envelope format "${mediaType}".`);
  }

  let mdoc;
  try {
    mdoc = parse(Buffer.from(contents, encoding));
  } catch {
    _throwNotSupported('The mdoc device response could not be parsed.');
  }
  const {documents = []} = mdoc;
  if(!(documents.length === 1 && documents[0].docType === MDOC_TYPE_MDL)) {
    _throwNotSupported(
      `Only a single "${MDOC_TYPE_MDL}" document can be mapped to a vDL.`);
  }
  return documents[0];
}

async function _createVdl({document}) {
  const {issuerAuth} = document.issuerSigned;
  const {validityInfo} = issuerAuth.decodedPayload;
  const namespaces = document.issuerSignedNameSpaces;

  const driversLicense = {type: 'Iso18013DriversLicense'};
  if(namespaces.includes(MDL_NAMESPACE)) {
    const elements = document.getIssuerNameSpace(MDL_NAMESPACE);
    for(const [name, value] of Object.entries(elements)) {
      if(ISO_TERMS.has(name)) {
        _setTerm({driversLicense, term: name, value});
      }
    }
  }
  if(namespaces.includes(AAMVA_NAMESPACE)) {
    const elements = document.getIssuerNameSpace(AAMVA_NAMESPACE);
    for(const [name, value] of Object.entries(elements)) {
      const term = AAMVA_TERMS.get(name);
      if(term) {
        _setTerm({driversLicense, term, value});
      }
    }
  }

  const {certificate} = issuerAuth;
  const issuer = {id: await _getIssuerDid({certificate})};
  const name = certificate.subjectName.getField('CN')?.[0] ??
    driversLicense.issuing_authority;
  if(name !== undefined) {
    issuer.name = name;
  }

  return {
    '@context': [VC_CONTEXT_2, VDL_CONTEXT, VDL_AAMVA_CONTEXT],
    type: ['VerifiableCredential', 'Iso18013DriversLicenseCredential'],
    name: 'Mobile Driver\'s License',
    description: 'A license granting driving privileges.',
    issuer,
    validFrom: _toDateTime({value: validityInfo.validFrom}),
    validUntil: _toDateTime({value: validityInfo.validUntil}),
    credentialSubject: {
      type: 'LicensedDriver',
      driversLicense
    }
  };
}

// the issuer is identified by a `did:jwk` for its certificate's public key
async function _getIssuerDid({certificate}) {
  const publicKey = await certificate.publicKey.export();
  const jwk = await globalThis.crypto.subtle.exportKey('jwk', publicKey);
  // keep only the key members, not WebCrypto's usage metadata, in
  // lexicographic order, so the same key always gives the same DID
  const publicJwk = Object.fromEntries(Object.entries(jwk)
    .filter(([k]) => !JWK_METADATA.has(k))
    .sort(([a], [b]) => a < b ? -1 : 1));
  const encoded = Buffer.from(JSON.stringify(publicJwk)).toString('base64url');
  return `did:jwk:${encoded}`;
}

// set a vDL term from an mdoc value; a value with no JSON form is left out
function _setTerm({driversLicense, term, value}) {
  const termValue = _toTermValue({term, value});
  if(termValue !== undefined) {
    driversLicense[term] = termValue;
  }
}

function _toTermValue({term, value}) {
  if(DATE_TIME_TERMS.has(term)) {
    return _toDateTime({value});
  }
  if(IMAGE_TERMS.has(term)) {
    // an image term is an `@id`, so only image bytes, as a `data:` URL, are
    // kept; any other value is left out
    return value instanceof Uint8Array ?
      _toImageDataUrl({bytes: value}) : undefined;
  }
  return _toJson({value});
}

// The vDL context types the date terms as `xsd:dateTime`, but the mdoc holds
// several of them, such as `birth_date`, as date-only values. A date-only
// value is given as midnight UTC, `YYYY-MM-DDT00:00:00Z`; that time and zone
// are not in the source data. A full date-time is kept, without milliseconds.
function _toDateTime({value}) {
  if(_isDateOnly({value})) {
    return `${value.toISOString()}T00:00:00Z`;
  }
  if(value instanceof Date) {
    return value.toISOString().replace(/\.\d+Z$/, 'Z');
  }
  if(typeof value === 'string' && DATE_ONLY.test(value)) {
    return `${value}T00:00:00Z`;
  }
  return _toJson({value});
}

function _toImageDataUrl({bytes}) {
  let mediaType = 'application/octet-stream';
  if(bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) {
    mediaType = 'image/jpeg';
  } else if(bytes[4] === 0x6a && bytes[5] === 0x50 &&
    bytes[6] === 0x20 && bytes[7] === 0x20) {
    // JPEG 2000 file signature box (`jP  `)
    mediaType = 'image/jp2';
  } else if(bytes[0] === 0xff && bytes[1] === 0x4f &&
    bytes[2] === 0xff && bytes[3] === 0x51) {
    // JPEG 2000 codestream (SOC and SIZ markers), without the file format
    mediaType = 'image/j2c';
  }
  return `data:${mediaType};base64,${Buffer.from(bytes).toString('base64')}`;
}

// Convert a decoded CBOR value to JSON; values of `@json` terms, such as
// `driving_privileges`, keep date-only values as `YYYY-MM-DD`. CBOR can hold
// values JSON can't: an integer beyond 2^53, which is decoded as a `BigInt`,
// becomes a decimal string; a `Set` becomes an array; a typed array becomes
// base64. Any other non-JSON value, such as an unknown
// CBOR tag, has no JSON form and is left out (`undefined`).
function _toJson({value}) {
  if(value === null || typeof value === 'string' ||
    typeof value === 'boolean') {
    return value;
  }
  if(typeof value === 'number') {
    return Number.isFinite(value) ? value : undefined;
  }
  if(typeof value === 'bigint') {
    return value.toString();
  }
  if(_isDateOnly({value})) {
    return value.toISOString();
  }
  if(value instanceof Date) {
    return value.toISOString().replace(/\.\d+Z$/, 'Z');
  }
  if(ArrayBuffer.isView(value)) {
    return Buffer.from(value.buffer, value.byteOffset, value.byteLength)
      .toString('base64');
  }
  if(value instanceof Map) {
    const entries = [...value]
      .map(([k, v]) => [String(k), _toJson({value: v})])
      .filter(([, v]) => v !== undefined);
    return Object.fromEntries(entries);
  }
  if(Array.isArray(value) || value instanceof Set) {
    return [...value].map(v => _toJson({value: v}))
      .filter(v => v !== undefined);
  }
  return undefined;
}

// `@auth0/mdl` decodes a CBOR full-date as a `DateOnly`, a `Date` subclass
// whose `toISOString()` gives `YYYY-MM-DD`
function _isDateOnly({value}) {
  return Object.prototype.toString.call(value) === '[object DateOnly]';
}

function _parseDataUrl({url}) {
  const comma = typeof url === 'string' ? url.indexOf(',') : -1;
  if(!(url?.startsWith('data:') && comma !== -1)) {
    _throwNotSupported('The payload is not an mdoc envelope.');
  }
  const [mediaType, ...parameters] = url.slice('data:'.length, comma)
    .split(';');
  return {mediaType, parameters, contents: url.slice(comma + 1)};
}

function _throwNotSupported(message) {
  throw new BedrockError(message, {
    name: 'NotSupportedError',
    details: {httpStatusCode: 400, public: true}
  });
}
