/*!
 * Copyright (c) 2022-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {schemas} from '@bedrock/validation';

const VC_CONTEXT_1 = 'https://www.w3.org/2018/credentials/v1';
const VC_CONTEXT_2 = 'https://www.w3.org/ns/credentials/v2';

const vcContext = {
  type: 'array',
  minItems: 1,
  // the first context must be the VC context
  items: [{
    oneOf: [{
      const: VC_CONTEXT_1
    }, {
      const: VC_CONTEXT_2
    }]
  }],
  // additional contexts maybe strings or objects
  additionalItems: {
    anyOf: [{type: 'string'}, {type: 'object'}]
  }
};

function idOrObjectWithId() {
  return {
    title: 'identifier or an object with an id',
    anyOf: [
      schemas.identifier(),
      {
        type: 'object',
        required: ['id'],
        additionalProperties: true,
        properties: {id: schemas.identifier()}
      }
    ]
  };
}

function verifiableCredential() {
  return {
    title: 'Verifiable Credential',
    type: 'object',
    required: [
      '@context',
      'credentialSubject',
      'issuer',
      'type'
    ],
    additionalProperties: true,
    properties: {
      '@context': vcContext,
      credentialSubject: {
        anyOf: [
          {type: 'object'},
          {type: 'array', minItems: 1, items: {type: 'object'}}
        ]
      },
      id: {
        type: 'string'
      },
      issuer: idOrObjectWithId(),
      type: {
        type: 'array',
        minItems: 1,
        // this first type must be VerifiableCredential
        items: [
          {const: 'VerifiableCredential'},
        ],
        // additional types must be strings
        additionalItems: {
          type: 'string'
        }
      },
      proof: schemas.proof()
    }
  };
}

const envelopedVerifiableCredential = {
  title: 'Enveloped Verifiable Credential',
  type: 'object',
  additionalProperties: false,
  required: ['@context', 'id', 'type'],
  properties: {
    '@context': {
      anyOf: [{
        const: VC_CONTEXT_2
      }, {
        type: 'array',
        minItems: 1,
        maxItems: 1,
        // the first context must be the VC context
        items: [{
          const: VC_CONTEXT_2
        }]
      }]
    },
    id: {
      type: 'string'
    },
    type: {
      const: 'EnvelopedVerifiableCredential'
    }
  }
};

export function verifiablePresentation() {
  return {
    title: 'Verifiable Presentation',
    type: 'object',
    required: ['@context', 'type'],
    additionalProperties: true,
    properties: {
      '@context': vcContext,
      id: {
        type: 'string'
      },
      type: {
        type: 'array',
        minItems: 1,
        // this first type must be VerifiablePresentation
        items: [
          {const: 'VerifiablePresentation'},
        ],
        // additional types must be strings
        additionalItems: {
          type: 'string'
        }
      },
      verifiableCredential: {
        anyOf: [
          verifiableCredential(),
          envelopedVerifiableCredential, {
            type: 'array',
            minItems: 1,
            items: {
              anyOf: [verifiableCredential(), envelopedVerifiableCredential]
            }
          }
        ]
      },
      holder: idOrObjectWithId(),
      proof: schemas.proof()
    }
  };
}

const envelopedVerifiablePresentation = {
  title: 'Enveloped Verifiable Presentation',
  type: 'object',
  additionalProperties: false,
  required: ['@context', 'id', 'type'],
  properties: {
    '@context': {
      anyOf: [{
        const: VC_CONTEXT_2
      }, {
        type: 'array',
        minItems: 1,
        maxItems: 1,
        // the first context must be the VC context
        items: [{
          const: VC_CONTEXT_2
        }]
      }]
    },
    id: {
      type: 'string'
    },
    type: {
      const: 'EnvelopedVerifiablePresentation'
    }
  }
};

export const verifyOptions = {
  title: 'Verify Options',
  type: 'object',
  oneOf: [{
    required: ['didResolver']
  }, {
    required: ['documentLoader']
  }],
  additionalProperties: false,
  properties: {
    didResolver: {
      title: 'DID Resolver',
      type: 'object',
      required: ['url'],
      additionalProperties: false,
      properties: {
        url: {
          type: 'string',
          pattern: '^https://[^.]+.[^.]+'
        }
      }
    },
    documentLoader: {
      title: 'Document Loader',
      type: 'object',
      required: ['allowRemoteContexts'],
      additionalProperties: false,
      properties: {
        allowRemoteContexts: {
          type: 'boolean'
        }
      }
    }
  }
};

export const createChallengeBody = {
  title: 'Create Challenge Body',
  type: 'object',
  additionalProperties: false,
  // body must be empty
  properties: {}
};

export function verifyCredentialBody() {
  return {
    title: 'Verify Credential Body',
    type: 'object',
    required: ['verifiableCredential'],
    additionalProperties: false,
    properties: {
      options: {
        type: 'object'
      },
      verifiableCredential: {
        anyOf: [
          verifiableCredential(),
          envelopedVerifiableCredential
        ]
      }
    }
  };
}

export function verifyPresentationBody() {
  return {
    title: 'Verify Presentation Body',
    type: 'object',
    required: ['verifiablePresentation'],
    additionalProperties: false,
    properties: {
      options: {
        type: 'object'
      },
      verifiablePresentation: {
        anyOf: [
          verifiablePresentation(),
          envelopedVerifiablePresentation
        ]
      }
    }
  };
}
