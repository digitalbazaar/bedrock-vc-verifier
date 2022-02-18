/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
const context = {
  title: '@context',
  type: 'array',
  minItems: 1,
  items: {
    type: ['string', 'object']
  }
};

export const createChallengeBody = {
  title: 'Create Challenge Body',
  type: 'object',
  additionalProperties: false,
  // body must be empty
  properties: {}
};

export const verifyCredentialBody = {
  title: 'Verify Credential Body',
  type: 'object',
  required: ['verifiableCredential'],
  additionalProperties: false,
  properties: {
    options: {
      type: 'object'
    },
    verifiableCredential: {
      type: 'object',
      additionalProperties: true,
      required: ['@context'],
      properties: {
        '@context': context
      }
    }
  }
};

export const verifyPresentationBody = {
  title: 'Verify Presentation Body',
  type: 'object',
  required: ['verifiablePresentation'],
  additionalProperties: false,
  properties: {
    options: {
      type: 'object'
    },
    verifiablePresentation: {
      type: 'object',
      additionalProperties: true,
      required: ['@context'],
      properties: {
        '@context': context
      }
    }
  }
};
