/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
const sequence = {
  title: 'sequence',
  type: 'integer',
  minimum: 0,
  maximum: Number.MAX_SAFE_INTEGER - 1
};

export const contextBody = {
  title: 'JSON-LD Context Record',
  type: 'object',
  required: ['id', 'context'],
  additionalProperties: false,
  properties: {
    id: {
      title: 'Context ID',
      type: 'string'
    },
    context: {
      type: 'object',
      additionalProperties: true,
      required: ['@context'],
      properties: {
        '@context': {
          title: '@context',
          anyOf: [{
            type: 'string'
          }, {
            type: 'object'
          }, {
            type: 'array',
            minItems: 1,
            items: {
              type: ['string', 'object']
            }
          }]
        }
      }
    }
  }
};
export const createContextBody = {
  ...contextBody,
  title: 'createContextBody'
};

export const updateContextBody = {
  ...contextBody,
  required: ['id', 'context', 'sequence'],
  properties: {
    ...contextBody.properties,
    sequence
  },
  title: 'updateContextBody'
};
