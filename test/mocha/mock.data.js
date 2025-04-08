/*!
* Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
*/
import {config} from '@bedrock/core';

export const mockData = {};

// mock product IDs and reverse lookup for service products
mockData.productIdMap = new Map([
  // edv service
  ['edv', 'urn:uuid:dbd15f08-ff67-11eb-893b-10bf48838a41'],
  ['urn:uuid:dbd15f08-ff67-11eb-893b-10bf48838a41', 'edv'],
  // vc-verifier service
  ['vc-verifier', 'urn:uuid:66aad4d0-8ac1-11ec-856f-10bf48838a41'],
  ['urn:uuid:66aad4d0-8ac1-11ec-856f-10bf48838a41', 'vc-verifier'],
  // webkms service
  ['webkms', 'urn:uuid:80a82316-e8c2-11eb-9570-10bf48838a41'],
  ['urn:uuid:80a82316-e8c2-11eb-9570-10bf48838a41', 'webkms']
]);

mockData.baseUrl = config.server.baseUri;

// OpenID discovery server meta data example:
// https://accounts.google.com/.well-known/openid-configuration

// `jwks_uri` example w/RSA keys:
// https://www.googleapis.com/oauth2/v3/certs

// minimal example open ID config for testing
mockData.oauth2IssuerConfigRoute = '/.well-known/oauth-authorization-server';
mockData.oauth2Config = {
  issuer: mockData.baseUrl,
  jwks_uri: `${mockData.baseUrl}/oauth2/jwks`
};

// Ed25519 and EC keys
mockData.ed25519KeyPair = {
  kid: '-iHGX4KWRiuX0aa3sAnhKTw7utzGI2el7HVI4LCFiJg',
  kty: 'OKP',
  crv: 'Ed25519',
  d: 'ANQCyJz3mHyJGYzvAwHlUa4pHzfMhJWSHvadUYTi7Hg',
  x: '-iHGX4KWRiuX0aa3sAnhKTw7utzGI2el7HVI4LCFiJg'
};

mockData.jwks = {
  // Ed25519 public key matches full key pair above
  keys: [{
    kid: '-iHGX4KWRiuX0aa3sAnhKTw7utzGI2el7HVI4LCFiJg',
    kty: 'OKP',
    crv: 'Ed25519',
    //d: 'ANQCyJz3mHyJGYzvAwHlUa4pHzfMhJWSHvadUYTi7Hg',
    x: '-iHGX4KWRiuX0aa3sAnhKTw7utzGI2el7HVI4LCFiJg',
    key_ops: ['verify']
  }, {
    kid: 'H6hWVHmpAG6mnCW6_Up2EYYZu-98-MK298t4LLsqGSM',
    kty: 'EC',
    crv: 'P-256',
    x: 'H6hWVHmpAG6mnCW6_Up2EYYZu-98-MK298t4LLsqGSM',
    y: 'iU2niSRdN77sFhdRvTifg4hcy4AmfsDSOND0_RHhcIU',
    //d: '25f2jge6YltyS3kdXHsm3tEEbkj_fdyC6ODJAfjgem4',
    use: 'sig'
  }, {
    kid: 'uApgIU7jCc8QRcm1iJR7AuYOCGVsTuY--6jvYCNsrY6naQ2TJETabttQSI33Tg5_',
    kty: 'EC',
    crv: 'P-384',
    x: 'uApgIU7jCc8QRcm1iJR7AuYOCGVsTuY--6jvYCNsrY6naQ2TJETabttQSI33Tg5_',
    y: 'rnavIz5-cIeuJDYzX-E4vwLRo7g2z96KBcGMaQ0V2KMvS-q8e2sZmLfL-O0kZf6v',
    //d: 'BK5RZ_7qm2JhoNAfXxW-Ka6PbAJTUaK7f2Xm-c8jBkk3dpFi2d15gl_nPHnX4Nfg',
    key_ops: ['verify']
  }]
};

// eslint-disable-next-line max-len
const pdf417String = '@\n\x1e\rANSI 000000090002DL00410234ZZ02750202DLDAQF987654321\nDCSSMITH\nDDEN\nDACJOHN\nDDFN\nDADNONE\nDDGN\nDCAC\nDCBNONE\nDCDNONE\nDBD01012024\nDBB04191988\nDBA04192030\nDBC1\nDAU069 IN\nDAYBRO\nDAG123 MAIN ST\nDAIANYVILLE\nDAJUTO\nDAKF87P20000  \nDCFUTODOCDISCRIM\nDCGUTO\nDAW158\nDCK1234567890\nDDAN\rZZZZA2QZkpgGDGYAAGYABGYACGJ2CGHYYpBi4oxicGKYYzhiyGNAa5ZIggRi6ohicGKAYqER1ggAgGL4YqhjApRicGGwY1gQY4BjmGOJYQXq3wuVrSeLM5iGEziaBjhWosXMWRAG107uT_9bSteuPasCXFQKuPdSdF-xmUoFkA0yRJoW4ERvATNyewT263ZHMGOQYrA==\r';

mockData.vcbs = {
  pdf417: pdf417String,
  // eslint-disable-next-line max-len
  qr_code: 'VC1-RSJRPWCR803A3P0098G3A3-B02-J743853U53KGK0XJ6MKJ1OI0M.FO053.33963DN04$RAQS+4SMC8C3KM7VX4VAPL9%EILI:I1O$D:23%GJ0OUCPS0H8D2FB9D5G00U39.PXG49%SOGGB*K$Z6%GUSCLWEJ8%B95MOD0P NG-I:V8N63K53'
};
