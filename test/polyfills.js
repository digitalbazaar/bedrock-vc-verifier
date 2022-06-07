// WebCrypto polyfill if needed
import crypto from 'node:crypto';
import webcrypto from 'isomorphic-webcrypto';

if(!crypto.webcrypto) {
  crypto.webcrypto = webcrypto;
}

