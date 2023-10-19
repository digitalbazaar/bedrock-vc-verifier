/*!
 * Copyright (c) 2023 Digital Bazaar, Inc. All rights reserved.
 */
const SUPPORTED_ECDSA_KEY_TYPES = new Map([
  ['zDna', 'P-256'],
  ['z82L', 'P-384']
]);

export function getEcdsaKeyTypes({credential, presentation} = {}) {
  let vc = presentation ? presentation.verifiableCredential : credential;
  vc = Array.isArray(vc) ? vc : [vc];
  const ecdsaKeyTypes = [];
  vc.forEach(credential => {
    const proofs = Array.isArray(credential.proof) ? credential.proof :
      [credential.proof];
    for(const proof of proofs) {
      if(proof.cryptosuite === 'ecdsa-2019') {
        const {verificationMethod} = proof;
        const multibaseMultikeyHeader =
          verificationMethod.substring('did:key:'.length).slice(0, 4);
        const ecdsaKeyType =
          SUPPORTED_ECDSA_KEY_TYPES.get(multibaseMultikeyHeader);
        if(!ecdsaKeyTypes.includes(ecdsaKeyType)) {
          ecdsaKeyTypes.push(ecdsaKeyType);
        }
      }
    }
  });
  return ecdsaKeyTypes;
}
