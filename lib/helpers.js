/*!
 * Copyright (c) 2024 European EPC Competence Center GmbH. All rights reserved.
 */

/**
 * Gets the size of an RSA secret key in bytes based on modulus length.
 * For RSA, the secret key size is the same as the modulus length in bits / 8.
 *
 * @param {object} options - Options hash.
 * @param {number} options.modulusLength - The RSA modulus length in bits.
 *
 * @returns {number} The secret key size in bytes.
 */
export function getSecretKeySize({modulusLength}) {
  if(typeof modulusLength !== 'number') {
    throw new TypeError('"modulusLength" must be a number.');
  }
  // RSA secret key size is the modulus length in bytes
  return modulusLength / 8;
}

/**
 * Gets the modulus length from a JWK.
 *
 * @param {object} jwk - The JWK.
 *
 * @returns {number} The modulus length in bits.
 */
export function getModulusLengthFromJwk(jwk) {
  if(!jwk || !jwk.n) {
    throw new TypeError('"jwk" must have an "n" property.');
  }
  // The modulus n is base64url encoded, so we need to decode it
  // to get the byte length, then multiply by 8 to get bits
  const nBytes = Buffer.from(jwk.n, 'base64url').length;
  return nBytes * 8;
}

