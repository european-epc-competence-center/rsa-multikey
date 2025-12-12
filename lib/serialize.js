/*!
 * Copyright (c) 2024 European EPC Competence Center GmbH. All rights reserved.
 */

import {webcrypto} from './crypto.js';
import {base58btc} from 'multiformats/bases/base58';
import {getModulusLengthFromJwk} from './helpers.js';
import {CryptoKey} from './crypto.js';

/**
 * Converts a JWK to public key bytes (DER-encoded SPKI).
 *
 * @param {object} options - Options hash.
 * @param {object} options.jwk - The JWK to convert.
 *
 * @returns {Uint8Array} The public key bytes.
 */
export async function toPublicKeyBytes({jwk} = {}) {
  if(!jwk || typeof jwk !== 'object') {
    throw new TypeError('"jwk" must be an object.');
  }
  const publicKey = await webcrypto.subtle.importKey(
    'jwk',
    jwk,
    {
      name: 'RSA-PSS',
      hash: 'SHA-256',
    },
    true,
    ['verify']
  );
  const exported = await webcrypto.subtle.exportKey('spki', publicKey);
  return new Uint8Array(exported);
}

/**
 * Converts a JWK to secret key bytes (DER-encoded PKCS#8).
 *
 * @param {object} options - Options hash.
 * @param {object} options.jwk - The JWK to convert.
 *
 * @returns {Uint8Array} The secret key bytes.
 */
export async function toSecretKeyBytes({jwk} = {}) {
  if(!jwk || typeof jwk !== 'object') {
    throw new TypeError('"jwk" must be an object.');
  }
  if(!jwk.d) {
    throw new Error('JWK does not contain a private key.');
  }
  const privateKey = await webcrypto.subtle.importKey(
    'jwk',
    jwk,
    {
      name: 'RSA-PSS',
      hash: 'SHA-256',
    },
    true,
    ['sign']
  );
  const exported = await webcrypto.subtle.exportKey('pkcs8', privateKey);
  return new Uint8Array(exported);
}

/**
 * Converts public key bytes to multibase format.
 *
 * @param {object} options - Options hash.
 * @param {Uint8Array} options.publicKeyBytes - The public key bytes.
 *
 * @returns {string} The multibase-encoded public key.
 */
export function toPublicKeyMultibase({publicKeyBytes} = {}) {
  if(!(publicKeyBytes instanceof Uint8Array)) {
    throw new TypeError('"publicKeyBytes" must be a Uint8Array.');
  }
  // base58btc.encode already includes the 'z' prefix
  return base58btc.encode(publicKeyBytes);
}

/**
 * Converts secret key bytes to multibase format.
 *
 * @param {object} options - Options hash.
 * @param {Uint8Array} options.secretKeyBytes - The secret key bytes.
 *
 * @returns {string} The multibase-encoded secret key.
 */
export function toSecretKeyMultibase({secretKeyBytes} = {}) {
  if(!(secretKeyBytes instanceof Uint8Array)) {
    throw new TypeError('"secretKeyBytes" must be a Uint8Array.');
  }
  // base58btc.encode already includes the 'z' prefix
  return base58btc.encode(secretKeyBytes);
}

/**
 * Converts a JWK to public key multibase.
 *
 * @param {object} options - Options hash.
 * @param {object} options.jwk - The JWK to convert.
 *
 * @returns {string} The multibase-encoded public key.
 */
export async function toPublicKeyMultibaseFromJwk({jwk} = {}) {
  // Extract only public key fields for conversion
  const publicJwk = {
    kty: jwk.kty,
    n: jwk.n,
    e: jwk.e,
    alg: jwk.alg
  };
  const publicKeyBytes = await toPublicKeyBytes({jwk: publicJwk});
  return toPublicKeyMultibase({publicKeyBytes});
}

/**
 * Converts a JWK to secret key multibase.
 *
 * @param {object} options - Options hash.
 * @param {object} options.jwk - The JWK to convert.
 *
 * @returns {string} The multibase-encoded secret key.
 */
export async function toSecretKeyMultibaseFromJwk({jwk} = {}) {
  const secretKeyBytes = await toSecretKeyBytes({jwk});
  return toSecretKeyMultibase({secretKeyBytes});
}

/**
 * Converts multibase-encoded public key to bytes.
 *
 * @param {object} options - Options hash.
 * @param {string} options.publicKeyMultibase - The multibase-encoded public key.
 *
 * @returns {Uint8Array} The public key bytes.
 */
export function fromPublicKeyMultibase({publicKeyMultibase} = {}) {
  if(typeof publicKeyMultibase !== 'string') {
    throw new TypeError('"publicKeyMultibase" must be a string.');
  }
  // base58btc.decode handles the 'z' prefix automatically
  return base58btc.decode(publicKeyMultibase);
}

/**
 * Converts multibase-encoded secret key to bytes.
 *
 * @param {object} options - Options hash.
 * @param {string} options.secretKeyMultibase - The multibase-encoded secret key.
 *
 * @returns {Uint8Array} The secret key bytes.
 */
export function fromSecretKeyMultibase({secretKeyMultibase} = {}) {
  if(typeof secretKeyMultibase !== 'string') {
    throw new TypeError('"secretKeyMultibase" must be a string.');
  }
  // base58btc.decode handles the 'z' prefix automatically
  return base58btc.decode(secretKeyMultibase);
}

/**
 * Creates a CryptoKey from raw key bytes.
 *
 * @param {object} options - Options hash.
 * @param {number} options.modulusLength - The RSA modulus length.
 * @param {Uint8Array} [options.secretKey] - The secret key bytes (PKCS#8).
 * @param {Uint8Array} options.publicKey - The public key bytes (SPKI).
 * @param {boolean} [options.keyAgreement=false] - Whether this is for key agreement.
 *
 * @returns {Promise<CryptoKey>} The CryptoKey.
 */
export async function cryptoKeyfromRaw({
  modulusLength,
  secretKey,
  publicKey,
  keyAgreement = false
} = {}) {
  if(typeof modulusLength !== 'number') {
    throw new TypeError('"modulusLength" must be a number.');
  }
  if(!(publicKey instanceof Uint8Array)) {
    throw new TypeError('"publicKey" must be a Uint8Array.');
  }
  if(secretKey && !(secretKey instanceof Uint8Array)) {
    throw new TypeError('"secretKey" must be a Uint8Array.');
  }

  const algorithm = {
    name: 'RSA-PSS',
    hash: 'SHA-256',
    modulusLength,
  };
  const usage = keyAgreement ? ['deriveBits'] : ['sign', 'verify'];

  if(secretKey) {
    const key = await webcrypto.subtle.importKey(
      'pkcs8',
      secretKey,
      algorithm,
      true,
      keyAgreement ? ['deriveBits'] : ['sign']
    );
    return key;
  }

  const key = await webcrypto.subtle.importKey(
    'spki',
    publicKey,
    algorithm,
    true,
    keyAgreement ? ['deriveBits'] : ['verify']
  );
  return key;
}

/**
 * Imports a key pair from multibase or JWK format.
 *
 * @param {object} keyPair - The key pair object.
 *
 * @returns {Promise<object>} The imported key pair with CryptoKey objects.
 */
export async function importKeyPair(keyPair) {
  if(!keyPair || typeof keyPair !== 'object') {
    throw new TypeError('"keyPair" must be an object.');
  }

  // If already has CryptoKey objects, return as-is
  if(keyPair.publicKey instanceof CryptoKey || 
     (keyPair.publicKey && keyPair.publicKey.algorithm)) {
    return keyPair;
  }

  // Try to import from JWK
  if(keyPair.publicKeyJwk) {
    const publicKey = await webcrypto.subtle.importKey(
      'jwk',
      keyPair.publicKeyJwk,
      {
        name: 'RSA-PSS',
        hash: 'SHA-256',
      },
      true,
      keyPair.keyAgreement ? ['deriveBits'] : ['verify']
    );
    const result = {
      ...keyPair,
      publicKey,
    };
    if(keyPair.secretKeyJwk || keyPair.privateKeyJwk) {
      const secretJwk = keyPair.secretKeyJwk || keyPair.privateKeyJwk;
      const secretKey = await webcrypto.subtle.importKey(
        'jwk',
        secretJwk,
        {
          name: 'RSA-PSS',
          hash: 'SHA-256',
        },
        true,
        keyPair.keyAgreement ? ['deriveBits'] : ['sign']
      );
      result.secretKey = secretKey;
    }
    return result;
  }

  // Try to import from multibase
  if(keyPair.publicKeyMultibase) {
    const publicKeyBytes = fromPublicKeyMultibase({
      publicKeyMultibase: keyPair.publicKeyMultibase
    });
    const modulusLength = keyPair.modulusLength || 4096;
    const publicKey = await cryptoKeyfromRaw({
      modulusLength,
      publicKey: publicKeyBytes,
      keyAgreement: keyPair.keyAgreement
    });
    const result = {
      ...keyPair,
      publicKey,
    };
    if(keyPair.secretKeyMultibase) {
      const secretKeyBytes = fromSecretKeyMultibase({
        secretKeyMultibase: keyPair.secretKeyMultibase
      });
      const secretKey = await cryptoKeyfromRaw({
        modulusLength,
        secretKey: secretKeyBytes,
        publicKey: publicKeyBytes,
        keyAgreement: keyPair.keyAgreement
      });
      result.secretKey = secretKey;
    }
    return result;
  }

  throw new Error('Key pair must have publicKeyJwk or publicKeyMultibase.');
}

/**
 * Exports a key pair to multibase or JWK format.
 *
 * @param {object} options - Options hash.
 * @param {object} options.keyPair - The key pair with CryptoKey objects.
 * @param {boolean} [options.publicKey=true] - Whether to export public key.
 * @param {boolean} [options.secretKey=false] - Whether to export secret key.
 * @param {boolean} [options.includeContext=true] - Whether to include @context.
 *
 * @returns {Promise<object>} The exported key pair.
 */
export async function exportKeyPair({
  keyPair,
  publicKey = true,
  secretKey = false,
  includeContext = true
} = {}) {
  if(!keyPair || typeof keyPair !== 'object') {
    throw new TypeError('"keyPair" must be an object.');
  }

  const result = {
    type: 'Multikey',
  };

  if(includeContext) {
    result['@context'] = 'https://w3id.org/security/multikey/v1';
  }

  if(keyPair.id) {
    result.id = keyPair.id;
  }
  if(keyPair.controller) {
    result.controller = keyPair.controller;
  }

  // Export public key
  if(publicKey && keyPair.publicKey) {
    const publicKeyJwk = await webcrypto.subtle.exportKey('jwk', keyPair.publicKey);
    const publicKeyBytes = await toPublicKeyBytes({jwk: publicKeyJwk});
    result.publicKeyMultibase = toPublicKeyMultibase({publicKeyBytes});
    result.publicKeyJwk = publicKeyJwk;
  }

  // Export secret key
  if(secretKey && keyPair.secretKey) {
    const secretKeyJwk = await webcrypto.subtle.exportKey('jwk', keyPair.secretKey);
    const secretKeyBytes = await toSecretKeyBytes({jwk: secretKeyJwk});
    result.secretKeyMultibase = toSecretKeyMultibase({secretKeyBytes});
    result.secretKeyJwk = secretKeyJwk;
  }

  return result;
}

