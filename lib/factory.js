/*!
 * Copyright (c) 2024 European EPC Competence Center GmbH. All rights reserved.
 */

import {webcrypto} from './crypto.js';

/**
 * Creates a signer function for RSA-PSS signing.
 *
 * @param {object} options - Options hash.
 * @param {string} options.id - The key ID.
 * @param {CryptoKey} options.secretKey - The secret key.
 *
 * @returns {Function} The signer function.
 */
export function createSigner({id, secretKey} = {}) {
  if(!id || typeof id !== 'string') {
    throw new TypeError('"id" must be a non-empty string.');
  }
  if(!secretKey) {
    throw new TypeError('"secretKey" is required.');
  }

  // Get modulus length from secret key algorithm
  const modulusLength = secretKey.algorithm?.modulusLength || 4096;
  
  return {
    algorithm: 'PS256', // RSA-PSS with SHA-256
    id,
    async sign({data} = {}) {
      if(!data) {
        throw new TypeError('"data" is required.');
      }
      // Handle both string (JWT) and Uint8Array (Data Integrity) signing
      let dataToSign;
      if(typeof data === 'string') {
        // For JWT, data is already the signing input (header.payload)
        // Sign the string directly as UTF-8 bytes
        dataToSign = new TextEncoder().encode(data);
      } else if(data instanceof Uint8Array) {
        // For Data Integrity, sign the raw bytes
        dataToSign = data;
      } else {
        throw new TypeError('"data" must be a string or Uint8Array.');
      }

      // Sign using RSA-PSS with SHA-256
      const signature = await webcrypto.subtle.sign(
        {
          name: 'RSA-PSS',
          saltLength: 32, // SHA-256 hash length
        },
        secretKey,
        dataToSign
      );

      return new Uint8Array(signature);
    }
  };
}

/**
 * Creates a verifier function for RSA-PSS verification.
 *
 * @param {object} options - Options hash.
 * @param {string} options.id - The key ID.
 * @param {CryptoKey} options.publicKey - The public key.
 *
 * @returns {Function} The verifier function.
 */
export function createVerifier({id, publicKey} = {}) {
  if(!id || typeof id !== 'string') {
    throw new TypeError('"id" must be a non-empty string.');
  }
  if(!publicKey) {
    throw new TypeError('"publicKey" is required.');
  }

  // Get modulus length from public key algorithm
  const modulusLength = publicKey.algorithm?.modulusLength || 4096;
  
  return {
    algorithm: 'PS256', // RSA-PSS with SHA-256
    id,
    async verify({data, signature} = {}) {
      if(!data) {
        throw new TypeError('"data" is required.');
      }
      if(!signature) {
        throw new TypeError('"signature" is required.');
      }

      let dataToVerify;
      if(typeof data === 'string') {
        // For JWT, data is the signing input (header.payload)
        // Verify the string directly as UTF-8 bytes
        dataToVerify = new TextEncoder().encode(data);
      } else if(data instanceof Uint8Array) {
        // For Data Integrity, verify the raw bytes
        dataToVerify = data;
      } else {
        throw new TypeError('"data" must be a string or Uint8Array.');
      }

      if(!(signature instanceof Uint8Array)) {
        throw new TypeError('"signature" must be a Uint8Array.');
      }

      try {
        // Verify using RSA-PSS with SHA-256
        const isValid = await webcrypto.subtle.verify(
          {
            name: 'RSA-PSS',
            saltLength: 32, // SHA-256 hash length
          },
          publicKey,
          signature,
          dataToVerify
        );
        return isValid;
      } catch(e) {
        // Verification failed
        return false;
      }
    }
  };
}

