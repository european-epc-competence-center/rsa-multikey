/*!
 * Copyright (c) 2024 Digital Bazaar, Inc. All rights reserved.
 */
import {
  ALGORITHM,
  EXTRACTABLE,
  MULTIKEY_CONTEXT_V1_URL,
  DEFAULT_MODULUS_LENGTH
} from './constants.js';
import {CryptoKey, webcrypto} from './crypto.js';
import {createSigner, createVerifier} from './factory.js';
import {
  cryptoKeyfromRaw,
  exportKeyPair,
  importKeyPair,
  toPublicKeyBytes,
  toSecretKeyBytes,
  toPublicKeyMultibase,
  toSecretKeyMultibase,
  toPublicKeyMultibaseFromJwk,
  toSecretKeyMultibaseFromJwk
} from './serialize.js';
import {getModulusLengthFromJwk} from './helpers.js';
import {toMultikey} from './translators.js';

/**
 * Generates an RSA key pair for PS256 signing.
 *
 * @param {object} [options={}] - Options hash.
 * @param {string} [options.id] - Optional key ID.
 * @param {string} [options.controller] - Optional controller (DID).
 * @param {number} [options.modulusLength=4096] - RSA modulus length (2048, 3072, or 4096).
 *
 * @returns {Promise<object>} The generated key pair interface.
 */
export async function generate({
  id,
  controller,
  modulusLength = DEFAULT_MODULUS_LENGTH
} = {}) {
  if(modulusLength !== 2048 && modulusLength !== 3072 && modulusLength !== 4096) {
    throw new TypeError(
      '"modulusLength" must be one of: 2048, 3072, or 4096.');
  }

  const algorithm = {
    name: ALGORITHM,
    hash: 'SHA-256',
    modulusLength,
    publicExponent: new Uint8Array([1, 0, 1]) // 65537, standard RSA public exponent
  };
  const usage = ['sign', 'verify'];

  const keyPair = await webcrypto.subtle.generateKey(
    algorithm, EXTRACTABLE, usage);
  keyPair.secretKey = keyPair.privateKey;
  delete keyPair.privateKey;

  const keyPairInterface = await _createKeyPairInterface({
    keyPair,
    modulusLength
  });
  const exportedKeyPair = await keyPairInterface.export({publicKey: true});
  const {publicKeyMultibase} = exportedKeyPair;
  if(!id) {
    if(controller) {
      id = `${controller}#${publicKeyMultibase}`;
    } else {
      // Generate a default id if neither id nor controller is provided
      id = `#${publicKeyMultibase}`;
    }
  }
  keyPairInterface.id = id;
  keyPairInterface.controller = controller;
  keyPairInterface.modulusLength = modulusLength;
  return keyPairInterface;
}

/**
 * Imports an RSA key pair from JSON Multikey format.
 *
 * @param {object} key - The key object (Multikey format).
 * @param {object} [options={}] - Options hash.
 *
 * @returns {Promise<object>} The imported key pair interface.
 */
export async function from(key, options = {}) {
  let multikey = {...key};
  if(multikey.type !== 'Multikey') {
    // attempt loading from JWK if `publicKeyJwk` is present
    if(multikey.publicKeyJwk) {
      let id;
      let controller;
      if(multikey.type === 'JsonWebKey' || multikey.type === 'JsonWebKey2020') {
        ({id, controller} = multikey);
      }
      return fromJwk({
        jwk: multikey.publicKeyJwk,
        secretKey: !!multikey.secretKeyJwk || !!multikey.privateKeyJwk,
        id,
        controller
      });
    }
    if(multikey.type) {
      multikey = await toMultikey({keyPair: multikey});
      return _createKeyPairInterface({keyPair: multikey});
    }
  }
  if(!multikey.type) {
    multikey.type = 'Multikey';
  }
  if(!multikey['@context']) {
    multikey['@context'] = MULTIKEY_CONTEXT_V1_URL;
  }
  if(multikey.controller && !multikey.id) {
    multikey.id = `${multikey.controller}#${multikey.publicKeyMultibase}`;
  }

  _assertMultikey(multikey);
  return _createKeyPairInterface({keyPair: multikey});
}

/**
 * Imports an RSA key pair from JWK format.
 *
 * @param {object} options - Options hash.
 * @param {object} options.jwk - The JWK.
 * @param {boolean} [options.secretKey=false] - Whether to include secret key.
 * @param {string} [options.id] - Optional key ID.
 * @param {string} [options.controller] - Optional controller (DID).
 *
 * @returns {Promise<object>} The imported key pair interface.
 */
export async function fromJwk({jwk, secretKey = false, id, controller} = {}) {
  if(!jwk || typeof jwk !== 'object') {
    throw new TypeError('"jwk" is required.');
  }
  if(jwk.kty !== 'RSA') {
    throw new TypeError('JWK must have kty "RSA".');
  }

  const modulusLength = getModulusLengthFromJwk(jwk);
  // Extract only public key fields for multibase conversion
  const publicJwk = {
    kty: jwk.kty,
    n: jwk.n,
    e: jwk.e,
    alg: jwk.alg
  };
  const multikey = {
    '@context': MULTIKEY_CONTEXT_V1_URL,
    type: 'Multikey',
    publicKeyMultibase: await toPublicKeyMultibaseFromJwk({jwk: publicJwk}),
    publicKeyJwk: {
      kty: jwk.kty,
      n: jwk.n,
      e: jwk.e,
      alg: jwk.alg || 'PS256'
    },
    modulusLength
  };
  if(typeof id === 'string') {
    multikey.id = id;
  }
  if(typeof controller === 'string') {
    multikey.controller = controller;
  }
  if(secretKey && jwk.d) {
    multikey.secretKeyMultibase = await toSecretKeyMultibaseFromJwk({jwk});
    multikey.secretKeyJwk = {
      kty: jwk.kty,
      n: jwk.n,
      e: jwk.e,
      d: jwk.d,
      p: jwk.p,
      q: jwk.q,
      dp: jwk.dp,
      dq: jwk.dq,
      qi: jwk.qi,
      alg: jwk.alg || 'PS256'
    };
  }
  return from(multikey);
}

/**
 * Converts a key pair to JWK format.
 *
 * @param {object} options - Options hash.
 * @param {object} options.keyPair - The key pair.
 * @param {boolean} [options.secretKey=false] - Whether to export secret key.
 *
 * @returns {Promise<object>} The JWK.
 */
export async function toJwk({keyPair, secretKey = false} = {}) {
  if(!(keyPair?.publicKey instanceof CryptoKey) &&
     !(keyPair?.publicKey?.algorithm)) {
    keyPair = await importKeyPair(keyPair);
  }
  const useSecretKey = secretKey && !!keyPair.secretKey;
  const cryptoKey = useSecretKey ? keyPair.secretKey : keyPair.publicKey;
  const jwk = await webcrypto.subtle.exportKey('jwk', cryptoKey);
  // Ensure alg is set for PS256 compatibility
  if(!jwk.alg) {
    jwk.alg = 'PS256';
  }
  return jwk;
}

/**
 * Imports a key pair from raw bytes.
 *
 * @param {object} options - Options hash.
 * @param {number} options.modulusLength - The RSA modulus length.
 * @param {Uint8Array} [options.secretKey] - The secret key bytes (PKCS#8).
 * @param {Uint8Array} options.publicKey - The public key bytes (SPKI).
 *
 * @returns {Promise<object>} The imported key pair interface.
 */
export async function fromRaw({
  modulusLength,
  secretKey,
  publicKey
} = {}) {
  if(typeof modulusLength !== 'number') {
    throw new TypeError('"modulusLength" must be a number.');
  }
  if(secretKey && !(secretKey instanceof Uint8Array)) {
    throw new TypeError('"secretKey" must be a Uint8Array.');
  }
  if(!(publicKey instanceof Uint8Array)) {
    throw new TypeError('"publicKey" must be a Uint8Array.');
  }
  const cryptoKey = await cryptoKeyfromRaw({
    modulusLength,
    secretKey,
    publicKey
  });
  const jwk = await webcrypto.subtle.exportKey('jwk', cryptoKey);
  return fromJwk({jwk, secretKey: !!secretKey});
}

/**
 * Augments key pair with useful metadata and utilities.
 *
 * @param {object} options - Options hash.
 * @param {object} options.keyPair - The key pair.
 * @param {number} [options.modulusLength] - The RSA modulus length.
 *
 * @returns {Promise<object>} The augmented key pair interface.
 */
async function _createKeyPairInterface({keyPair, modulusLength} = {}) {
  if(!(keyPair?.publicKey instanceof CryptoKey) &&
     !(keyPair?.publicKey?.algorithm)) {
    keyPair = await importKeyPair(keyPair);
  }

  // Determine modulus length if not provided
  if(!modulusLength) {
    if(keyPair.modulusLength) {
      modulusLength = keyPair.modulusLength;
    } else if(keyPair.publicKeyJwk) {
      modulusLength = getModulusLengthFromJwk(keyPair.publicKeyJwk);
    } else {
      modulusLength = DEFAULT_MODULUS_LENGTH;
    }
  }

  const exportFn = async ({
    publicKey = true,
    secretKey = false,
    includeContext = true,
    raw = false
  } = {}) => {
    if(raw) {
      const jwk = await toJwk({keyPair, secretKey});
      const result = {};
      if(publicKey) {
        // Extract only public key fields for public key bytes
        const publicJwk = {
          kty: jwk.kty,
          n: jwk.n,
          e: jwk.e,
          alg: jwk.alg
        };
        result.publicKey = await toPublicKeyBytes({jwk: publicJwk});
      }
      if(secretKey) {
        result.secretKey = await toSecretKeyBytes({jwk});
      }
      return result;
    }
    return exportKeyPair({keyPair, publicKey, secretKey, includeContext});
  };

  const {publicKeyMultibase, secretKeyMultibase} = await exportFn({
    publicKey: true,
    secretKey: true,
    includeContext: true
  });

  keyPair = {
    ...keyPair,
    publicKeyMultibase,
    secretKeyMultibase,
    modulusLength,
    export: exportFn,
    signer() {
      const {id, secretKey} = keyPair;
      if(!secretKey) {
        throw new Error('Secret key is required for signing.');
      }
      return createSigner({id, secretKey});
    },
    verifier() {
      const {id, publicKey} = keyPair;
      return createVerifier({id, publicKey});
    }
  };

  return keyPair;
}

/**
 * Checks if key pair is in Multikey format.
 *
 * @param {object} key - The key to check.
 *
 * @throws {TypeError} If key is not a valid Multikey.
 */
function _assertMultikey(key) {
  if(!(key && typeof key === 'object')) {
    throw new TypeError('"key" must be an object.');
  }
  if(key.type !== 'Multikey') {
    throw new TypeError('"key" must be a Multikey with type "Multikey".');
  }
  if(!(key['@context'] === MULTIKEY_CONTEXT_V1_URL ||
    (Array.isArray(key['@context']) &&
    key['@context'].includes(MULTIKEY_CONTEXT_V1_URL)))) {
    throw new TypeError(
      '"key" must be a Multikey with context ' +
      `"${MULTIKEY_CONTEXT_V1_URL}".`);
  }
}

