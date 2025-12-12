/*!
 * Copyright (c) 2024 European EPC Competence Center GmbH. All rights reserved.
 */

import {MULTIKEY_CONTEXT_V1_URL} from './constants.js';
import {
  toPublicKeyMultibaseFromJwk,
  toSecretKeyMultibaseFromJwk
} from './serialize.js';

/**
 * Converts a key pair to Multikey format.
 *
 * @param {object} options - Options hash.
 * @param {object} options.keyPair - The key pair to convert.
 *
 * @returns {Promise<object>} The Multikey format key pair.
 */
export async function toMultikey({keyPair} = {}) {
  if(!keyPair || typeof keyPair !== 'object') {
    throw new TypeError('"keyPair" must be an object.');
  }

  const multikey = {
    '@context': MULTIKEY_CONTEXT_V1_URL,
    type: 'Multikey',
  };

  if(keyPair.id) {
    multikey.id = keyPair.id;
  }
  if(keyPair.controller) {
    multikey.controller = keyPair.controller;
  }

  // Convert JWK to multibase if available
  if(keyPair.publicKeyJwk) {
    multikey.publicKeyMultibase = await toPublicKeyMultibaseFromJwk({
      jwk: keyPair.publicKeyJwk
    });
    multikey.publicKeyJwk = keyPair.publicKeyJwk;
  }

  if(keyPair.secretKeyJwk || keyPair.privateKeyJwk) {
    const secretJwk = keyPair.secretKeyJwk || keyPair.privateKeyJwk;
    multikey.secretKeyMultibase = await toSecretKeyMultibaseFromJwk({
      jwk: secretJwk
    });
    multikey.secretKeyJwk = secretJwk;
  }

  return multikey;
}

