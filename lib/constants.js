/*!
 * Copyright (c) 2024 Digital Bazaar, Inc. All rights reserved.
 */

export const ALGORITHM = 'RSA-PSS';
export const MULTIKEY_CONTEXT_V1_URL = 'https://w3id.org/security/multikey/v1';
export const EXTRACTABLE = true;

// RSA modulus lengths
export const RSA_MODULUS_LENGTH = {
  '2048': 2048,
  '3072': 3072,
  '4096': 4096
};

// Default modulus length for PS256
export const DEFAULT_MODULUS_LENGTH = 4096;

