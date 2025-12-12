/*!
 * Copyright (c) 2024 Digital Bazaar, Inc. All rights reserved.
 */

// Mock RSA keys will be generated during test setup
// These are placeholders - actual keys will be generated in tests
export const mockKeyRsa2048 = {
  type: 'Multikey',
  controller: 'did:example:1234',
  // These will be populated during test setup
  publicKeyMultibase: null,
  secretKeyMultibase: null
};

export const mockKeyRsa3072 = {
  type: 'Multikey',
  controller: 'did:example:1234',
  publicKeyMultibase: null,
  secretKeyMultibase: null
};

export const mockKeyRsa4096 = {
  type: 'Multikey',
  controller: 'did:example:1234',
  publicKeyMultibase: null,
  secretKeyMultibase: null
};

const getKeyId = ({controller, publicKeyMultibase}) =>
  `${controller}#${publicKeyMultibase}`;

// RSA key sizes (approximate DER-encoded sizes)
// These are approximate as DER encoding adds overhead
const RSA_2048_PUBLIC_BYTES = 294; // ~294 bytes for SPKI
const RSA_2048_SECRET_BYTES = 1218; // ~1218 bytes for PKCS#8
const RSA_3072_PUBLIC_BYTES = 422; // ~422 bytes for SPKI
const RSA_3072_SECRET_BYTES = 1794; // ~1794 bytes for PKCS#8
const RSA_4096_PUBLIC_BYTES = 550; // ~550 bytes for SPKI
const RSA_4096_SECRET_BYTES = 2342; // ~2342 bytes for PKCS#8

export const multikeys = new Map([
  ['2048', {
    id: null, // Will be set during test setup
    serializedKeyPair: mockKeyRsa2048,
    props: {
      modulusLength: 2048,
      secretKeyByteLength: RSA_2048_SECRET_BYTES,
      publicKeyByteLength: RSA_2048_PUBLIC_BYTES
    }
  }],
  ['3072', {
    id: null, // Will be set during test setup
    serializedKeyPair: mockKeyRsa3072,
    props: {
      modulusLength: 3072,
      secretKeyByteLength: RSA_3072_SECRET_BYTES,
      publicKeyByteLength: RSA_3072_PUBLIC_BYTES
    }
  }],
  ['4096', {
    id: null, // Will be set during test setup
    serializedKeyPair: mockKeyRsa4096,
    props: {
      modulusLength: 4096,
      secretKeyByteLength: RSA_4096_SECRET_BYTES,
      publicKeyByteLength: RSA_4096_PUBLIC_BYTES
    }
  }]
]);

