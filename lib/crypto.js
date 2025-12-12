/*!
 * Copyright (c) 2024 Digital Bazaar, Inc. All rights reserved.
 */

import {webcrypto} from 'node:crypto';

// Re-export webcrypto for convenience
export {webcrypto};

// CryptoKey wrapper for compatibility
export class CryptoKey {
  constructor(key) {
    this._key = key;
  }

  get algorithm() {
    return this._key.algorithm;
  }

  get extractable() {
    return this._key.extractable;
  }

  get type() {
    return this._key.type;
  }

  get usages() {
    return this._key.usages;
  }
}

