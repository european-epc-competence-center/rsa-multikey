# rsa-multikey

Data integrity multikey for RSA-PSS (PS256) signatures compatible with https://github.com/digitalbazaar/data-integrity

This package provides RSA key pair generation, import/export, and signing/verification functionality compatible with the [Multikey](https://w3c.github.io/vc-data-integrity/#multikey) format used by Digital Bazaar's cryptographic suites.

## Features

- Generate RSA key pairs for PS256 (RSA-PSS with SHA-256) signatures
- Import/export keys in Multikey format (multibase encoding)
- Import/export keys in JWK format
- Sign and verify data using RSA-PSS
- Support for multiple RSA modulus lengths (2048, 3072, 4096 bits)
- Compatible with Digital Bazaar's multikey format

## Installation

```bash
npm install rsa-multikey
```

## Usage

### Generate a new RSA key pair

```javascript
import * as RsaMultikey from 'rsa-multikey';

// Generate a 4096-bit RSA key pair
const keyPair = await RsaMultikey.generate({
  controller: 'https://example.com/issuer',
  modulusLength: 4096
});

console.log(keyPair.id);
console.log(keyPair.publicKeyMultibase);
```

### Import from Multikey format

```javascript
const keyPair = await RsaMultikey.from({
  '@context': 'https://w3id.org/security/multikey/v1',
  type: 'Multikey',
  id: 'https://example.com/issuer#z...',
  controller: 'https://example.com/issuer',
  publicKeyMultibase: 'z...',
  secretKeyMultibase: 'z...' // optional
});
```

### Import from JWK format

```javascript
const keyPair = await RsaMultikey.fromJwk({
  jwk: {
    kty: 'RSA',
    n: '...',
    e: 'AQAB',
    d: '...', // optional
    p: '...', // optional
    q: '...', // optional
    dp: '...', // optional
    dq: '...', // optional
    qi: '...' // optional
  },
  id: 'https://example.com/issuer#key-1',
  controller: 'https://example.com/issuer',
  secretKey: true // include private key if available
});
```

### Sign data

```javascript
const signer = keyPair.signer();
const signature = await signer.sign({
  data: new TextEncoder().encode('Hello, World!')
});
```

### Verify signature

```javascript
const verifier = keyPair.verifier();
const isValid = await verifier.verify({
  data: new TextEncoder().encode('Hello, World!'),
  signature: signatureBytes
});
```

### Export to JWK

```javascript
const publicJwk = await RsaMultikey.toJwk({
  keyPair,
  secretKey: false
});

const privateJwk = await RsaMultikey.toJwk({
  keyPair,
  secretKey: true
});
```

## API

### `generate(options)`

Generates a new RSA key pair.

- `options.id` (string, optional): Key identifier
- `options.controller` (string, optional): Controller DID
- `options.modulusLength` (number, optional): RSA modulus length (2048, 3072, or 4096). Default: 4096

Returns: Promise\<KeyPair\>

### `from(key, options)`

Imports a key pair from Multikey format.

- `key` (object): Multikey object
- `options` (object, optional): Additional options

Returns: Promise\<KeyPair\>

### `fromJwk(options)`

Imports a key pair from JWK format.

- `options.jwk` (object): JSON Web Key
- `options.secretKey` (boolean, optional): Whether to include private key
- `options.id` (string, optional): Key identifier
- `options.controller` (string, optional): Controller DID

Returns: Promise\<KeyPair\>

### `toJwk(options)`

Exports a key pair to JWK format.

- `options.keyPair` (object): Key pair to export
- `options.secretKey` (boolean, optional): Whether to export private key. Default: false

Returns: Promise\<JWK\>

### `fromRaw(options)`

Imports a key pair from raw bytes.

- `options.modulusLength` (number): RSA modulus length
- `options.publicKey` (Uint8Array): Public key bytes (SPKI format)
- `options.secretKey` (Uint8Array, optional): Private key bytes (PKCS#8 format)

Returns: Promise\<KeyPair\>

### `toJsonWebKey2020(options)`

Converts a multikey key pair to JsonWebKey2020 format for use with ps256-signature-2020.

- `options.keyPair` (object): Key pair to convert
- `options.secretKey` (boolean, optional): Whether to include private key. Default: false

Returns: Promise\<JsonWebKey2020\>

## Compatibility with ps256-signature-2020

This package is designed to work seamlessly with [@eecc/ps256-signature-2020](https://github.com/european-epc-competence-center/ps256-signature-2020):

- **Signer interface**: Compatible with `sign({ data: Uint8Array }): Promise<Uint8Array>`
- **Verifier interface**: Compatible with `verify({ data: Uint8Array, signature: Uint8Array }): Promise<boolean>`
- **Algorithm parameters**: Uses `saltLength: 32` (SHA-256 hash length) matching ps256-signature-2020
- **Key format**: Supports JsonWebKey2020 format via `toJsonWebKey2020()` helper

Example integration:

```javascript
import * as RsaMultikey from 'rsa-multikey';
import { PS256Signature2020 } from '@eecc/ps256-signature-2020';

// Generate RSA key pair
const keyPair = await RsaMultikey.generate({
  controller: 'did:web:example.com',
  modulusLength: 4096
});

// Convert to JsonWebKey2020 format
const jsonWebKey2020 = await RsaMultikey.toJsonWebKey2020({
  keyPair,
  secretKey: true
});

// Use with ps256-signature-2020
const suite = new PS256Signature2020({ key: jsonWebKey2020 });
```

## License

BSD 3-Clause License
