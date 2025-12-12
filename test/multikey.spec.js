/*!
 * Copyright (c) 2024 Digital Bazaar, Inc.
 */

import * as RsaMultikey from '../lib/index.js';
import {
  testAlgorithm,
  testExport,
  testFrom,
  testGenerate,
  testJWK,
  testRaw,
  testSignVerify
} from './assertions.js';

// Generate mock keys for each modulus length
async function setupMockKeys() {
  const multikeys = new Map();
  
  for(const modulusLength of [2048, 3072, 4096]) {
    const keyPair = await RsaMultikey.generate({
      controller: 'did:example:1234',
      modulusLength
    });
    const exported = await keyPair.export({
      publicKey: true,
      secretKey: true
    });
    
    const id = `${exported.controller}#${exported.publicKeyMultibase}`;
    
    // Approximate byte lengths for RSA keys
    let secretKeyByteLength, publicKeyByteLength;
    if(modulusLength === 2048) {
      secretKeyByteLength = 1218;
      publicKeyByteLength = 294;
    } else if(modulusLength === 3072) {
      secretKeyByteLength = 1794;
      publicKeyByteLength = 422;
    } else {
      secretKeyByteLength = 2342;
      publicKeyByteLength = 550;
    }
    
    multikeys.set(String(modulusLength), {
      id,
      serializedKeyPair: exported,
      props: {
        modulusLength,
        secretKeyByteLength,
        publicKeyByteLength
      }
    });
  }
  
  return multikeys;
}

describe('rsa-multikey', function() {
  let multikeys;
  
  before(async function() {
    multikeys = await setupMockKeys();
  });
  
  // Test 2048-bit RSA
  describe('2048-bit RSA', function() {
    describe('algorithm', function() {
      testAlgorithm(() => {
        const keyData = multikeys.get('2048');
        return {serializedKeyPair: keyData.serializedKeyPair};
      });
    });
    describe('generate', function() {
      testGenerate(() => multikeys.get('2048').props);
    });
    describe('export', () => {
      testExport(() => ({modulusLength: multikeys.get('2048').props.modulusLength}));
    });
    describe('sign and verify', function() {
      testSignVerify(() => {
        const keyData = multikeys.get('2048');
        return {id: keyData.id, serializedKeyPair: keyData.serializedKeyPair};
      });
    });
    describe('from', function() {
      testFrom(() => {
        const keyData = multikeys.get('2048');
        return {id: keyData.id, serializedKeyPair: keyData.serializedKeyPair};
      });
    });
    describe('fromJwk/toJwk', () => {
      testJWK(() => ({modulusLength: multikeys.get('2048').props.modulusLength}));
    });
    describe('fromRaw', () => {
      testRaw(() => ({modulusLength: multikeys.get('2048').props.modulusLength}));
    });
  });

  // Test 3072-bit RSA
  describe('3072-bit RSA', function() {
    describe('algorithm', function() {
      testAlgorithm(() => {
        const keyData = multikeys.get('3072');
        return {serializedKeyPair: keyData.serializedKeyPair};
      });
    });
    describe('generate', function() {
      testGenerate(() => multikeys.get('3072').props);
    });
    describe('export', () => {
      testExport(() => ({modulusLength: multikeys.get('3072').props.modulusLength}));
    });
    describe('sign and verify', function() {
      testSignVerify(() => {
        const keyData = multikeys.get('3072');
        return {id: keyData.id, serializedKeyPair: keyData.serializedKeyPair};
      });
    });
    describe('from', function() {
      testFrom(() => {
        const keyData = multikeys.get('3072');
        return {id: keyData.id, serializedKeyPair: keyData.serializedKeyPair};
      });
    });
    describe('fromJwk/toJwk', () => {
      testJWK(() => ({modulusLength: multikeys.get('3072').props.modulusLength}));
    });
    describe('fromRaw', () => {
      testRaw(() => ({modulusLength: multikeys.get('3072').props.modulusLength}));
    });
  });

  // Test 4096-bit RSA
  describe('4096-bit RSA', function() {
    describe('algorithm', function() {
      testAlgorithm(() => {
        const keyData = multikeys.get('4096');
        return {serializedKeyPair: keyData.serializedKeyPair};
      });
    });
    describe('generate', function() {
      testGenerate(() => multikeys.get('4096').props);
    });
    describe('export', () => {
      testExport(() => ({modulusLength: multikeys.get('4096').props.modulusLength}));
    });
    describe('sign and verify', function() {
      testSignVerify(() => {
        const keyData = multikeys.get('4096');
        return {id: keyData.id, serializedKeyPair: keyData.serializedKeyPair};
      });
    });
    describe('from', function() {
      testFrom(() => {
        const keyData = multikeys.get('4096');
        return {id: keyData.id, serializedKeyPair: keyData.serializedKeyPair};
      });
    });
    describe('fromJwk/toJwk', () => {
      testJWK(() => ({modulusLength: multikeys.get('4096').props.modulusLength}));
    });
    describe('fromRaw', () => {
      testRaw(() => ({modulusLength: multikeys.get('4096').props.modulusLength}));
    });
  });
});
