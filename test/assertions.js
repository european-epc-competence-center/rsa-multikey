/*!
 * Copyright (c) 2024 European EPC Competence Center GmbH. All rights reserved.
 */
import {base58btc} from 'multiformats/bases/base58';
import chai from 'chai';
import * as RsaMultikey from '../lib/index.js';
import {stringToUint8Array} from './text-encoder.js';
import {CryptoKey} from '../lib/crypto.js';
import {webcrypto} from '../lib/crypto.js';
import {exportKeyPair} from '../lib/serialize.js';

const {expect} = chai;

export function testAlgorithm(optionsOrGetter) {
  const getOptions = typeof optionsOrGetter === 'function' ? optionsOrGetter : () => optionsOrGetter;
  
  it('signer() instance should export proper algorithm', async () => {
    const {serializedKeyPair} = getOptions();
    const keyPair = await RsaMultikey.from(serializedKeyPair);
    const signer = keyPair.signer();
    signer.algorithm.should.equal('PS256');
  });
  it('verifier() instance should export proper algorithm', async () => {
    const {serializedKeyPair} = getOptions();
    const keyPair = await RsaMultikey.from(serializedKeyPair);
    const verifier = keyPair.verifier();
    verifier.algorithm.should.equal('PS256');
  });
}

export function testSignVerify(optionsOrGetter) {
  const getOptions = typeof optionsOrGetter === 'function' ? optionsOrGetter : () => optionsOrGetter;
  
  let signer;
  let verifier;
  before(async function() {
    const {id, serializedKeyPair} = getOptions();
    const keyPair = await RsaMultikey.from({
      id,
      ...serializedKeyPair
    });
    signer = keyPair.signer();
    verifier = keyPair.verifier();
  });
  it('should have correct id', function() {
    const {id} = getOptions();
    signer.should.have.property('id', id);
    verifier.should.have.property('id', id);
  });
  it('should sign & verify', async function() {
    const data = stringToUint8Array('test 1234');
    const signature = await signer.sign({data});
    const result = await verifier.verify({data, signature});
    result.should.be.true;
  });

  it('has proper signature format', async function() {
    const data = stringToUint8Array('test 1234');
    const signature = await signer.sign({data});
    expect(signature).to.be.instanceof(Uint8Array);
  });

  it('fails if signing data is changed', async function() {
    const data = stringToUint8Array('test 1234');
    const signature = await signer.sign({data});
    const changedData = stringToUint8Array('test 4321');
    const result = await verifier.verify({data: changedData, signature});
    result.should.be.false;
  });
}

export function testGenerate(optionsOrGetter) {
  // Support both direct options and getter function
  const getOptions = typeof optionsOrGetter === 'function' ? optionsOrGetter : () => optionsOrGetter;
  
  it('should generate a key pair', async function() {
    const {
      modulusLength,
      secretKeyByteLength,
      publicKeyByteLength
    } = getOptions();
    let keyPair;
    let err;
    try {
      keyPair = await RsaMultikey.generate({modulusLength});
    } catch(e) {
      err = e;
    }
    expect(err).to.not.exist;
    expect(keyPair).to.have.property('publicKeyMultibase');
    expect(keyPair).to.have.property('secretKeyMultibase');
    expect(keyPair).to.have.property('publicKey');
    // Check if publicKey is a valid CryptoKey (either our wrapper or native Web Crypto API)
    const hasValidPublicKey = !!(keyPair?.publicKey && (
      keyPair.publicKey instanceof CryptoKey || 
      (keyPair.publicKey.algorithm && 
       typeof keyPair.publicKey.algorithm === 'object' &&
       keyPair.publicKey.algorithm.name === 'RSA-PSS')
    ));
    expect(hasValidPublicKey).to.be.true;
    expect(keyPair).to.have.property('secretKey');
    // Check if secretKey is a valid CryptoKey (either our wrapper or native Web Crypto API)
    const hasValidSecretKey = !!(keyPair?.secretKey && (
      keyPair.secretKey instanceof CryptoKey || 
      (keyPair.secretKey.algorithm && 
       typeof keyPair.secretKey.algorithm === 'object' &&
       keyPair.secretKey.algorithm.name === 'RSA-PSS')
    ));
    expect(hasValidSecretKey).to.be.true;
    expect(keyPair).to.have.property('export');
    expect(keyPair).to.have.property('signer');
    expect(keyPair).to.have.property('verifier');
    expect(keyPair).to.have.property('modulusLength', modulusLength);
    
    if(secretKeyByteLength && publicKeyByteLength) {
      const secretKeyBytes = base58btc.decode(
        keyPair.secretKeyMultibase);
      const publicKeyBytes = base58btc.decode(
        keyPair.publicKeyMultibase);
      // RSA keys are DER-encoded, so exact byte lengths vary
      // We just check they're reasonable (within expected range)
      secretKeyBytes.length.should.be.at.least(secretKeyByteLength * 0.9);
      secretKeyBytes.length.should.be.at.most(secretKeyByteLength * 1.1);
      publicKeyBytes.length.should.be.at.least(publicKeyByteLength * 0.9);
      publicKeyBytes.length.should.be.at.most(publicKeyByteLength * 1.1);
    }
  });
}

export function testExport(optionsOrGetter) {
  const getOptions = typeof optionsOrGetter === 'function' ? optionsOrGetter : () => optionsOrGetter;
  
  it('should export id, type and key material', async () => {
    const {modulusLength} = getOptions();
    const keyPair = await RsaMultikey.generate({
      id: '4e0db4260c87cc200df3',
      controller: 'did:example:1234',
      modulusLength
    });
    const keyPairExported = await keyPair.export({
      publicKey: true, secretKey: true
    });

    const expectedProperties = [
      'id', 'type', 'controller', 'publicKeyMultibase', 'secretKeyMultibase'
    ];
    for(const property of expectedProperties) {
      expect(keyPairExported).to.have.property(property);
      expect(keyPairExported[property]).to.exist;
    }

    expect(keyPairExported.controller).to.equal('did:example:1234');
    expect(keyPairExported.type).to.equal('Multikey');
    expect(keyPairExported.id).to.equal('4e0db4260c87cc200df3');
  });

  it('should only export public key if specified', async () => {
    const {modulusLength} = getOptions();
    const keyPair = await RsaMultikey.generate({
      id: '4e0db4260c87cc200df3',
      modulusLength
    });
    const keyPairExported = await keyPair.export({publicKey: true});

    expect(keyPairExported).not.to.have.property('secretKeyMultibase');
    expect(keyPairExported).to.have.property('publicKeyMultibase');
    expect(keyPairExported).to.have.property('id', '4e0db4260c87cc200df3');
    expect(keyPairExported).to.have.property('type', 'Multikey');
  });

  it('should only export secret key if available', async () => {
    const {modulusLength} = getOptions();
    const algorithm = {
      name: 'RSA-PSS',
      hash: 'SHA-256',
      modulusLength,
      publicExponent: new Uint8Array([1, 0, 1])
    };
    const keyPair = await webcrypto.subtle.generateKey(
      algorithm, true, ['sign', 'verify']);
    delete keyPair.privateKey;

    const keyPairExported = await exportKeyPair({
      keyPair,
      publicKey: true,
      secretKey: true,
      includeContext: true
    });

    expect(keyPairExported).not.to.have.property('secretKeyMultibase');
  });

  it('should export raw public key', async () => {
    const {modulusLength} = getOptions();
    const keyPair = await RsaMultikey.generate({modulusLength});
    const expectedPublicKey = base58btc.decode(
      keyPair.publicKeyMultibase);
    const {publicKey} = await keyPair.export({publicKey: true, raw: true});
    expect(expectedPublicKey).to.deep.equal(publicKey);
  });

  it('should export raw secret key', async () => {
    const {modulusLength} = getOptions();
    const keyPair = await RsaMultikey.generate({modulusLength});
    const expectedSecretKey = base58btc.decode(
      keyPair.secretKeyMultibase);
    const {secretKey} = await keyPair.export({secretKey: true, raw: true});
    expect(expectedSecretKey).to.deep.equal(secretKey);
  });
}

export function testFrom(optionsOrGetter) {
  const getOptions = typeof optionsOrGetter === 'function' ? optionsOrGetter : () => optionsOrGetter;
  
  it('should auto-set key.id based on controller', async () => {
    const {serializedKeyPair, id} = getOptions();
    const {publicKeyMultibase} = serializedKeyPair;
    const keyPair = await RsaMultikey.from(serializedKeyPair);
    expect(keyPair.publicKeyMultibase).to.equal(publicKeyMultibase);
    expect(keyPair.id).to.equal(id);
  });
  it('should round-trip load exported keys', async () => {
    const keyPair = await RsaMultikey.generate({
      id: '4e0db4260c87cc200df3',
      modulusLength: 2048
    });
    const keyPairExported = await keyPair.export({
      publicKey: true, secretKey: true
    });
    const keyPairImported = await RsaMultikey.from(keyPairExported);

    expect(await keyPairImported.export({publicKey: true, secretKey: true}))
      .to.eql(keyPairExported);
  });

  it('should import with `@context` array', async () => {
    const keyPair = await RsaMultikey.generate({
      id: '4e0db4260c87cc200df3',
      modulusLength: 2048
    });
    const keyPairExported = await keyPair.export({
      publicKey: true, secretKey: true
    });
    const keyPairImported = await RsaMultikey.from({
      ...keyPairExported,
      '@context': [{}, keyPairExported['@context']]
    });

    expect(await keyPairImported.export({publicKey: true, secretKey: true}))
      .to.eql(keyPairExported);
  });
  it('should load `publicKeyJwk`', async () => {
    const keyPair = await RsaMultikey.generate({
      id: '4e0db4260c87cc200df3',
      modulusLength: 2048
    });
    const jwk1 = await RsaMultikey.toJwk({keyPair});
    expect(jwk1.d).to.not.exist;
    const keyPairImported1 = await RsaMultikey.from({publicKeyJwk: jwk1});
    const keyPairImported2 = await RsaMultikey.from({
      type: 'JsonWebKey',
      publicKeyJwk: jwk1
    });
    const jwk2 = await RsaMultikey.toJwk({keyPair: keyPairImported1});
    const jwk3 = await RsaMultikey.toJwk({keyPair: keyPairImported2});
    expect(jwk1).to.eql(jwk2);
    expect(jwk1).to.eql(jwk3);
  });
}

export function testJWK(optionsOrGetter) {
  const getOptions = typeof optionsOrGetter === 'function' ? optionsOrGetter : () => optionsOrGetter;
  
  it('should round-trip secret JWKs', async () => {
    const {modulusLength} = getOptions();
    const keyPair = await RsaMultikey.generate({
      id: '4e0db4260c87cc200df3',
      modulusLength
    });
    const jwk1 = await RsaMultikey.toJwk({keyPair, secretKey: true});
    expect(jwk1.d).to.exist;
    const keyPairImported = await RsaMultikey.fromJwk(
      {jwk: jwk1, secretKey: true});
    const jwk2 = await RsaMultikey.toJwk(
      {keyPair: keyPairImported, secretKey: true});
    expect(jwk1).to.eql(jwk2);
  });

  it('should round-trip public JWKs', async () => {
    const {modulusLength} = getOptions();
    const keyPair = await RsaMultikey.generate({
      id: '4e0db4260c87cc200df3',
      modulusLength
    });
    const jwk1 = await RsaMultikey.toJwk({keyPair});
    expect(jwk1.d).to.not.exist;
    const keyPairImported = await RsaMultikey.fromJwk({jwk: jwk1});
    const jwk2 = await RsaMultikey.toJwk({keyPair: keyPairImported});
    expect(jwk1).to.eql(jwk2);
  });
}

export function testRaw(optionsOrGetter) {
  const getOptions = typeof optionsOrGetter === 'function' ? optionsOrGetter : () => optionsOrGetter;
  
  it('should import raw public key', async () => {
    const {modulusLength} = getOptions();
    const keyPair = await RsaMultikey.generate({modulusLength});

    // first export
    const expectedPublicKey = base58btc.decode(
      keyPair.publicKeyMultibase);
    const {publicKey} = await keyPair.export({publicKey: true, raw: true});
    expect(expectedPublicKey).to.deep.equal(publicKey);

    // then import
    const imported = await RsaMultikey.fromRaw({modulusLength, publicKey});

    // then re-export to confirm
    const {publicKey: publicKey2} = await imported.export(
      {publicKey: true, raw: true});
    expect(expectedPublicKey).to.deep.equal(publicKey2);
  });

  it('should import raw secret key', async () => {
    const {modulusLength} = getOptions();
    const keyPair = await RsaMultikey.generate({modulusLength});

    // first export
    const expectedSecretKey = base58btc.decode(
      keyPair.secretKeyMultibase);
    const {secretKey, publicKey} = await keyPair.export(
      {secretKey: true, raw: true});
    expect(expectedSecretKey).to.deep.equal(secretKey);

    // then import
    const imported = await RsaMultikey.fromRaw(
      {modulusLength, secretKey, publicKey});

    // then re-export to confirm
    const {secretKey: secretKey2} = await imported.export(
      {secretKey: true, raw: true});
    expect(expectedSecretKey).to.deep.equal(secretKey2);
  });
}

