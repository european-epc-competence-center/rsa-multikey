/*!
 * Copyright (c) 2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as RsaMultikey from '../lib/index.js';
import chai from 'chai';

const should = chai.should();
const {expect} = chai;

describe('RsaMultikey', () => {
  describe('module', () => {
    it('should have proper exports', async () => {
      expect(RsaMultikey).to.have.property('generate');
      expect(RsaMultikey).to.have.property('from');
      expect(RsaMultikey).to.have.property('fromJwk');
      expect(RsaMultikey).to.have.property('toJwk');
      expect(RsaMultikey).to.have.property('fromRaw');
    });
  });

  describe('generate', () => {
    it('should generate a 2048-bit RSA key pair', async () => {
      const keyPair = await RsaMultikey.generate({modulusLength: 2048});
      expect(keyPair).to.have.property('publicKeyMultibase');
      expect(keyPair).to.have.property('secretKeyMultibase');
      expect(keyPair).to.have.property('modulusLength', 2048);
    });

    it('should generate a 3072-bit RSA key pair', async () => {
      const keyPair = await RsaMultikey.generate({modulusLength: 3072});
      expect(keyPair).to.have.property('publicKeyMultibase');
      expect(keyPair).to.have.property('secretKeyMultibase');
      expect(keyPair).to.have.property('modulusLength', 3072);
    });

    it('should generate a 4096-bit RSA key pair', async () => {
      const keyPair = await RsaMultikey.generate({modulusLength: 4096});
      expect(keyPair).to.have.property('publicKeyMultibase');
      expect(keyPair).to.have.property('secretKeyMultibase');
      expect(keyPair).to.have.property('modulusLength', 4096);
    });

    it('should error on invalid modulus length', async () => {
      let err;
      try {
        await RsaMultikey.generate({modulusLength: 1024});
      } catch(e) {
        err = e;
      }
      expect(err).to.be.an.instanceof(TypeError);
    });

    it('should set id from controller', async () => {
      const controller = 'did:example:1234';
      const keyPair = await RsaMultikey.generate({
        controller,
        modulusLength: 2048
      });
      expect(keyPair.controller).to.equal(controller);
      expect(keyPair.id).to.include(controller);
    });
  });

  describe('from', () => {
    it('should error if publicKeyMultibase property is missing', async () => {
      let error;
      try {
        await RsaMultikey.from({});
      } catch(e) {
        error = e;
      }
      expect(error).to.be.an.instanceof(Error);
    });
  });

  describe('sign and verify', () => {
    it('should sign and verify data', async () => {
      const keyPair = await RsaMultikey.generate({
        id: 'did:example:1234#key-1',
        controller: 'did:example:1234',
        modulusLength: 2048
      });
      const data = (new TextEncoder()).encode('test data goes here');
      const signer = keyPair.signer();
      const verifier = keyPair.verifier();
      const signature = await signer.sign({data});

      expect(await verifier.verify({data, signature})).to.be.true;
    });

    it('should sign and verify string data', async () => {
      const keyPair = await RsaMultikey.generate({
        id: 'did:example:1234#key-1',
        controller: 'did:example:1234',
        modulusLength: 2048
      });
      const data = 'test data goes here';
      const signer = keyPair.signer();
      const verifier = keyPair.verifier();
      const signature = await signer.sign({data});

      expect(await verifier.verify({data, signature})).to.be.true;
    });
  });
});

