import { pki } from 'node-forge';
import { RSAPrivateKey } from '../keys/rsa';
import EncryptionPublicKey from './publicKey';
import { PKE_ALGO_RSA } from './constants';
import { encodePrivateKeyInfo, decodePrivateKey } from '../utils';

export default class EncryptionPrivateKey {
  constructor({ algo, pemPrivateKey, password }) {
    if (pemPrivateKey) {
      this.load(pemPrivateKey, password);
    } else {
      this.generate(algo);
    }
  }

  generate = algo => {
    this._algo = algo;
    switch (algo) {
      case PKE_ALGO_RSA.name: {
        this._key = new RSAPrivateKey();
        break;
      }
      default:
        throw new Error(`Unsupported signing algorithm "${algo}"`);
    }
  };

  load = (pemPrivateKey, password = null) => {
    const { key, oid } = decodePrivateKey(pemPrivateKey, password);
    switch (oid) {
      case PKE_ALGO_RSA.oid:
        this._key = new RSAPrivateKey(pki.privateKeyFromAsn1(key));
        this._algo = PKE_ALGO_RSA.name;
        break;
      default:
        throw new Error(`Unsupported signing algorithm OID ${oid}"`);
    }
  };

  publicKey = () => {
    switch (this._algo) {
      case PKE_ALGO_RSA.name:
        return new EncryptionPublicKey({
          publicKey: this._key.publicKey(),
          algo: this._algo
        });
      default:
        throw new Error(`Unsupported signing algorithm "${this._algo}"`);
    }
  };

  decrypt = (encryptedKey, ciphertext, iv, tag) =>
    this._key.decrypt(encryptedKey, ciphertext, iv, tag);

  export = (password = null) => {
    let privateKeyInfo;
    switch (this._algo) {
      case PKE_ALGO_RSA.name:
        privateKeyInfo = this._key.toPkcs8();
        break;
      default:
        throw new Error(`Unsupported signing algorithm "${this._algo}"`);
    }

    if (!password) return encodePrivateKeyInfo(privateKeyInfo, this._algo);

    const encryptedPrivateKeyInfo = pki.encryptPrivateKeyInfo(
      privateKeyInfo,
      password,
      { algorithm: 'aes256' }
    );

    // Export keys to pem format
    return pki.encryptedPrivateKeyToPem(encryptedPrivateKeyInfo);
  };
}
