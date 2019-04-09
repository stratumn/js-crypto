import { pki } from 'node-forge';
import { RSAPrivateKey } from '../keys/rsa';
import EncryptionPublicKey from './publicKey';
import { PKE_ALGO_RSA } from './constants';
import { encodePrivateKeyInfo, decodePrivateKey } from '../utils/encoding';

export default class EncryptionPrivateKey {
  static generateAsync = async algo => {
    const privateKey = new EncryptionPrivateKey({ generate: false });
    privateKey._algo = algo;
    switch (algo) {
      case PKE_ALGO_RSA.name: {
        privateKey._key = await RSAPrivateKey.generateAsync();
        return privateKey;
      }
      default:
        throw new Error(`Unsupported encryption algorithm "${algo}"`);
    }
  };

  constructor({ algo, pemPrivateKey, password, generate = true }) {
    if (pemPrivateKey) {
      this.load(pemPrivateKey, password);
    } else if (generate) {
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
        throw new Error(`Unsupported encryption algorithm "${algo}"`);
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
        throw new Error(`Unsupported encryption algorithm OID ${oid}"`);
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
        throw new Error(`Unsupported encryption algorithm "${this._algo}"`);
    }
  };

  // decrypt should be used for message encrypted with pke.EncryptionPublicKey.encrypt()
  decrypt = ciphertext => this._key.decrypt(ciphertext);

  // decrypt should be used for message encrypted with pke.EncryptionPublicKey.encryptShort()
  decryptShort = ciphertext => this._key.decryptShort(ciphertext);

  export = (password = null) => {
    let privateKeyInfo;
    switch (this._algo) {
      case PKE_ALGO_RSA.name:
        privateKeyInfo = this._key.toPkcs8();
        break;
      default:
        throw new Error(`Unsupported encryption algorithm "${this._algo}"`);
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
