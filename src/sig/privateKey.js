import { pki } from 'node-forge';

import {
  ED25519PrivateKey,
  ed25519PrivateKeyFromAsn1
} from '../keys/curve25519';
import { RSAPrivateKey } from '../keys/rsa';

import SigningPublicKey from './publicKey';
import { SIGNING_ALGO_RSA, SIGNING_ALGO_ED25519 } from './constants';

import {
  encodePrivateKeyInfo,
  encodeSignature,
  decodePrivateKey
} from '../utils/encoding';

import { stringToBytes } from '../utils';

export default class SigningPrivateKey {
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
      case SIGNING_ALGO_RSA.name: {
        this._key = new RSAPrivateKey();
        break;
      }
      case SIGNING_ALGO_ED25519.name: {
        this._key = new ED25519PrivateKey();
        break;
      }
      default:
        throw new Error(`Unsupported signing algorithm "${algo}"`);
    }
  };

  load = (pemPrivateKey, password = null) => {
    const { key, oid } = decodePrivateKey(pemPrivateKey, password);
    switch (oid) {
      case SIGNING_ALGO_RSA.oid:
        this._key = new RSAPrivateKey(pki.privateKeyFromAsn1(key));
        this._algo = SIGNING_ALGO_RSA.name;
        break;
      case SIGNING_ALGO_ED25519.oid:
        this._key = ed25519PrivateKeyFromAsn1(key);
        this._algo = SIGNING_ALGO_ED25519.name;
        break;
      default:
        throw new Error(`Unsupported signing algorithm OID ${oid}"`);
    }
  };

  publicKey = () => {
    switch (this._algo) {
      case SIGNING_ALGO_RSA.name:
      case SIGNING_ALGO_ED25519.name:
        return new SigningPublicKey({
          publicKey: this._key.publicKey(),
          algo: this._algo
        });
      default:
        throw new Error(`Unsupported signing algorithm "${this._algo}"`);
    }
  };

  sign = message => {
    // message should be a UInt8Array
    if (!(message instanceof Uint8Array))
      throw new Error('unexpected type, use Uint8Array');

    let sig;
    switch (this._algo) {
      case SIGNING_ALGO_RSA.name:
      case SIGNING_ALGO_ED25519.name:
        sig = this._key.sign(message);
        break;
      default:
        throw new Error(`Unsupported signing algorithm "${this._algo}"`);
    }

    return {
      public_key: stringToBytes(this.publicKey().export()),
      signature: stringToBytes(encodeSignature(sig)),
      message
    };
  };

  export = (password = null) => {
    let privateKeyInfo;
    switch (this._algo) {
      case SIGNING_ALGO_RSA.name:
      case SIGNING_ALGO_ED25519.name:
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
