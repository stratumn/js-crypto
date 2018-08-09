import { pki } from 'node-forge';
import { ED25519PublicKey } from '../keys/curve25519';
import { RSAPublicKey } from '../keys/rsa';

import { SIGNING_ALGO_RSA, SIGNING_ALGO_ED25519 } from './constants';

import {
  encodePublicKey,
  decodePublicKey,
  decodeSignature,
  unicodeToBuffer
} from '../utils';

export default class SigningPublicKey {
  constructor({ publicKey, pemPublicKey, algo }) {
    if (publicKey) {
      if (!algo)
        throw new Error(
          'You must specify the algo when creating from the raw key.'
        );
      this._key = publicKey;
      this._algo = algo;
    } else {
      this.load(pemPublicKey);
    }
  }

  load = pemPublicKey => {
    const { oid, ...asn1Data } = decodePublicKey(pemPublicKey);

    switch (oid) {
      case SIGNING_ALGO_RSA.oid:
        this._key = new RSAPublicKey(
          pki.publicKeyFromAsn1(asn1Data.rsaPublicKey)
        );
        this._algo = SIGNING_ALGO_RSA.name;
        break;
      case SIGNING_ALGO_ED25519.oid:
        this._key = new ED25519PublicKey(
          unicodeToBuffer(asn1Data.curve25519PublicKey)
        );
        this._algo = SIGNING_ALGO_ED25519.name;
        break;

      default:
        throw new Error(`Unsupported signing algorithm OID ${oid}"`);
    }
  };

  verify = (message, signature) => {
    const sig = decodeSignature(signature);
    switch (this._algo) {
      case SIGNING_ALGO_RSA.name:
      case SIGNING_ALGO_ED25519.name:
        return this._key.verify(message, sig);

      default:
        throw new Error(`Unsupported signing algorithm "${this._algo}"`);
    }
  };

  export = () => {
    let asn1PublicKey;
    switch (this._algo) {
      case SIGNING_ALGO_RSA.name:
      case SIGNING_ALGO_ED25519.name:
        asn1PublicKey = this._key.toAsn1();
        break;

      default:
        throw new Error(`Unsupported encryption algorithm ${this._algo}"`);
    }

    return encodePublicKey(asn1PublicKey, this._algo);
  };
}
