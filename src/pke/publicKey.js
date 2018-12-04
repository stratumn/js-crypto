import { pki } from 'node-forge';
import { RSAPublicKey } from '../keys/rsa';
import { PKE_ALGO_RSA } from './constants';
import { encodePublicKey, decodePublicKey } from '../utils/encoding';

export default class EncryptionPublicKey {
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
      case PKE_ALGO_RSA.oid:
        this._key = new RSAPublicKey(
          pki.publicKeyFromAsn1(asn1Data.rsaPublicKey)
        );
        this._algo = PKE_ALGO_RSA.name;
        break;

      default:
        throw new Error(`Unsupported encryption algorithm OID ${oid}"`);
    }
  };

  // encrypt uses symmetric encryption under the hood in order to encrypt large messages.
  encrypt = message => this._key.encrypt(message);

  // encryptShort provides pure asymetric encryption but does not support messages larger than 256 bytes.
  encryptShort = message => this._key.encryptShort(message);

  export = () => {
    let asn1PublicKey;
    switch (this._algo) {
      case PKE_ALGO_RSA.name:
        asn1PublicKey = this._key.toAsn1();
        break;

      default:
        throw new Error(`Unsupported encryption algorithm ${this._algo}"`);
    }

    return encodePublicKey(asn1PublicKey, this._algo);
  };
}
