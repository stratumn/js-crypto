import { util, asn1, pki } from 'node-forge';

import {
  ED25519PrivateKey,
  ed25519PrivateKeyFromAsn1
} from '../keys/curve25519';
import { RSAPrivateKey } from '../keys/rsa';

import SigningPublicKey from './publicKey';
import {
  SIGNING_ALGOS,
  SIGNING_ALGO_RSA,
  SIGNING_ALGO_ED25519
} from './constants';

import {
  encodePrivateKeyInfo,
  encodeSignature,
  decodePrivateKey
} from '../utils';

export default class SigningPrivateKey {
  constructor({ algo, pemPrivateKey, password }) {
    if (pemPrivateKey) {
      this.load(pemPrivateKey, password);
    } else {
      this.generate(algo);
    }
  }

  generate = algo => {
    if (SIGNING_ALGOS.indexOf(algo) === -1)
      throw new Error(`Unsupported signing algorithm "${algo}"`);

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
    const keyInfo = decodePrivateKey(pemPrivateKey, password);
    const { privateKey, algo } = decodePrivateKeyAsn1(keyInfo);
    this._key = privateKey;
    this._algo = algo;
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
    let sig;
    switch (this._algo) {
      case SIGNING_ALGO_RSA.name:
      case SIGNING_ALGO_ED25519.name:
        sig = this._key.sign(message);
        break;
      default:
        throw new Error(`Unsupported signing algorithm "${this._algo}"`);
    }

    return encodeSignature(sig);
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

// validator for a PrivateKeyInfo structure
// Same as here: https://github.com/digitalbazaar/forge/blob/master/lib/rsa.js#L91
// we copied this here because we need to do additionnal work on the switch in `decodePrivateKeyAsn1`
// to include ED25519 logic
const privateKeyValidator = {
  // PrivateKeyInfo
  name: 'PrivateKeyInfo',
  tagClass: asn1.Class.UNIVERSAL,
  type: asn1.Type.SEQUENCE,
  constructed: true,
  value: [
    {
      // Version (INTEGER)
      name: 'PrivateKeyInfo.version',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.INTEGER,
      constructed: false,
      capture: 'privateKeyVersion'
    },
    {
      // privateKeyAlgorithm
      name: 'PrivateKeyInfo.privateKeyAlgorithm',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.SEQUENCE,
      constructed: true,
      value: [
        {
          name: 'AlgorithmIdentifier.algorithm',
          tagClass: asn1.Class.UNIVERSAL,
          type: asn1.Type.OID,
          constructed: false,
          capture: 'privateKeyOid'
        }
      ]
    },
    {
      // PrivateKey
      name: 'PrivateKeyInfo',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.OCTETSTRING,
      constructed: false,
      capture: 'privateKey'
    }
  ]
};

// decodePrivateKeyAsn1 returns an object containing the private key and the algo label.
const decodePrivateKeyAsn1 = key => {
  let obj = key;

  // Get private key info
  const capture = {};
  const errors = [];
  if (asn1.validate(obj, privateKeyValidator, capture, errors)) {
    obj = asn1.fromDer(util.createBuffer(capture.privateKey));
  }

  // Decode private key
  const oid = asn1.derToOid(capture.privateKeyOid);
  switch (oid) {
    case SIGNING_ALGO_RSA.oid:
      return {
        privateKey: new RSAPrivateKey(pki.privateKeyFromAsn1(obj)),
        algo: SIGNING_ALGO_RSA.name
      };
    case SIGNING_ALGO_ED25519.oid:
      return {
        privateKey: ed25519PrivateKeyFromAsn1(obj),
        algo: SIGNING_ALGO_ED25519.name
      };
    default:
      throw new Error(`Unsupported signing algorithm OID ${oid}"`);
  }
};
