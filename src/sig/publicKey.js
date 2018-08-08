import { asn1, pki } from 'node-forge';
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
    const asn1PublicKey = decodePublicKey(pemPublicKey);

    const { key, algo } = decodePublicKeyAsn1(asn1PublicKey);

    this._algo = algo;
    this._key = key;
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
        break;
    }

    return encodePublicKey(asn1PublicKey, this._algo);
  };
}

// validator for a SubjectPublicKeyInfo structure
// Same as here: https://github.com/digitalbazaar/forge/blob/master/lib/rsa.js#L226
// we copied this here because we need to do additionnal work on the switch in `decodePublicKeyAsn1`
// to include ED25519 logic

const publicKeyValidator = {
  name: 'SubjectPublicKeyInfo',
  tagClass: asn1.Class.UNIVERSAL,
  type: asn1.Type.SEQUENCE,
  constructed: true,
  captureAsn1: 'subjectPublicKeyInfo',
  value: [
    {
      name: 'SubjectPublicKeyInfo.AlgorithmIdentifier',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.SEQUENCE,
      constructed: true,
      value: [
        {
          name: 'AlgorithmIdentifier.algorithm',
          tagClass: asn1.Class.UNIVERSAL,
          type: asn1.Type.OID,
          constructed: false,
          capture: 'publicKeyOid'
        }
      ]
    },
    {
      // RSA
      name: 'SubjectPublicKeyInfo.subjectPublicKey',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.BITSTRING,
      constructed: false,
      optional: true,
      captureAsn1: 'subjectPublicKeyRSA',
      value: [
        {
          // RSAPublicKey
          name: 'SubjectPublicKeyInfo.subjectPublicKey.RSAPublicKey',
          tagClass: asn1.Class.UNIVERSAL,
          type: asn1.Type.SEQUENCE,
          constructed: true,
          // optional: true,
          captureAsn1: 'rsaPublicKey'
        }
      ]
    },
    {
      // ED25519
      name: 'SubjectPublicKeyInfo.subjectPublicKey',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.BITSTRING,
      constructed: false,
      optional: true,
      captureBitStringValue: 'subjectPublicKeyED25519'
    }
  ]
};

const decodePublicKeyAsn1 = key => {
  const capture = {};
  const errors = [];
  asn1.validate(key, publicKeyValidator, capture, errors);
  // get oid
  const oid = asn1.derToOid(capture.publicKeyOid);

  switch (oid) {
    case SIGNING_ALGO_RSA.oid:
      return {
        key: new RSAPublicKey(pki.publicKeyFromAsn1(capture.rsaPublicKey)),
        algo: SIGNING_ALGO_RSA.name
      };
    case SIGNING_ALGO_ED25519.oid:
      return {
        key: new ED25519PublicKey(
          unicodeToBuffer(capture.subjectPublicKeyED25519)
        ),
        algo: SIGNING_ALGO_ED25519.name
      };

    default:
      throw new Error(`Unsupported signing algorithm OID ${oid}"`);
  }
};
