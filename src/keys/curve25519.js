import { asn1, ed25519, util } from 'node-forge';
import { unicodeToUint8Array, concatUint8Arrays } from '../utils';

export const X25519_OID = '1.3.101.110';
export const ED25519_OID = '1.3.101.112';

// ============================================================================
// ====                       ED25519 PRIVATE KEY                           ====
// ============================================================================

export class ED25519PrivateKey {
  constructor(key = null) {
    if (!key) this.generate();
    else this._key = key;
  }

  generate = () => {
    this._key = ed25519.generateKeyPair().privateKey;
  };

  publicKey = () =>
    new ED25519PublicKey(
      ed25519.publicKeyFromPrivateKey({ privateKey: this._key })
    );

  sign = message => {
    const signature = ed25519.sign({
      privateKey: this._key,
      encoding: 'binary',
      message
    });
    return util.createBuffer(signature).getBytes();
  };

  toPkcs8 = () => privateKeyToPkcs8(this._key, ED25519_OID);
}

export const ed25519PrivateKeyFromAsn1 = key => {
  const capture = {};
  const errors = [];
  if (!asn1.validate(key, curve25519PrivateKeyValidator, capture, errors)) {
    const error = new Error(
      'Cannot read private key. ASN.1 object does not contain an ED25519PrivateKey.'
    );
    error.errors = errors;
    throw error;
  }

  const keyBytes = unicodeToUint8Array(capture.privateKey);
  return new ED25519PrivateKey(keyBytes);
};

// ============================================================================
// ====                        ED25519 PUBLIC KEY                           ====
// ============================================================================

export class ED25519PublicKey {
  constructor(key) {
    this._key = key;
  }

  verify = (message, signature) =>
    ed25519.verify({
      publicKey: this._key,
      message,
      encoding: 'binary',
      signature: unicodeToUint8Array(signature)
    });

  toAsn1 = () =>
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
      // AlgorithmIdentifier
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
        // algorithm
        asn1.create(
          asn1.Class.UNIVERSAL,
          asn1.Type.OID,
          false,
          asn1.oidToDer(ED25519_OID).getBytes()
        ),
        // parameters (null)
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, '')
      ]),
      // subjectPublicKey
      asn1.create(
        asn1.Class.UNIVERSAL,
        asn1.Type.BITSTRING,
        false,
        // We need to pad the key with the byte 0 (zero).
        util.createBuffer(concatUint8Arrays([0], this._key)).getBytes()
      )
    ]);
}

// ============================================================================
// ====                             HELPERS                                ====
// ============================================================================

// validator for an ED25519 private key
const curve25519PrivateKeyValidator = {
  name: 'ED25519PrivateKey',
  tagClass: asn1.Class.UNIVERSAL,
  type: asn1.Type.OCTETSTRING,
  constructed: false,
  capture: 'privateKey'
};

const privateKeyToPkcs8 = (key, oid) => {
  const asn1Key = asn1.create(
    asn1.UNIVERSAL,
    asn1.Type.OCTETSTRING,
    false,
    util.createBuffer(key).getBytes()
  );

  return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    // version (0)
    asn1.create(
      asn1.Class.UNIVERSAL,
      asn1.Type.INTEGER,
      false,
      asn1.integerToDer(0).getBytes()
    ),
    // privateKeyAlgorithm
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
      asn1.create(
        asn1.Class.UNIVERSAL,
        asn1.Type.OID,
        false,
        asn1.oidToDer(oid).getBytes()
      ),
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, '')
    ]),
    // PrivateKey
    asn1.create(
      asn1.Class.UNIVERSAL,
      asn1.Type.OCTETSTRING,
      false,
      asn1.toDer(asn1Key).getBytes()
    )
  ]);
};
