import { asn1, ed25519, util } from 'node-forge';

export const ED25519_OID = '1.3.101.112';

// ============================================================================
// ====                      ED25519 PRIVATE KEY                           ====
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

  toPkcs8 = () => {
    const asn1Key = asn1.create(
      asn1.UNIVERSAL,
      asn1.Type.OCTETSTRING,
      false,
      util.createBuffer(this._key).getBytes()
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
          asn1.oidToDer(ED25519_OID).getBytes()
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
}

// validator for an ED25519 private key
const ed25519PrivateKeyValidator = {
  name: 'ED25519PrivateKey',
  tagClass: asn1.Class.UNIVERSAL,
  type: asn1.Type.OCTETSTRING,
  constructed: false,
  capture: 'privateKey'
};

export const ed25519PrivateKeyFromAsn1 = key => {
  const capture = {};
  const errors = [];
  if (!asn1.validate(key, ed25519PrivateKeyValidator, capture, errors)) {
    const error = new Error(
      'Cannot read private key. ASN.1 object does not contain an ED25519PrivateKey.'
    );
    error.errors = errors;
    throw error;
  }

  const keyBytes = unicodeToBuffer(capture.privateKey);
  return new ED25519PrivateKey(keyBytes);
};

const unicodeToBuffer = str =>
  Buffer.from(str.split('').map(s => s.charCodeAt(0)));

// ============================================================================
// ====                       ED25519 PUBLIC KEY                           ====
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
      signature: unicodeToBuffer(signature)
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
        util
          .createBuffer(Buffer.concat([Buffer.from([0]), this._key]))
          .getBytes()
      )
    ]);
}
