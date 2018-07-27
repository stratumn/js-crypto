import { rsa, md, util, asn1, pem, pki, ed25519, oids } from 'node-forge';

const SIGNING_ALGO_RSA = { label: 'RSA', oid: oids.rsaEncryption };

const ED25519_OID = '1.3.101.112';
const SIGNING_ALGO_ED25519 = { label: 'ED25519', oid: ED25519_OID };

export const SIGNING_ALGOS = [
  SIGNING_ALGO_RSA.label,
  SIGNING_ALGO_ED25519.label
];

export class SigningKeyPair {
  constructor(opts) {
    // opts should contain either pemPrivateKey and password to load a key
    // of algo to generate a new one.
    this._privateKey = new SigningPrivateKey(opts);
    this._publicKey = this._privateKey.publicKey();
  }

  get private() {
    return this._privateKey;
  }

  get public() {
    return this._publicKey;
  }

  export = password => ({
    privateKey: this._privateKey.export(password),
    publicKey: this._publicKey.export()
  });
}

export class SigningPrivateKey {
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
      case SIGNING_ALGO_RSA.label: {
        this._key = rsa.generateKeyPair({ bits: 2048, e: 0x10001 }).privateKey;
        break;
      }
      case SIGNING_ALGO_ED25519.label: {
        // this._key = ed25519.generateKeyPair().privateKey;
        this._key = Buffer.from(
          'Xbasq0x/pvKMSjFJO9Ez0PDzBnfrJ0mlwS9taru10jdcX6TuycANPIsqN/2Y3Xyjp69EezwNx6k+dJq8HPGwzw==',
          'base64'
        );
        break;
      }
      default:
        throw new Error(`Unsupported signing algorithm "${algo}"`);
    }
  };

  load = (pemPrivateKey, password = null) => {
    if (password) {
      const msg = pem.decode(pemPrivateKey)[0];
      const keyInfo = pki.decryptPrivateKeyInfo(
        asn1.fromDer(msg.body),
        password
      );
      const { privateKey, algo } = decodePrivateKeyAsn1(keyInfo);
      this._key = privateKey;
      this._algo = algo;
      return;
    }

    const msg = pem.decode(pemPrivateKey)[0];

    if (msg.procType && msg.procType.type === 'ENCRYPTED') {
      throw new Error(
        'Could not convert private key from PEM; PEM is encrypted.'
      );
    }

    const keyInfo = asn1.fromDer(msg.body);
    const { privateKey, algo } = decodePrivateKeyAsn1(keyInfo);
    this._key = privateKey;
    this._algo = algo;
  };

  publicKey = () => {
    switch (this._algo) {
      case SIGNING_ALGO_RSA.label:
        return new SigningPublicKey({
          publicKey: pki.setRsaPublicKey(this._key.n, this._key.e),
          algo: this._algo
        });
      case SIGNING_ALGO_ED25519.label:
        return new SigningPublicKey({
          publicKey: ed25519.publicKeyFromPrivateKey({ privateKey: this._key }),
          algo: this._algo
        });
      default:
        throw new Error(`Unsupported signing algorithm "${this._algo}"`);
    }
  };

  sign = message => {
    switch (this._algo) {
      case SIGNING_ALGO_RSA.label: {
        const hash = md.sha1.create();
        hash.update(message, 'utf-8');

        const signature = this._key.sign(hash);
        return util.encode64(signature);
      }
      case SIGNING_ALGO_ED25519.label: {
        const signature = ed25519.sign({
          privateKey: this._key,
          encoding: 'binary',
          message
        });
        return signature.toString('base64');
      }
      default:
        throw new Error(`Unsupported signing algorithm "${this._algo}"`);
    }
  };

  export = (password = null) => {
    let privateKeyInfo;
    switch (this._algo) {
      case SIGNING_ALGO_RSA.label: {
        const privateKey = pki.privateKeyToAsn1(this._key);
        privateKeyInfo = pki.wrapRsaPrivateKey(privateKey);
        break;
      }
      case SIGNING_ALGO_ED25519.label: {
        const privateKey = ed25519PrivateKeyToAsn1(this._key);
        privateKeyInfo = wrapEd25519PrivateKey(privateKey);
        break;
      }

      default:
        throw new Error(`Unsupported signing algorithm "${this._algo}"`);
    }

    if (password) {
      const encryptedPrivateKeyInfo = pki.encryptPrivateKeyInfo(
        privateKeyInfo,
        password,
        { algorithm: 'aes256' }
      );

      // Export keys to pem format
      return pki.encryptedPrivateKeyToPem(encryptedPrivateKeyInfo);
    }

    const msg = {
      type: `${this._algo} PRIVATE KEY`,
      body: asn1.toDer(privateKeyInfo).getBytes()
    };
    return pem.encode(msg);
  };
}

export class SigningPublicKey {
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
    const derPublicKey = pem.decode(pemPublicKey);
    const asn1PublicKey = asn1.fromDer(derPublicKey[0].body);

    const { key, algo } = decodePublicKeyAsn1(asn1PublicKey);

    this._algo = algo;
    this._key = key;
  };

  verify = (message, signature) => {
    switch (this._algo) {
      case SIGNING_ALGO_RSA.label: {
        const hash = md.sha1.create();
        hash.update(message, 'utf-8');

        return this._key.verify(
          hash.digest().bytes(),
          util.decode64(signature)
        );
      }
      case SIGNING_ALGO_ED25519.label: {
        return ed25519.verify({
          publicKey: this._key,
          message,
          encoding: 'binary',
          signature: Buffer.from(signature, 'base64')
        });
      }

      default:
        throw new Error(`Unsupported signing algorithm "${this._algo}"`);
    }
  };

  export = () => {
    let asn1PublicKey;
    switch (this._algo) {
      case SIGNING_ALGO_RSA.label:
        asn1PublicKey = pki.publicKeyToAsn1(this._key);
        break;
      case SIGNING_ALGO_ED25519.label:
        asn1PublicKey = ed25519PublicKeyToAsn1(this._key);
        break;

      default:
        break;
    }
    const derPublicKey = asn1.toDer(asn1PublicKey);

    return pem.encode({
      type: `${this._algo} PUBLIC KEY`,
      body: derPublicKey.data
    });
  };
}

// ============================================================================
// ====                              ED25519                               ====
// ============================================================================

//
// export
//

// PRIVATE KEY
export const ed25519PrivateKeyToAsn1 = key =>
  asn1.create(asn1.UNIVERSAL, asn1.Type.OCTETSTRING, false, key);

export const wrapEd25519PrivateKey = key =>
  asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
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
      asn1.toDer(key).getBytes()
    )
  ]);

// PUBLIC KEY
const ed25519PublicKeyToAsn1 = key =>
  // SubjectPublicKeyInfo
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
      util.createBuffer(Buffer.concat([Buffer.from([0]), key])).getBytes()
    )
  ]);

//
// import
//

// PRIVATE KEY

export const decryptEd25519PrivateKey = (key, password) => {
  // TODO: Validation

  const msg = pem.decode(key)[0];
  const keyInfo = pki.decryptPrivateKeyInfo(asn1.fromDer(msg.body), password);
  return ed25519PrivateKeyFromAsn1(keyInfo);
};

// validator for a PrivateKeyInfo structure
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

// validator for an ED25519 private key
const ed25519PrivateKeyValidator = {
  name: 'ED25519PrivateKey',
  tagClass: asn1.Class.UNIVERSAL,
  type: asn1.Type.OCTETSTRING,
  constructed: false,
  capture: 'privateKey'
};

// decodePrivateKeyAsn1 returns an object containing the private key and the algo label.
export const decodePrivateKeyAsn1 = key => {
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
        privateKey: pki.privateKeyFromAsn1(obj),
        algo: SIGNING_ALGO_RSA.label
      };
    case SIGNING_ALGO_ED25519.oid:
      return {
        privateKey: ed25519PrivateKeyFromAsn1(obj),
        algo: SIGNING_ALGO_ED25519.label
      };
    default:
      throw new Error(`Unsupported signing algorithm OID ${oid}"`);
  }
};

const ed25519PrivateKeyFromAsn1 = key => {
  const capture = {};
  const errors = [];
  if (!asn1.validate(key, ed25519PrivateKeyValidator, capture, errors)) {
    const error = new Error(
      'Cannot readt private key. ASN.1 object does not contain an ED25519PrivateKey.'
    );
    error.errors = errors;
    throw error;
  }

  return unicodeToBuffer(capture.privateKey);
};

// PUBLIC KEY

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

export const decodePublicKeyAsn1 = key => {
  const capture = {};
  const errors = [];
  asn1.validate(key, publicKeyValidator, capture, errors);
  // get oid
  const oid = asn1.derToOid(capture.publicKeyOid);

  switch (oid) {
    case SIGNING_ALGO_RSA.oid:
      return {
        key: pki.publicKeyFromAsn1(capture.rsaPublicKey),
        algo: SIGNING_ALGO_RSA.label
      };
    case SIGNING_ALGO_ED25519.oid:
      return {
        key: unicodeToBuffer(capture.subjectPublicKeyED25519),
        algo: SIGNING_ALGO_ED25519.label
      };

    default:
      throw new Error(`Unsupported signing algorithm OID ${oid}"`);
  }
};

const unicodeToBuffer = str =>
  Buffer.from(str.split('').map(s => s.charCodeAt(0)));
