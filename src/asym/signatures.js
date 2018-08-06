import { rsa, md, util, asn1, pem, pki, oids } from 'node-forge';
import {
  ED25519_OID,
  ED25519PrivateKey,
  ed25519PrivateKeyFromAsn1,
  ED25519PublicKey
} from './ed25519';

const PRIVATE_KEY_PEM_LABEL = 'PRIVATE KEY';
const PUBLIC_KEY_PEM_LABEL = 'PUBLIC KEY';
const SIGNATURE_PEM_LABEL = 'MESSAGE';

const SIGNING_ALGO_RSA = { name: 'RSA', oid: oids.rsaEncryption };
const SIGNING_ALGO_ED25519 = { name: 'ED25519', oid: ED25519_OID };

export const SIGNING_ALGOS = [SIGNING_ALGO_RSA.name, SIGNING_ALGO_ED25519.name];

export class SigningKeyPair {
  constructor(opts) {
    // opts should contain either pemPrivateKey and password to load a key
    // or algo to generate a new one.
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

// ============================================================================
// ====                           PRIVATE KEY                              ====
// ============================================================================

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
      case SIGNING_ALGO_RSA.name: {
        this._key = rsa.generateKeyPair({ bits: 2048, e: 0x10001 }).privateKey;
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
    const msg = pem.decode(pemPrivateKey)[0];
    if (password) {
      const keyInfo = pki.decryptPrivateKeyInfo(
        asn1.fromDer(msg.body),
        password
      );
      const { privateKey, algo } = decodePrivateKeyAsn1(keyInfo);
      this._key = privateKey;
      this._algo = algo;
      return;
    }

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
      case SIGNING_ALGO_RSA.name:
        return new SigningPublicKey({
          publicKey: pki.setRsaPublicKey(this._key.n, this._key.e),
          algo: this._algo
        });
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
      case SIGNING_ALGO_RSA.name: {
        const hash = md.sha256.create();
        hash.update(message, 'utf-8');
        sig = this._key.sign(hash);
        break;
      }
      case SIGNING_ALGO_ED25519.name: {
        sig = this._key.sign(message);
        break;
      }
      default:
        throw new Error(`Unsupported signing algorithm "${this._algo}"`);
    }

    return pem.encode({
      type: SIGNATURE_PEM_LABEL,
      body: sig
    });
  };

  export = (password = null) => {
    let privateKeyInfo;
    switch (this._algo) {
      case SIGNING_ALGO_RSA.name: {
        const privateKey = pki.privateKeyToAsn1(this._key);
        privateKeyInfo = pki.wrapRsaPrivateKey(privateKey);
        break;
      }
      case SIGNING_ALGO_ED25519.name: {
        privateKeyInfo = this._key.toPkcs8();
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
      type: privateKeyPEMLabel(this._algo),
      body: asn1.toDer(privateKeyInfo).getBytes()
    };
    return pem.encode(msg);
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

// ============================================================================
// ====                           PUBLIC KEY                               ====
// ============================================================================

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
    const { body } = pem.decode(signature)[0];
    switch (this._algo) {
      case SIGNING_ALGO_RSA.name: {
        const hash = md.sha256.create();
        hash.update(message, 'utf-8');

        return this._key.verify(hash.digest().bytes(), body);
      }
      case SIGNING_ALGO_ED25519.name: {
        return this._key.verify(message, body);
      }

      default:
        throw new Error(`Unsupported signing algorithm "${this._algo}"`);
    }
  };

  export = () => {
    let asn1PublicKey;
    switch (this._algo) {
      case SIGNING_ALGO_RSA.name:
        asn1PublicKey = pki.publicKeyToAsn1(this._key);
        break;
      case SIGNING_ALGO_ED25519.name:
        asn1PublicKey = this._key.toAsn1();
        break;

      default:
        break;
    }
    const derPublicKey = asn1.toDer(asn1PublicKey);

    return pem.encode({
      type: publicKeyPEMLabel(this._algo),
      body: derPublicKey.data
    });
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

// ============================================================================
// ====                             HELPERS                                ====
// ============================================================================

const unicodeToBuffer = str =>
  Buffer.from(str.split('').map(s => s.charCodeAt(0)));

const privateKeyPEMLabel = algoName => `${algoName} ${PRIVATE_KEY_PEM_LABEL}`;
const publicKeyPEMLabel = algoName => `${algoName} ${PUBLIC_KEY_PEM_LABEL}`;
