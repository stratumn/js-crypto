import { asn1, pem, pki, util } from 'node-forge';

// ============================================================================
// =====                             ENCODING                             =====
// ============================================================================

const PRIVATE_KEY_PEM_LABEL = 'PRIVATE KEY';
const PUBLIC_KEY_PEM_LABEL = 'PUBLIC KEY';
const SIGNATURE_PEM_LABEL = 'MESSAGE';

const privateKeyPEMLabel = algoName => `${algoName} ${PRIVATE_KEY_PEM_LABEL}`;
const publicKeyPEMLabel = algoName => `${algoName} ${PUBLIC_KEY_PEM_LABEL}`;

// Encode an ASN1 encoded private to PEM
export const encodePrivateKeyInfo = (asn1PrivateKeyInfo, algo) =>
  pem.encode({
    type: privateKeyPEMLabel(algo),
    body: asn1.toDer(asn1PrivateKeyInfo).getBytes()
  });

// encode an ASN1 encoded public key to PEM
export const encodePublicKey = (asn1PublicKey, algo) =>
  pem.encode({
    type: publicKeyPEMLabel(algo),
    body: asn1.toDer(asn1PublicKey).getBytes()
  });

// encode a signature to PEM
export const encodeSignature = sig =>
  pem.encode({
    type: SIGNATURE_PEM_LABEL,
    body: sig
  });

// ============================================================================
// =====                             DECODING                             =====
// ============================================================================
// decode a PEM encoded signature key
export const decodeSignature = pemSignature => pem.decode(pemSignature)[0].body;

/*
  PUBLIC KEY
*/

// decode a PEM encoded public key.
// returns an object containing the asn1 data, including:
// - oid the algo identifier
// - rsaPublicKey if the algo is rsa
// - curve25519PublicKey if we are in a curve25519 algo
export const decodePublicKey = pemPublicKey => {
  const derPublicKey = pem.decode(pemPublicKey);
  return decodePublicKeyAsn1(asn1.fromDer(derPublicKey[0].body));
};

// validator for a SubjectPublicKeyInfo structure
// Same as here: https://github.com/digitalbazaar/forge/blob/master/lib/rsa.js#L226
// we copied this here because we need to do additionnal work on the switch in `decodePublicKeyAsn1`
// to include Curve25519 logic

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
          captureAsn1: 'rsaPublicKey'
        }
      ]
    },
    {
      // Curve25519
      name: 'SubjectPublicKeyInfo.subjectPublicKey',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.BITSTRING,
      constructed: false,
      optional: true,
      captureBitStringValue: 'curve25519PublicKey'
    }
  ]
};

const decodePublicKeyAsn1 = key => {
  const capture = {};
  const errors = [];
  asn1.validate(key, publicKeyValidator, capture, errors);
  return {
    ...capture,
    oid: asn1.derToOid(capture.publicKeyOid)
  };
};

/*
  PRIVATE KEY
*/

// decode - and decrypt if necessary - a PEM encoded private key embedded in PKCS#8 to ASN1.
// returns the oid and the key asn1.
export const decodePrivateKey = (pemPrivateKey, password = null) => {
  let keyInfo;
  const msg = pem.decode(pemPrivateKey)[0];
  if (password) {
    keyInfo = pki.decryptPrivateKeyInfo(asn1.fromDer(msg.body), password);
  } else {
    if (msg.procType && msg.procType.type === 'ENCRYPTED') {
      throw new Error(
        'Could not convert private key from PEM; PEM is encrypted.'
      );
    }

    keyInfo = asn1.fromDer(msg.body);
  }
  return decodePrivateKeyAsn1(keyInfo);
};

// validator for a PrivateKeyInfo structure
// Same as here: https://github.com/digitalbazaar/forge/blob/master/lib/rsa.js#L91
// we copied this here because we need to do additionnal work on the switch in `decodePrivateKeyAsn1`
// to include Curve25519 logic
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
const decodePrivateKeyAsn1 = keyInfo => {
  // Get private key info
  const capture = {};
  const errors = [];
  if (!asn1.validate(keyInfo, privateKeyValidator, capture, errors)) {
    throw new Error('private key should be PKCS#8 embedded');
  }

  const key = asn1.fromDer(util.createBuffer(capture.privateKey));
  const oid = asn1.derToOid(capture.privateKeyOid);

  return { oid, key };
};
