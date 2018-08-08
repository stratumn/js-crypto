import { asn1, pem, pki } from 'node-forge';

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

// decode - and decrypt if necessary - a PEM encoded private key to ASN1.
export const decodePrivateKey = (pemPrivateKey, password = null) => {
  const msg = pem.decode(pemPrivateKey)[0];
  if (password) {
    return pki.decryptPrivateKeyInfo(asn1.fromDer(msg.body), password);
  }
  if (msg.procType && msg.procType.type === 'ENCRYPTED') {
    throw new Error(
      'Could not convert private key from PEM; PEM is encrypted.'
    );
  }

  return asn1.fromDer(msg.body);
};

// decode a PEM encoded public key
export const decodePublicKey = pemPublicKey => {
  const derPublicKey = pem.decode(pemPublicKey);
  return asn1.fromDer(derPublicKey[0].body);
};

// decode a PEM encoded signature key
export const decodeSignature = pemSignature => pem.decode(pemSignature)[0].body;
