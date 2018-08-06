import { rsa, pki, md } from 'node-forge';

// ============================================================================
// ====                           PRIVATE KEY                              ====
// ============================================================================

export class RSAPrivateKey {
  constructor(key = null) {
    if (!key) this.generate();
    else this._key = key;
  }

  generate = () => {
    this._key = rsa.generateKeyPair({ bits: 2048, e: 0x10001 }).privateKey;
  };

  publicKey = () =>
    new RSAPublicKey(pki.setRsaPublicKey(this._key.n, this._key.e));

  sign = message => {
    const hash = md.sha256.create();
    hash.update(message, 'utf-8');
    return this._key.sign(hash);
  };

  toPkcs8 = () => {
    const privateKey = pki.privateKeyToAsn1(this._key);
    return pki.wrapRsaPrivateKey(privateKey);
  };
}

// ============================================================================
// ====                           PUBLIC KEY                               ====
// ============================================================================

export class RSAPublicKey {
  constructor(key) {
    this._key = key;
  }

  verify = (message, signature) => {
    const hash = md.sha256.create();
    hash.update(message, 'utf-8');
    return this._key.verify(hash.digest().bytes(), signature);
  };

  toAsn1 = () => pki.publicKeyToAsn1(this._key);
}
