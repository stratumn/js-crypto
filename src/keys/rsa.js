import { rsa, pki, md, util } from 'node-forge';
import { SymmetricKey } from '../aes';

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

  decrypt = (encryptedKey, iv, cipherText) => {
    // Decrypt symmetric key with private key
    const key = this._key.decrypt(util.decode64(encryptedKey), 'RSA-OAEP');
    const symmetricKey = new SymmetricKey(key, iv);

    // Decrypt message
    return symmetricKey.decrypt(cipherText);
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

  encrypt = message => {
    // Generate a symmetric key to encrypt the message
    const symmetricKey = new SymmetricKey();
    const cipherText = symmetricKey.encrypt(message);

    // Encrypt symmetric key with public key
    const { key, iv } = symmetricKey.export();
    const encryptedKey = util.encode64(this._key.encrypt(key, 'RSA-OAEP'));

    return { encryptedKey, iv, cipherText };
  };

  toAsn1 = () => pki.publicKeyToAsn1(this._key);
}
