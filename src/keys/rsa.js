import { rsa, pki, md, util } from 'node-forge';
import { SymmetricKey } from '../aes';

import { bytesToString } from '../utils';

// ============================================================================
// ====                           PRIVATE KEY                              ====
// ============================================================================

export class RSAPrivateKey {
  constructor(key = null) {
    if (!key) this.generate();
    else this._key = key;
  }

  generate = () => {
    this._key = rsa.generateKeyPair({ bits: 2048 }).privateKey;
  };

  publicKey = () =>
    new RSAPublicKey(pki.setRsaPublicKey(this._key.n, this._key.e));

  sign = message => {
    const hash = md.sha256.create();
    hash.update(bytesToString(message));
    return this._key.sign(hash);
  };

  decrypt = ciphertext => {
    // the length of the encrypted aes key is equal to
    // the modulus of the RSA key.
    const modulus = this._key.n.bitLength() / 8;

    const decodedBytes = util.decode64(ciphertext);
    const encryptedAESKey = decodedBytes.slice(0, modulus);
    const message = decodedBytes.slice(SymmetricKey.size);

    if (!encryptedAESKey || !message) {
      throw new Error('wrong ciphertext format');
    }
    // Decrypt symmetric key with private key
    const key = this._key.decrypt(encryptedAESKey, 'RSA-OAEP');
    const symmetricKey = new SymmetricKey(key);

    // Decrypt message
    return symmetricKey.decrypt(util.encode64(message));
  };

  decryptShort = ciphertext =>
    this._key.decrypt(util.decode64(ciphertext), 'RSA-OAEP');

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
    hash.update(bytesToString(message));
    return this._key.verify(hash.digest().bytes(), signature);
  };

  /*
  Encrypts a message.
  It formats the encrypted message as follows:
  - <encryptedAESKey><ciphertext>
  */
  encrypt = message => {
    // Generate a symmetric key to encrypt the message
    const symmetricKey = new SymmetricKey();
    const ciphertext = symmetricKey.encrypt(message);

    // Encrypt symmetric key with public key
    const { key } = symmetricKey.export();
    const encryptedAESKey = util.encode64(this._key.encrypt(key, 'RSA-OAEP'));

    return `${encryptedAESKey}${ciphertext}`;
  };

  encryptShort = message =>
    util.encode64(this._key.encrypt(message, 'RSA-OAEP'));

  toAsn1 = () => pki.publicKeyToAsn1(this._key);
}
