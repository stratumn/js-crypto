import { rsa, util, asn1, pem, pki } from 'node-forge';

import { SymmetricKey } from '../aes';

export class EncryptionKeyPair {
  constructor(pemPrivateKey = null, password = null) {
    if (pemPrivateKey) {
      this._privateKey = new EncryptionPrivateKey(pemPrivateKey, password);
    } else {
      this._privateKey = new EncryptionPrivateKey();
    }

    this._publicKey = this._privateKey.publicKey();
    this._password = password;
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

export class EncryptionPrivateKey {
  constructor(pemPrivateKey = null, password = null) {
    if (pemPrivateKey) {
      this._key = this.loadPrivateKey(pemPrivateKey, password);
    } else {
      const { privateKey } = rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
      this._key = privateKey;
    }
  }

  loadPrivateKey = (pemPrivateKey, password = null) => {
    if (password) {
      return pki.decryptRsaPrivateKey(pemPrivateKey, password);
    }

    return pki.privateKeyFromPem(pemPrivateKey);
  };

  publicKey = () => {
    const publicKey = pki.setRsaPublicKey(this._key.n, this._key.e);
    return new EncryptionPublicKey(publicKey);
  };

  decrypt = (encryptedKey, iv, cipherText) => {
    // Decrypt symmetric key with private key
    const key = this._key.decrypt(util.decode64(encryptedKey));
    const symmetricKey = new SymmetricKey(key, iv);

    // Decrypt message
    return symmetricKey.decrypt(cipherText);
  };

  export = (password = null) => {
    const rsaPrivateKey = pki.privateKeyToAsn1(this._key);
    const privateKeyInfo = pki.wrapRsaPrivateKey(rsaPrivateKey);

    if (password) {
      const encryptedPrivateKeyInfo = pki.encryptPrivateKeyInfo(
        privateKeyInfo,
        password,
        { algorithm: 'aes256' }
      );

      // Export keys to pem format
      return pki.encryptedPrivateKeyToPem(encryptedPrivateKeyInfo);
    }

    return pki.privateKeyInfoToPem(privateKeyInfo);
  };
}

export class EncryptionPublicKey {
  constructor(publicKey = null, pemPublicKey = null) {
    if (publicKey) {
      this._key = publicKey;
    } else {
      this._key = this.loadPublicKey(pemPublicKey);
    }
  }

  loadPublicKey = pemPublicKey => {
    const derPublicKey = pem.decode(pemPublicKey);
    const asn1PublicKey = asn1.fromDer(derPublicKey[0].body);

    return pki.publicKeyFromAsn1(asn1PublicKey);
  };

  encrypt = message => {
    // Generate a symmetric key to encrypt the message
    const symmetricKey = new SymmetricKey();
    const cipherText = symmetricKey.encrypt(message);

    // Encrypt symmetric key with public key
    const { key, iv } = symmetricKey.export();
    const encryptedKey = util.encode64(this._key.encrypt(key));

    return { encryptedKey, iv, cipherText };
  };

  export = () => {
    const asn1PublicKey = pki.publicKeyToAsn1(this._key);
    const derPublicKey = asn1.toDer(asn1PublicKey);

    return pem.encode({
      type: 'RSA PUBLIC KEY',
      body: derPublicKey.data
    });
  };
}
