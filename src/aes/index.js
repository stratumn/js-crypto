import { util, random, cipher } from 'node-forge';

// length of the salt in bytes.
export const SALT_LENGTH = 12;
// length of the tag in bytes.
export const TAG_LENGTH = 16;

export class SymmetricKey {
  static size = 256;

  constructor(key = null) {
    if (!key) this._key = random.getBytesSync(32);
    else this._key = util.decode64(key);
  }

  /*
    Encrypts a message with the symmetric key.
    It formats the encrypted message as follows:
      - base64(<iv><ciphertext><tag>)
  */
  encrypt = message => {
    const iv = random.getBytesSync(SALT_LENGTH);
    const ci = cipher.createCipher('AES-GCM', this._key);

    // 128 bits is the default MAC tag length that forge uses
    // but we set it explicitly for clarity purposes.
    ci.start({ iv, tagLength: TAG_LENGTH * 8 });
    ci.update(util.createBuffer(message));
    ci.finish();

    const ciphertext = `${iv}${ci.output.bytes()}${ci.mode.tag.bytes()}`;
    return util.encode64(ciphertext);
  };

  /*
    Decrypts a message with the symmetric key.
    It accepts a message formatted as follows:
      - base64(<iv><ciphertext><tag>)
  */
  decrypt = ciphertext => {
    if (ciphertext.length <= SALT_LENGTH + TAG_LENGTH) {
      throw new Error('wrong ciphertext format');
    }
    const encryptedBytes = util.decode64(ciphertext);
    const iv = encryptedBytes.slice(0, SALT_LENGTH);
    const tag = encryptedBytes.slice(-TAG_LENGTH);
    const ct = encryptedBytes.slice(SALT_LENGTH, -TAG_LENGTH);

    const de = cipher.createDecipher('AES-GCM', this._key);
    de.start({ iv, tag });
    de.update(util.createBuffer(ct));
    if (!de.finish()) {
      throw new Error('error while decrypting');
    }
    return de.output.data;
  };

  export = () => ({
    key: util.encode64(this._key)
  });
}
