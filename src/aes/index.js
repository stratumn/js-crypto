import { util, random, cipher } from 'node-forge';

// length of the salt in bytes.
export const SALT_LENGTH = 12;
// length of the tag in bytes.
export const TAG_LENGTH = 16;

export class SymmetricKey {
  constructor(key = null) {
    if (!key) this._key = random.getBytesSync(32);
    else this._key = util.decode64(key);
  }

  /*
    Encrypts a message with the symmetric key.
    The encoding may be specified with the following values: 'utf8' (default), 'ascii', 'binary'
    It formats the encrypted message as follows:
      - base64(<iv><ciphertext><tag>)
  */
  encrypt = (
    message,
    plaintextEncoding = 'utf8',
    cipherTextEncoding = 'base64'
  ) => {
    if (!['binary', 'base64'].includes(cipherTextEncoding))
      throw new Error(
        `Invalid output encoding ${cipherTextEncoding}; should be "base64" or "binary"`
      );
    const iv = random.getBytesSync(SALT_LENGTH);
    const ci = cipher.createCipher('AES-GCM', this._key);

    // 128 bits is the default MAC tag length that forge uses
    // but we set it explicitly for clarity purposes.
    ci.start({ iv, tagLength: TAG_LENGTH * 8 });
    ci.update(util.createBuffer(message, plaintextEncoding));
    ci.finish();

    const ciphertext = `${iv}${ci.output.bytes()}${ci.mode.tag.bytes()}`;
    if (cipherTextEncoding === 'binary') return ciphertext;
    return util.encode64(ciphertext);
  };

  /*
    Decrypts a message with the symmetric key.
    The encoding may be specified with the following values: 'utf8' (default), 'ascii', 'binary'.
    Returns the decoded message as a string except if the encoding is set to
    'binary' (in which case the result will be a Buffer or an Uint8Array).
    It accepts a message formatted as follows:
      - cipherTextEncoding(<iv><ciphertext><tag>)
  */
  decrypt = (
    ciphertext,
    plaintextEncoding = 'utf8',
    cipherTextEncoding = 'base64'
  ) => {
    if (ciphertext.length <= SALT_LENGTH + TAG_LENGTH) {
      throw new Error('wrong ciphertext format');
    }
    if (!['binary', 'base64'].includes(cipherTextEncoding))
      throw new Error(
        `Invalid input encoding ${cipherTextEncoding}; should be "base64" or "binary"`
      );
    const encryptedBytes =
      cipherTextEncoding === 'binary' ? ciphertext : util.decode64(ciphertext);
    const iv = encryptedBytes.slice(0, SALT_LENGTH);
    const tag = encryptedBytes.slice(-TAG_LENGTH);
    const ct = encryptedBytes.slice(SALT_LENGTH, -TAG_LENGTH);

    const de = cipher.createDecipher('AES-GCM', this._key);
    de.start({ iv, tag });
    de.update(util.createBuffer(ct));
    if (!de.finish()) {
      throw new Error('error while decrypting');
    }

    if (plaintextEncoding === 'binary') {
      const decrypted = de.output.data;
      let res = Buffer.alloc(0);
      // Encode the decrpyted data per block of 4MB
      const chunkSize = 1024 * 1024 * 4; // 4MB
      let index = 0;
      do {
        res = Buffer.concat([
          res,
          Buffer.from(decrypted.substr(index, chunkSize), 'binary')
        ]);
        index += chunkSize;
      } while (index < decrypted.length);

      return res;
    }
    return de.output.toString(plaintextEncoding);
  };

  export = () => ({
    key: util.encode64(this._key)
  });
}
