import { util, random, cipher } from 'node-forge';

export class SymmetricKey {
  constructor(key = null, iv = null) {
    if (!key || !iv) {
      this._key = random.getBytesSync(32);
      this._iv = random.getBytesSync(16);
    } else {
      this._key = util.decode64(key);
      this._iv = util.decode64(iv);
    }
  }

  encrypt = message => {
    const ci = cipher.createCipher('AES-CBC', this._key);
    ci.start({ iv: this._iv });
    ci.update(util.createBuffer(message));
    ci.finish();

    return util.encode64(ci.output.bytes());
  };

  decrypt = cipherText => {
    const de = cipher.createDecipher('AES-CBC', this._key);
    de.start({ iv: this._iv });
    de.update(util.createBuffer(util.decode64(cipherText)));
    de.finish();

    return de.output.data;
  };

  export = () => ({
    key: util.encode64(this._key),
    iv: util.encode64(this._iv)
  });
}
