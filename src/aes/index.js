import { util, random, cipher } from 'node-forge';

export class SymmetricKey {
  constructor(key = null) {
    if (!key) this._key = random.getBytesSync(32);
    else this._key = util.decode64(key);
  }

  encrypt = message => {
    const iv = random.getBytesSync(12);
    const ci = cipher.createCipher('AES-GCM', this._key);
    ci.start({ iv });
    ci.update(util.createBuffer(message));
    ci.finish();

    return {
      ciphertext: util.encode64(ci.output.bytes()),
      iv: util.encode64(iv),
      tag: util.encode64(ci.mode.tag.bytes())
    };
  };

  decrypt = (cipherText, iv, tag) => {
    const de = cipher.createDecipher('AES-GCM', this._key);
    de.start({ iv: util.decode64(iv), tag: util.decode64(tag) });
    de.update(util.createBuffer(util.decode64(cipherText)));
    de.finish();

    return de.output.data;
  };

  export = () => ({
    key: util.encode64(this._key)
  });
}
