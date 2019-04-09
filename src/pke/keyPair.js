import EncryptionPrivateKey from './privateKey';

export default class EncryptionKeyPair {
  static generateAsync = async algo => {
    const keyPair = new EncryptionKeyPair({ generate: false });
    keyPair._privateKey = await EncryptionPrivateKey.generateAsync(algo);
    keyPair._publicKey = keyPair._privateKey.publicKey();
    return keyPair;
  };

  constructor(opts) {
    // opts can contain either pemPrivateKey and password to load a key
    // or algo to generate a new one. It can also forgo key generation
    // to use the more preformant async option.
    if (opts.generate !== false) {
      this._privateKey = new EncryptionPrivateKey(opts);
      this._publicKey = this._privateKey.publicKey();
    }
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
