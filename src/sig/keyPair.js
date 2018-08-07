import SigningPrivateKey from './privateKey';

export default class SigningKeyPair {
  constructor(opts) {
    // opts should contain either pemPrivateKey and password to load a key
    // or algo to generate a new one.
    this._privateKey = new SigningPrivateKey(opts);
    this._publicKey = this._privateKey.publicKey();
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
