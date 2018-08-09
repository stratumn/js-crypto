import {
  EncryptionKeyPair,
  EncryptionPrivateKey,
  EncryptionPublicKey
} from '../pke';

import cases from './cases.json';

describe('Encryption', () => {
  Object.entries(cases.pke).forEach(([k, v]) => {
    describe(k, () => {
      describe('Key Pair', () => {
        it('should generate', () => {
          const kp = new EncryptionKeyPair({ algo: k });
          expect(kp.private).not.toBeFalsy();
          expect(kp.public).not.toBeFalsy();
        });

        it('should load private key', () => {
          const kp = new EncryptionKeyPair({ pemPrivateKey: v.priv });
          expectPEMStringsEqual(kp.private.export(), v.priv);
          expectPEMStringsEqual(kp.public.export(), v.pub);
        });

        it('should load encrypted key', () => {
          const kp = new EncryptionKeyPair({
            pemPrivateKey: v.encPriv,
            password: cases.password
          });
          expectPEMStringsEqual(kp.private.export(), v.priv);
          expectPEMStringsEqual(kp.public.export(), v.pub);
        });

        it('should export encrypted key', () => {
          const kp = new EncryptionKeyPair({ algo: k });
          const enc = kp.private.export(cases.password);

          const kp2 = new EncryptionKeyPair({
            pemPrivateKey: enc,
            password: cases.password
          });
          expectPEMStringsEqual(kp.private.export(), kp2.private.export());
        });
      });

      describe('Private Key', () => {
        it('should load and export', () => {
          const key = new EncryptionPrivateKey({ pemPrivateKey: v.priv });
          expectPEMStringsEqual(key.export(), v.priv);
        });

        it('should load encrypted key', () => {
          const key = new EncryptionPrivateKey({
            pemPrivateKey: v.encPriv,
            password: cases.password
          });
          expectPEMStringsEqual(key.export(), v.priv);
        });

        it('should export encrypted key', () => {
          const key = new EncryptionPrivateKey({ algo: k });
          const enc = key.export(cases.password);

          const key2 = new EncryptionPrivateKey({
            pemPrivateKey: enc,
            password: cases.password
          });
          expectPEMStringsEqual(key.export(), key2.export());
        });

        it('should decrypt message', () => {
          const key = new EncryptionPrivateKey({ pemPrivateKey: v.priv });
          const { ciphertext, iv, tag, encryptedKey } = v.encMessage;
          const plaintext = key.decrypt(encryptedKey, ciphertext, iv, tag);
          expect(plaintext).toBe(cases.message);
        });
      });

      describe('Public Key', () => {
        it('should load and export', () => {
          const key = new EncryptionPublicKey({ pemPublicKey: v.pub });
          expectPEMStringsEqual(key.export(), v.pub);
        });

        it('should encrypt message', () => {
          const pk = new EncryptionPublicKey({ pemPublicKey: v.pub });
          const sk = new EncryptionPrivateKey({ pemPrivateKey: v.priv });
          const msg = 'plap';

          const { ciphertext, iv, tag, encryptedKey } = pk.encrypt(msg);
          const plaintext = sk.decrypt(encryptedKey, ciphertext, iv, tag);
          expect(plaintext).toBe(msg);
        });
      });
    });
  });
});

// Remove new lines fomr PEM strings before comparing them
const expectPEMStringsEqual = (str1, str2) => {
  const rmNewLines = str => str.replace(/\r\n|\n/gm, '');
  expect(rmNewLines(str1)).toBe(rmNewLines(str2));
};
