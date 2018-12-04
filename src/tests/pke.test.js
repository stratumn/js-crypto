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
          expect(kp.private.export()).toBe(v.priv);
          expect(kp.public.export()).toBe(v.pub);
        });

        it('should load encrypted key', () => {
          const kp = new EncryptionKeyPair({
            pemPrivateKey: v.encPriv,
            password: cases.password
          });
          expect(kp.private.export()).toBe(v.priv);
          expect(kp.public.export()).toBe(v.pub);
        });

        it('should export encrypted key', () => {
          const kp = new EncryptionKeyPair({ algo: k });
          const enc = kp.private.export(cases.password);

          const kp2 = new EncryptionKeyPair({
            pemPrivateKey: enc,
            password: cases.password
          });
          expect(kp.private.export()).toBe(kp2.private.export());
        });
      });

      describe('Private Key', () => {
        it('should load and export', () => {
          const key = new EncryptionPrivateKey({ pemPrivateKey: v.priv });
          expect(key.export()).toBe(v.priv);
        });

        it('should load encrypted key', () => {
          const key = new EncryptionPrivateKey({
            pemPrivateKey: v.encPriv,
            password: cases.password
          });
          expect(key.export()).toBe(v.priv);
        });

        it('should export encrypted key', () => {
          const key = new EncryptionPrivateKey({ algo: k });
          const enc = key.export(cases.password);

          const key2 = new EncryptionPrivateKey({
            pemPrivateKey: enc,
            password: cases.password
          });
          expect(key.export()).toBe(key2.export());
        });

        it('should decrypt message', () => {
          const key = new EncryptionPrivateKey({ pemPrivateKey: v.priv });
          const plaintext = key.decrypt(v.ciphertext);
          expect(plaintext).toBe(cases.message);
        });

        it('errors when message is badly formatted', () => {
          const key = new EncryptionPrivateKey({ pemPrivateKey: v.priv });
          expect(() => key.decrypt('message')).toThrow(
            'wrong ciphertext format'
          );
        });

        it('should decrypt a short message', () => {
          const key = new EncryptionPrivateKey({ pemPrivateKey: v.priv });
          const plaintext = key.decryptShort(v.shortCiphertext);
          expect(plaintext).toBe(cases.message);
        });
      });

      describe('Public Key', () => {
        it('should load and export', () => {
          const key = new EncryptionPublicKey({ pemPublicKey: v.pub });
          expect(key.export()).toBe(v.pub);
        });

        it('should encrypt message', () => {
          const pk = new EncryptionPublicKey({ pemPublicKey: v.pub });
          const sk = new EncryptionPrivateKey({ pemPrivateKey: v.priv });
          const msg = 'plap';

          const ciphertext = pk.encrypt(msg);
          const plaintext = sk.decrypt(ciphertext);
          expect(plaintext).toBe(msg);
        });

        it('should encrypt a short message', () => {
          const pk = new EncryptionPublicKey({ pemPublicKey: v.pub });
          const sk = new EncryptionPrivateKey({ pemPrivateKey: v.priv });
          const msg = 'plap';

          const ciphertext = pk.encrypt(msg);
          const plaintext = sk.decrypt(ciphertext);
          expect(plaintext).toBe(msg);
        });
      });
    });
  });
});
