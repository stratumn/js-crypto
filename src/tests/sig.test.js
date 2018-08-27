import { util } from 'node-forge';
import { SigningKeyPair, SigningPrivateKey, SigningPublicKey } from '../sig';

import cases from './cases.json';

describe('Signatures', () => {
  Object.entries(cases.sig).forEach(([k, v]) => {
    describe(k, () => {
      describe('Key Pair', () => {
        it('should generate', () => {
          const kp = new SigningKeyPair({ algo: k });
          expect(kp.private).not.toBeFalsy();
          expect(kp.public).not.toBeFalsy();
        });

        it('should load private key', () => {
          const kp = new SigningKeyPair({ pemPrivateKey: v.priv });
          expect(kp.private.export()).toBe(v.priv);
          expect(kp.public.export()).toBe(v.pub);
        });

        it('should load encrypted key', () => {
          const kp = new SigningKeyPair({
            pemPrivateKey: v.encPriv,
            password: cases.password
          });
          expect(kp.private.export()).toBe(v.priv);
          expect(kp.public.export()).toBe(v.pub);
        });

        it('should export encrypted key', () => {
          const kp = new SigningKeyPair({ algo: k });
          const enc = kp.private.export(cases.password);

          const kp2 = new SigningKeyPair({
            pemPrivateKey: enc,
            password: cases.password
          });
          expect(kp.private.export()).toBe(kp2.private.export());
        });
      });

      describe('Private Key', () => {
        it('should load and export', () => {
          const key = new SigningPrivateKey({ pemPrivateKey: v.priv });
          expect(key.export()).toBe(v.priv);
        });

        it('should load encrypted key', () => {
          const key = new SigningPrivateKey({
            pemPrivateKey: v.encPriv,
            password: cases.password
          });
          expect(key.export()).toBe(v.priv);
        });

        it('should export encrypted key', () => {
          const key = new SigningPrivateKey({ algo: k });
          const enc = key.export(cases.password);

          const key2 = new SigningPrivateKey({
            pemPrivateKey: enc,
            password: cases.password
          });
          expect(key.export()).toBe(key2.export());
        });

        it('should sign message', () => {
          const key = new SigningPrivateKey({ pemPrivateKey: v.priv });
          const sig = key.sign(cases.message);
          expect(util.decode64(sig.signature)).toBe(v.sig);
          expect(util.decode64(sig.public_key)).toBe(key.publicKey().export());
          expect(util.decode64(sig.message)).toBe(cases.message);
        });
      });

      describe('Public Key', () => {
        it('should load and export', () => {
          const key = new SigningPublicKey({ pemPublicKey: v.pub });
          expect(key.export()).toBe(v.pub);
        });

        it('should verify signature', () => {
          const key = new SigningPublicKey({ pemPublicKey: v.pub });
          expect(key.verify({ message: cases.message, signature: v.sig })).toBe(
            true
          );
        });

        it('should not verify bad signature', () => {
          const key = new SigningPublicKey({ pemPublicKey: v.pub });
          expect(
            key.verify({ message: 'some bad message', signature: v.sig })
          ).toBe(false);
        });
      });
    });
  });
});
