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
          expectPEMStringsEqual(kp.private.export(), v.priv);
          expectPEMStringsEqual(kp.public.export(), v.pub);
        });

        it('should load encrypted key', () => {
          const kp = new SigningKeyPair({
            pemPrivateKey: v.encPriv,
            password: cases.password
          });
          expectPEMStringsEqual(kp.private.export(), v.priv);
          expectPEMStringsEqual(kp.public.export(), v.pub);
        });

        it('should export encrypted key', () => {
          const kp = new SigningKeyPair({ algo: k });
          const enc = kp.private.export(cases.password);

          const kp2 = new SigningKeyPair({
            pemPrivateKey: enc,
            password: cases.password
          });
          expectPEMStringsEqual(kp.private.export(), kp2.private.export());
        });
      });

      describe('Private Key', () => {
        it('should load and export', () => {
          const key = new SigningPrivateKey({ pemPrivateKey: v.priv });
          expectPEMStringsEqual(key.export(), v.priv);
        });

        it('should load encrypted key', () => {
          const key = new SigningPrivateKey({
            pemPrivateKey: v.encPriv,
            password: cases.password
          });
          expectPEMStringsEqual(key.export(), v.priv);
        });

        it('should export encrypted key', () => {
          const key = new SigningPrivateKey({ algo: k });
          const enc = key.export(cases.password);

          const key2 = new SigningPrivateKey({
            pemPrivateKey: enc,
            password: cases.password
          });
          expectPEMStringsEqual(key.export(), key2.export());
        });

        it('should sign message', () => {
          const key = new SigningPrivateKey({ pemPrivateKey: v.priv });
          const sig = key.sign(cases.message);
          expectPEMStringsEqual(sig, v.sig);
        });
      });

      describe('Public Key', () => {
        it('should load and export', () => {
          const key = new SigningPublicKey({ pemPublicKey: v.pub });
          expectPEMStringsEqual(key.export(), v.pub);
        });

        it('should verify signature', () => {
          const key = new SigningPublicKey({ pemPublicKey: v.pub });
          expect(key.verify(cases.message, v.sig)).toBe(true);
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
