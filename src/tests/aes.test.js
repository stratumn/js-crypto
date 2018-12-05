import { util, random } from 'node-forge';

import cases from './cases.json';
import { SymmetricKey, SALT_LENGTH, TAG_LENGTH } from '../aes';

describe('SymmetricKey', () => {
  Object.entries(cases.aes).forEach(([k, v]) => {
    describe(k, () => {
      describe('encryption', () => {
        it('encrypts a message', () => {
          const key = new SymmetricKey(v.key);
          const msg = 'plap';

          const ciphertext = key.encrypt(msg);
          const plaintext = key.decrypt(ciphertext);
          expect(plaintext).toBe(msg);
        });

        it('errors if the ciphertext is badly formatted', () => {
          const key = new SymmetricKey(v.key);
          expect(() => key.decrypt('test')).toThrow('wrong ciphertext format');
        });
      });

      describe('decryption', () => {
        it('decrypts a message', () => {
          const key = new SymmetricKey(v.key);
          const encrypted = key.decrypt(v.ciphertext);

          expect(encrypted).toEqual(cases.message);
        });

        it('fails if the salt is modified', () => {
          const key = new SymmetricKey(v.key);

          const iv = random.getBytesSync(SALT_LENGTH);
          const badIv = util.encode64(
            `${iv}${util.decode64(v.ciphertext).slice(SALT_LENGTH)}`
          );
          expect(() => key.decrypt(badIv)).toThrow('error while decrypting');
        });

        it('fails if the tag does not match', () => {
          const key = new SymmetricKey(v.key);

          const tag = random.getBytesSync(TAG_LENGTH);
          const badTag = util.encode64(
            `${util.decode64(v.ciphertext).slice(0, -TAG_LENGTH)}${tag}`
          );
          expect(() => key.decrypt(badTag)).toThrow('error while decrypting');
        });

        it('fails if the ciphertext does not match', () => {
          const key = new SymmetricKey(v.key);

          const decodedBytes = util.decode64(v.ciphertext);
          const iv = decodedBytes.slice(0, SALT_LENGTH);
          const tag = decodedBytes.slice(-TAG_LENGTH);
          const ct = random.getBytesSync(
            decodedBytes.slice(SALT_LENGTH, -TAG_LENGTH).length
          );
          const badCiphertext = util.encode64(`${iv}${ct}${tag}`);
          expect(() => key.decrypt(badCiphertext)).toThrow(
            'error while decrypting'
          );
        });
      });
    });
  });
});
