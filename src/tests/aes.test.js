import { readFile } from 'fs';
import path from 'path';
import { util, random } from 'node-forge';

import cases from './cases.json';
import {
  SymmetricKey,
  SALT_LENGTH,
  TAG_LENGTH,
  CIPHERTEXT_ENCODING_BIN
} from '../aes';

describe('SymmetricKey', () => {
  Object.entries(cases.aes).forEach(([k, v]) => {
    describe(k, () => {
      describe('encryption', () => {
        it('encrypts a message to base64', () => {
          const key = new SymmetricKey(v.key);
          const msg = 'plap';

          const ciphertext = key.encrypt(msg);
          const ctBinary = Buffer.from(ciphertext, 'base64').toString(
            CIPHERTEXT_ENCODING_BIN
          );
          expect(key.decrypt(ciphertext)).toBe(msg);
          expect(key.decrypt(ctBinary, 'utf8', CIPHERTEXT_ENCODING_BIN)).toBe(
            msg
          );
        });

        it('encrypts a message to binary', () => {
          const key = new SymmetricKey(v.key);
          const msg = 'plap';

          const ciphertext = key.encrypt(msg, 'utf8', CIPHERTEXT_ENCODING_BIN);
          const ctB64 = Buffer.from(
            ciphertext,
            CIPHERTEXT_ENCODING_BIN
          ).toString('base64');
          expect(key.decrypt(ciphertext, 'utf8', CIPHERTEXT_ENCODING_BIN)).toBe(
            msg
          );
          expect(key.decrypt(ctB64)).toBe(msg);
        });

        it('supports utf-8 characters', () => {
          const key = new SymmetricKey(v.key);
          const utf8Msg = '≤';

          const ciphertext = key.encrypt(utf8Msg);
          const plaintext = key.decrypt(ciphertext);

          expect(plaintext).toEqual(utf8Msg);
        });

        it('supports binary characters', done => {
          const key = new SymmetricKey(v.key);
          const file = './fixtures/testPicture.jpg';
          readFile(path.resolve(__dirname, file), (err, data) => {
            expect(err).toBe(null);
            const ciphertext = key.encrypt(data, CIPHERTEXT_ENCODING_BIN);
            const plaintext = Buffer.from(
              key.decrypt(ciphertext, CIPHERTEXT_ENCODING_BIN),
              CIPHERTEXT_ENCODING_BIN
            );
            expect(plaintext).toEqual(data);
            done();
          });
        });
      });

      describe('decryption', () => {
        it('decrypts a message from base64', () => {
          const key = new SymmetricKey(v.key);
          const encrypted = key.decrypt(v.ciphertext);

          expect(encrypted).toEqual(cases.message);
        });

        it('decrypts a message from binary', () => {
          const key = new SymmetricKey(v.key);
          const encrypted = key.decrypt(
            Buffer.from(v.ciphertext, 'base64'),
            'utf8',
            CIPHERTEXT_ENCODING_BIN
          );

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

        it('errors if the ciphertext is badly formatted', () => {
          const key = new SymmetricKey(v.key);
          expect(() => key.decrypt('test')).toThrow('wrong ciphertext format');
        });
      });
    });
  });
});
