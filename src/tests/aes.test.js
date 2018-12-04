import { SymmetricKey } from '../aes';
import { Buffer } from 'safe-buffer';
import { util } from 'node-forge';

const mockGetBytesSync = jest.fn().mockReturnValue(new Buffer.from('Salt'));
const mockCipher = {
  start: jest.fn(),
  update: jest.fn(),
  finish: jest.fn(),
  output: {
    bytes: jest.fn().mockReturnValue(new Buffer.from('Ciphertext')),
    data: 'decrypted'
  },
  mode: {
    tag: {
      bytes: jest.fn().mockReturnValue(new Buffer.from('Tag'))
    }
  }
};
const mockCreateCipher = jest.fn().mockReturnValue(mockCipher);
const mockCreateDecipher = jest.fn().mockReturnValue(mockCipher);

jest.mock('node-forge', () => ({
  util: jest.requireActual('node-forge').util,
  random: {
    getBytesSync: length => mockGetBytesSync(length)
  },
  cipher: {
    createCipher: (cipher, key) => mockCreateCipher(cipher, key),
    createDecipher: (cipher, key) => mockCreateDecipher(cipher, key)
  }
}));

describe('SymmetricKey', () => {
  let key;
  beforeEach(() => {
    key = new SymmetricKey();
    mockGetBytesSync.mockClear();
    mockCreateDecipher.mockClear();
    mockCreateCipher.mockClear();
    mockCipher.start.mockClear();
    mockCipher.update.mockClear();
    mockCipher.start.mockClear();
    mockCipher.finish.mockClear();
  });

  describe('encryption', () => {
    it('encrypts a message', () => {
      const encrypted = key.encrypt('message');

      expect(mockGetBytesSync).toHaveBeenCalledWith(12);
      expect(mockCreateCipher).toHaveBeenCalledWith(
        'AES-GCM',
        expect.anything()
      );
      expect(mockCipher.start).toHaveBeenCalledTimes(1);
      expect(mockCipher.update).toHaveBeenCalledWith(
        util.createBuffer('message')
      );
      expect(mockCipher.finish).toHaveBeenCalledTimes(1);

      expect(encrypted).toEqual(util.encode64('SaltCiphertextTag'));
    });
  });

  it('errors if the ciphertext is badly formatted', () => {
    expect(() => key.decrypt('test')).toThrow('wrong ciphertext format');
  });

  it('decrypts a message', () => {
    const encrypted = key.decrypt(
      util.encode64('SALTLENGTH12<ciphertext>TAGLENGTHSIXTEEN')
    );

    expect(mockCreateDecipher).toHaveBeenCalledWith(
      'AES-GCM',
      expect.anything()
    );
    expect(mockCipher.start).toHaveBeenCalledWith({
      tag: 'TAGLENGTHSIXTEEN',
      iv: 'SALTLENGTH12'
    });
    expect(mockCipher.update).toHaveBeenCalledWith(
      util.createBuffer('<ciphertext>')
    );
    expect(mockCipher.finish).toHaveBeenCalledTimes(1);

    expect(encrypted).toEqual('decrypted');
  });
});
