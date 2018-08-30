import { stratumn } from '../proto/crypto_pb';

/**
 * convert a string into its byte array representation.
 * @returns {Uint8Array}
 */
export const stringToBytes = str => {
  const array = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i += 1) {
    array[i] = str.charCodeAt(i);
  }
  return array;
};

/**
 * convert a byte array into a string
 * @param {Uint8Array} ba - the Uint8Array of bytes
 * @returns {string} - the string representation
 */
export const bytesToString = ba => String.fromCharCode.apply(null, ba);

/**
 * concatenate two Uint8Arrays into a third one
 * @param {Uint8Array} a1
 * @param {Uint8Array} a2
 * @returns {Uint8Array} - the concatenation of a1 and a2
 */
export const concatUint8Arrays = (a1, a2) => {
  const res = new Uint8Array(a1.length + a2.length);
  res.set(a1);
  res.set(a2, a1.length);
  return res;
};

/**
 * convert a plain JS signature object into a protobuf one.
 */
export const sigToPb = obj => {
  try {
    return stratumn.crypto.Signature.fromObject(obj);
  } catch (err) {
    throw new Error('bad encoding, argument fields should be bytes');
  }
};
