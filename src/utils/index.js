import { util } from 'node-forge';

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
 * convert a Uint8Array its string base 64 representation
 */
export const bytesToB64String = arr => util.encode64(bytesToString(arr));

/**
 * convert a base64 encoded string to its Uint8Array representation
 */
export const b64StringToBytes = str => stringToBytes(util.decode64(str));

/**
 * encode a string in base64
 */
export const stringToB64String = util.encode64;

/**
 * decode a base 64 string
 */
export const b64StringToString = util.decode64;

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
 * deserialize base64 strings into Uint8Arrays
 */
export const signatureFromJson = sig => ({
  signature: sig.signature ? b64StringToBytes(sig.signature) : new Uint8Array(),
  message: sig.message ? b64StringToBytes(sig.message) : new Uint8Array(),
  public_key: sig.public_key
    ? b64StringToBytes(sig.public_key)
    : new Uint8Array()
});

/**
 * serialize all Uint8Arrays into base64 strings
 */
export const signatureToJson = sig => ({
  signature: sig.signature ? bytesToB64String(sig.signature) : '',
  message: sig.message ? bytesToB64String(sig.message) : '',
  public_key: sig.public_key ? bytesToB64String(sig.public_key) : ''
});
