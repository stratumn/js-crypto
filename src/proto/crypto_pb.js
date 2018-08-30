/*eslint-disable block-scoped-var, id-length, no-control-regex, no-magic-numbers, no-prototype-builtins, no-redeclare, no-shadow, no-var, sort-vars*/
"use strict";

var $protobuf = require("protobufjs/minimal");

// Common aliases
var $Reader = $protobuf.Reader, $Writer = $protobuf.Writer, $util = $protobuf.util;

// Exported root namespace
var $root = $protobuf.roots["default"] || ($protobuf.roots["default"] = {});

$root.stratumn = (function() {

    /**
     * Namespace stratumn.
     * @exports stratumn
     * @namespace
     */
    var stratumn = {};

    stratumn.crypto = (function() {

        /**
         * Namespace crypto.
         * @memberof stratumn
         * @namespace
         */
        var crypto = {};

        crypto.Signature = (function() {

            /**
             * Properties of a Signature.
             * @memberof stratumn.crypto
             * @interface ISignature
             * @property {Uint8Array|null} [publicKey] Signature publicKey
             * @property {Uint8Array|null} [signature] Signature signature
             * @property {Uint8Array|null} [message] Signature message
             */

            /**
             * Constructs a new Signature.
             * @memberof stratumn.crypto
             * @classdesc Represents a Signature.
             * @implements ISignature
             * @constructor
             * @param {stratumn.crypto.ISignature=} [properties] Properties to set
             */
            function Signature(properties) {
                if (properties)
                    for (var keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                        if (properties[keys[i]] != null)
                            this[keys[i]] = properties[keys[i]];
            }

            /**
             * Signature publicKey.
             * @member {Uint8Array} publicKey
             * @memberof stratumn.crypto.Signature
             * @instance
             */
            Signature.prototype.publicKey = $util.newBuffer([]);

            /**
             * Signature signature.
             * @member {Uint8Array} signature
             * @memberof stratumn.crypto.Signature
             * @instance
             */
            Signature.prototype.signature = $util.newBuffer([]);

            /**
             * Signature message.
             * @member {Uint8Array} message
             * @memberof stratumn.crypto.Signature
             * @instance
             */
            Signature.prototype.message = $util.newBuffer([]);

            /**
             * Creates a new Signature instance using the specified properties.
             * @function create
             * @memberof stratumn.crypto.Signature
             * @static
             * @param {stratumn.crypto.ISignature=} [properties] Properties to set
             * @returns {stratumn.crypto.Signature} Signature instance
             */
            Signature.create = function create(properties) {
                return new Signature(properties);
            };

            /**
             * Encodes the specified Signature message. Does not implicitly {@link stratumn.crypto.Signature.verify|verify} messages.
             * @function encode
             * @memberof stratumn.crypto.Signature
             * @static
             * @param {stratumn.crypto.ISignature} message Signature message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            Signature.encode = function encode(message, writer) {
                if (!writer)
                    writer = $Writer.create();
                if (message.publicKey != null && message.hasOwnProperty("publicKey"))
                    writer.uint32(/* id 2, wireType 2 =*/18).bytes(message.publicKey);
                if (message.signature != null && message.hasOwnProperty("signature"))
                    writer.uint32(/* id 3, wireType 2 =*/26).bytes(message.signature);
                if (message.message != null && message.hasOwnProperty("message"))
                    writer.uint32(/* id 4, wireType 2 =*/34).bytes(message.message);
                return writer;
            };

            /**
             * Encodes the specified Signature message, length delimited. Does not implicitly {@link stratumn.crypto.Signature.verify|verify} messages.
             * @function encodeDelimited
             * @memberof stratumn.crypto.Signature
             * @static
             * @param {stratumn.crypto.ISignature} message Signature message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            Signature.encodeDelimited = function encodeDelimited(message, writer) {
                return this.encode(message, writer).ldelim();
            };

            /**
             * Decodes a Signature message from the specified reader or buffer.
             * @function decode
             * @memberof stratumn.crypto.Signature
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @param {number} [length] Message length if known beforehand
             * @returns {stratumn.crypto.Signature} Signature
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            Signature.decode = function decode(reader, length) {
                if (!(reader instanceof $Reader))
                    reader = $Reader.create(reader);
                var end = length === undefined ? reader.len : reader.pos + length, message = new $root.stratumn.crypto.Signature();
                while (reader.pos < end) {
                    var tag = reader.uint32();
                    switch (tag >>> 3) {
                    case 2:
                        message.publicKey = reader.bytes();
                        break;
                    case 3:
                        message.signature = reader.bytes();
                        break;
                    case 4:
                        message.message = reader.bytes();
                        break;
                    default:
                        reader.skipType(tag & 7);
                        break;
                    }
                }
                return message;
            };

            /**
             * Decodes a Signature message from the specified reader or buffer, length delimited.
             * @function decodeDelimited
             * @memberof stratumn.crypto.Signature
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @returns {stratumn.crypto.Signature} Signature
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            Signature.decodeDelimited = function decodeDelimited(reader) {
                if (!(reader instanceof $Reader))
                    reader = new $Reader(reader);
                return this.decode(reader, reader.uint32());
            };

            /**
             * Verifies a Signature message.
             * @function verify
             * @memberof stratumn.crypto.Signature
             * @static
             * @param {Object.<string,*>} message Plain object to verify
             * @returns {string|null} `null` if valid, otherwise the reason why it is not
             */
            Signature.verify = function verify(message) {
                if (typeof message !== "object" || message === null)
                    return "object expected";
                if (message.publicKey != null && message.hasOwnProperty("publicKey"))
                    if (!(message.publicKey && typeof message.publicKey.length === "number" || $util.isString(message.publicKey)))
                        return "publicKey: buffer expected";
                if (message.signature != null && message.hasOwnProperty("signature"))
                    if (!(message.signature && typeof message.signature.length === "number" || $util.isString(message.signature)))
                        return "signature: buffer expected";
                if (message.message != null && message.hasOwnProperty("message"))
                    if (!(message.message && typeof message.message.length === "number" || $util.isString(message.message)))
                        return "message: buffer expected";
                return null;
            };

            /**
             * Creates a Signature message from a plain object. Also converts values to their respective internal types.
             * @function fromObject
             * @memberof stratumn.crypto.Signature
             * @static
             * @param {Object.<string,*>} object Plain object
             * @returns {stratumn.crypto.Signature} Signature
             */
            Signature.fromObject = function fromObject(object) {
                if (object instanceof $root.stratumn.crypto.Signature)
                    return object;
                var message = new $root.stratumn.crypto.Signature();
                if (object.publicKey != null)
                    if (typeof object.publicKey === "string")
                        $util.base64.decode(object.publicKey, message.publicKey = $util.newBuffer($util.base64.length(object.publicKey)), 0);
                    else if (object.publicKey.length)
                        message.publicKey = object.publicKey;
                if (object.signature != null)
                    if (typeof object.signature === "string")
                        $util.base64.decode(object.signature, message.signature = $util.newBuffer($util.base64.length(object.signature)), 0);
                    else if (object.signature.length)
                        message.signature = object.signature;
                if (object.message != null)
                    if (typeof object.message === "string")
                        $util.base64.decode(object.message, message.message = $util.newBuffer($util.base64.length(object.message)), 0);
                    else if (object.message.length)
                        message.message = object.message;
                return message;
            };

            /**
             * Creates a plain object from a Signature message. Also converts values to other types if specified.
             * @function toObject
             * @memberof stratumn.crypto.Signature
             * @static
             * @param {stratumn.crypto.Signature} message Signature
             * @param {$protobuf.IConversionOptions} [options] Conversion options
             * @returns {Object.<string,*>} Plain object
             */
            Signature.toObject = function toObject(message, options) {
                if (!options)
                    options = {};
                var object = {};
                if (options.defaults) {
                    if (options.bytes === String)
                        object.publicKey = "";
                    else {
                        object.publicKey = [];
                        if (options.bytes !== Array)
                            object.publicKey = $util.newBuffer(object.publicKey);
                    }
                    if (options.bytes === String)
                        object.signature = "";
                    else {
                        object.signature = [];
                        if (options.bytes !== Array)
                            object.signature = $util.newBuffer(object.signature);
                    }
                    if (options.bytes === String)
                        object.message = "";
                    else {
                        object.message = [];
                        if (options.bytes !== Array)
                            object.message = $util.newBuffer(object.message);
                    }
                }
                if (message.publicKey != null && message.hasOwnProperty("publicKey"))
                    object.publicKey = options.bytes === String ? $util.base64.encode(message.publicKey, 0, message.publicKey.length) : options.bytes === Array ? Array.prototype.slice.call(message.publicKey) : message.publicKey;
                if (message.signature != null && message.hasOwnProperty("signature"))
                    object.signature = options.bytes === String ? $util.base64.encode(message.signature, 0, message.signature.length) : options.bytes === Array ? Array.prototype.slice.call(message.signature) : message.signature;
                if (message.message != null && message.hasOwnProperty("message"))
                    object.message = options.bytes === String ? $util.base64.encode(message.message, 0, message.message.length) : options.bytes === Array ? Array.prototype.slice.call(message.message) : message.message;
                return object;
            };

            /**
             * Converts this Signature to JSON.
             * @function toJSON
             * @memberof stratumn.crypto.Signature
             * @instance
             * @returns {Object.<string,*>} JSON object
             */
            Signature.prototype.toJSON = function toJSON() {
                return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
            };

            return Signature;
        })();

        return crypto;
    })();

    return stratumn;
})();

module.exports = $root;
