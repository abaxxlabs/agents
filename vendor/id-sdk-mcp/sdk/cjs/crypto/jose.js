"use strict";
var __rest = (this && this.__rest) || function (s, e) {
    var t = {};
    for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0)
        t[p] = s[p];
    if (s != null && typeof Object.getOwnPropertySymbols === "function")
        for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) {
            if (e.indexOf(p[i]) < 0 && Object.prototype.propertyIsEnumerable.call(s, p[i]))
                t[p[i]] = s[p[i]];
        }
    return t;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.CryptoKeyWithJwk = exports.CryptoKeyToJwkMixin = exports.Jose = void 0;
const sha256_1 = require("@noble/hashes/sha256");
const index_js_1 = require("../common/index.js");
const utils_js_1 = require("./utils.js");
const index_js_2 = require("./algorithms-api/index.js");
const index_js_3 = require("./crypto-primitives/index.js");
const joseToWebCryptoMapping = {
    'Ed25519': { name: 'EdDSA', namedCurve: 'Ed25519' },
    'Ed448': { name: 'EdDSA', namedCurve: 'Ed448' },
    'X25519': { name: 'ECDH', namedCurve: 'X25519' },
    'secp256k1:ES256K': { name: 'ECDSA', namedCurve: 'secp256k1' },
    'secp256k1': { name: 'ECDH', namedCurve: 'secp256k1' },
    'P-256': { name: 'ECDSA', namedCurve: 'P-256' },
    'P-384': { name: 'ECDSA', namedCurve: 'P-384' },
    'P-521': { name: 'ECDSA', namedCurve: 'P-521' },
    'A128CBC': { name: 'AES-CBC', length: 128 },
    'A192CBC': { name: 'AES-CBC', length: 192 },
    'A256CBC': { name: 'AES-CBC', length: 256 },
    'A128CTR': { name: 'AES-CTR', length: 128 },
    'A192CTR': { name: 'AES-CTR', length: 192 },
    'A256CTR': { name: 'AES-CTR', length: 256 },
    'A128GCM': { name: 'AES-GCM', length: 128 },
    'A192GCM': { name: 'AES-GCM', length: 192 },
    'A256GCM': { name: 'AES-GCM', length: 256 },
    'HS256': { name: 'HMAC', hash: { name: 'SHA-256' } },
    'HS384': { name: 'HMAC', hash: { name: 'SHA-384' } },
    'HS512': { name: 'HMAC', hash: { name: 'SHA-512' } },
};
const webCryptoToJoseMapping = {
    'EdDSA:Ed25519': { alg: 'EdDSA', crv: 'Ed25519', kty: 'OKP' },
    'EdDSA:Ed448': { alg: 'EdDSA', crv: 'Ed448', kty: 'OKP' },
    'ECDH:X25519': { crv: 'X25519', kty: 'OKP' },
    'ECDSA:secp256k1': { alg: 'ES256K', crv: 'secp256k1', kty: 'EC' },
    'ECDH:secp256k1': { crv: 'secp256k1', kty: 'EC' },
    'ECDSA:P-256': { alg: 'ES256', crv: 'P-256', kty: 'EC' },
    'ECDSA:P-384': { alg: 'ES384', crv: 'P-384', kty: 'EC' },
    'ECDSA:P-521': { alg: 'ES512', crv: 'P-521', kty: 'EC' },
    'AES-CBC:128': { alg: 'A128CBC', kty: 'oct' },
    'AES-CBC:192': { alg: 'A192CBC', kty: 'oct' },
    'AES-CBC:256': { alg: 'A256CBC', kty: 'oct' },
    'AES-CTR:128': { alg: 'A128CTR', kty: 'oct' },
    'AES-CTR:192': { alg: 'A192CTR', kty: 'oct' },
    'AES-CTR:256': { alg: 'A256CTR', kty: 'oct' },
    'AES-GCM:128': { alg: 'A128GCM', kty: 'oct' },
    'AES-GCM:192': { alg: 'A192GCM', kty: 'oct' },
    'AES-GCM:256': { alg: 'A256GCM', kty: 'oct' },
    'HMAC:SHA-256': { alg: 'HS256', kty: 'oct' },
    'HMAC:SHA-384': { alg: 'HS384', kty: 'oct' },
    'HMAC:SHA-512': { alg: 'HS512', kty: 'oct' },
};
const multicodecToJoseMapping = {
    'ed25519-pub': { alg: 'EdDSA', crv: 'Ed25519', kty: 'OKP', x: '' },
    'ed25519-priv': { alg: 'EdDSA', crv: 'Ed25519', kty: 'OKP', x: '', d: '' },
    'secp256k1-pub': { alg: 'ES256K', crv: 'secp256k1', kty: 'EC', x: '', y: '' },
    'secp256k1-priv': { alg: 'ES256K', crv: 'secp256k1', kty: 'EC', x: '', y: '', d: '' },
    'x25519-pub': { crv: 'X25519', kty: 'OKP', x: '' },
    'x25519-priv': { crv: 'X25519', kty: 'OKP', x: '', d: '' },
};
const joseToMulticodecMapping = {
    'Ed25519:public': 'ed25519-pub',
    'Ed25519:private': 'ed25519-priv',
    'secp256k1:public': 'secp256k1-pub',
    'secp256k1:private': 'secp256k1-priv',
    'X25519:public': 'x25519-pub',
    'X25519:private': 'x25519-priv',
};
class Jose {
    static async cryptoKeyToJwk(options) {
        const { algorithm, extractable, material, type, usages } = options.key;
        // Translate WebCrypto algorithm to JOSE format.
        let jsonWebKey = Jose.webCryptoToJose(algorithm);
        // Set extractable parameter.
        jsonWebKey.ext = extractable ? 'true' : 'false';
        // Set key use parameter.
        jsonWebKey.key_ops = usages;
        jsonWebKey = await Jose.keyToJwk(Object.assign({ keyMaterial: material, keyType: type }, jsonWebKey));
        return Object.assign({}, jsonWebKey);
    }
    static async cryptoKeyToJwkPair(options) {
        const { keyPair } = options;
        // Convert public and private keys into JSON Web Key format.
        const privateKeyJwk = await Jose.cryptoKeyToJwk({ key: keyPair.privateKey });
        const publicKeyJwk = await Jose.cryptoKeyToJwk({ key: keyPair.publicKey });
        // Assemble as a JWK key pair
        const jwkKeyPair = { privateKeyJwk, publicKeyJwk };
        return Object.assign({}, jwkKeyPair);
    }
    static async joseToMulticodec(options) {
        const jsonWebKey = options.key;
        const params = [];
        if ('crv' in jsonWebKey) {
            params.push(jsonWebKey.crv);
            if ('d' in jsonWebKey) {
                params.push('private');
            }
            else {
                params.push('public');
            }
        }
        const lookupKey = params.join(':');
        const name = joseToMulticodecMapping[lookupKey];
        if (name === undefined) {
            throw new Error(`Unsupported JOSE to Multicodec conversion: '${lookupKey}'`);
        }
        const code = index_js_1.Multicodec.getCodeFromName({ name });
        return { code, name };
    }
    static joseToWebCrypto(options) {
        const params = [];
        /**
         * All Elliptic Curve (EC) and Octet Key Pair (OKP) JSON Web Keys
         * set a value for the "crv" parameter.
         */
        if ('crv' in options && options.crv) {
            params.push(options.crv);
            // Special case for secp256k1. If alg is "ES256K", then ECDSA. Else ECDH.
            if (options.crv === 'secp256k1' && options.alg === 'ES256K') {
                params.push(options.alg);
            }
            /**
             * All Octet Sequence (oct) JSON Web Keys omit "crv" and
             * set a value for the "alg" parameter.
             */
        }
        else if (options.alg !== undefined) {
            params.push(options.alg);
        }
        else {
            throw new TypeError(`One or more parameters missing: 'alg' or 'crv'`);
        }
        const lookupKey = params.join(':');
        const webCrypto = joseToWebCryptoMapping[lookupKey];
        if (webCrypto === undefined) {
            throw new Error(`Unsupported JOSE to WebCrypto conversion: '${lookupKey}'`);
        }
        return Object.assign({}, webCrypto);
    }
    /**
     * Computes the thumbprint of a JSON Web Key (JWK) using the method
     * specified in RFC 7638. This function accepts RSA, EC, OKP, and oct keys
     * and returns the thumbprint as a base64url encoded SHA-256 hash of the
     * JWK's required members, serialized and sorted lexicographically.
     *
     * Purpose:
     * - Uniquely Identifying Keys: The thumbprint allows the unique
     *   identification of a specific JWK within a set of JWKs. It provides a
     *   deterministic way to generate a value that can be used as a key
     *   identifier (kid) or to match a specific key.
     *
     * - Simplifying Key Management: In systems where multiple keys are used,
     *   managing and identifying individual keys can become complex. The
     *   thumbprint method simplifies this by creating a standardized, unique
     *   identifier for each key.
     *
     * - Enabling Interoperability: By standardizing the method to compute a
     *   thumbprint, different systems can compute the same thumbprint value for
     *   a given JWK. This enables interoperability among systems that use JWKs.
     *
     * - Secure Comparison: The thumbprint provides a way to securely compare
     *   JWKs to determine if they are equivalent.
     *
     * @param jwk - The JSON Web Key for which the thumbprint will be computed.
     *              This must be an RSA, EC, OKP, or oct key.
     * @returns The thumbprint as a base64url encoded string.
     * @throws {Error} Throws an error if the provided key type is unsupported.
     *
     * @example
     * const jwk: PublicKeyJwk = {
     *   'kty': 'EC',
     *   'crv': 'secp256k1',
     *   'x': '61iPYuGefxotzBdQZtDvv6cWHZmXrTTscY-u7Y2pFZc',
     *   'y': '88nPCVLfrAY9i-wg5ORcwVbHWC_tbeAd1JE2e0co0lU'
     * };
     *
     * const thumbprint = jwkThumbprint(jwk);
     * console.log(`JWK thumbprint: ${thumbprint}`);
     *
     * @see {@link https://datatracker.ietf.org/doc/html/rfc7638 | RFC7638} for
     * the specification of JWK thumbprint computation.
     */
    static async jwkThumbprint(options) {
        const { key } = options;
        /** Step 1 - Normalization: The JWK is normalized to include only specific
         * members and in lexicographic order.
         */
        const keyType = key.kty;
        let normalizedJwk;
        if (keyType === 'EC') {
            normalizedJwk = { crv: key.crv, kty: key.kty, x: key.x, y: key.y };
        }
        else if (keyType === 'oct') {
            normalizedJwk = { k: key.k, kty: key.kty };
        }
        else if (keyType === 'OKP') {
            normalizedJwk = { crv: key.crv, kty: key.kty, x: key.x };
        }
        else if (keyType === 'RSA') {
            normalizedJwk = { e: key.e, kty: key.kty, n: key.n };
        }
        else {
            throw new Error(`Unsupported key type: ${keyType}`);
        }
        (0, index_js_1.removeUndefinedProperties)(normalizedJwk);
        /** Step 2 - Serialization: The normalized JWK is serialized to a UTF-8
         * representation of its JSON encoding. */
        const serializedJwk = Jose.canonicalize(normalizedJwk);
        /** Step 3 - Digest Calculation: A cryptographic hash function
         * (SHA-256 is recommended) is applied to the serialized JWK,
         * resulting in the thumbprint. */
        const utf8Bytes = index_js_1.Convert.string(serializedJwk).toUint8Array();
        const digest = (0, sha256_1.sha256)(utf8Bytes);
        // Encode as Base64Url.
        const thumbprint = index_js_1.Convert.uint8Array(digest).toBase64Url();
        return thumbprint;
    }
    static async jwkToCryptoKey(options) {
        const jsonWebKey = options.key;
        const { keyMaterial, keyType } = await Jose.jwkToKey({ key: jsonWebKey });
        // Translate JOSE format to WebCrypto algorithm.
        let algorithm = Jose.joseToWebCrypto(jsonWebKey);
        // Set extractable parameter.
        let extractable;
        if ('ext' in jsonWebKey && jsonWebKey.ext !== undefined) {
            extractable = jsonWebKey.ext === 'true' ? true : false;
        }
        else {
            throw new Error(`Conversion from JWK to CryptoKey failed. Required parameter missing: 'ext'`);
        }
        // Set key use parameter.
        let keyUsage;
        if ('key_ops' in jsonWebKey && jsonWebKey.key_ops !== undefined) {
            keyUsage = jsonWebKey.key_ops;
        }
        else {
            throw new Error(`Conversion from JWK to CryptoKey failed. Required parameter missing: 'key_ops'`);
        }
        const cryptoKey = new index_js_2.CryptoKey(algorithm, extractable, keyMaterial, keyType, keyUsage);
        return cryptoKey;
    }
    static async jwkToKey(options) {
        const jsonWebKey = options.key;
        let keyMaterial;
        let keyType;
        // Asymmetric private key ("EC" or "OKP" - Curve25519 or SECG curves).
        if ('d' in jsonWebKey) {
            keyMaterial = index_js_1.Convert.base64Url(jsonWebKey.d).toUint8Array();
            keyType = 'private';
        }
        // Asymmetric public key ("EC" - secp256k1, secp256r1, secp384r1, secp521r1).
        else if ('y' in jsonWebKey && jsonWebKey.y) {
            const prefix = new Uint8Array([0x04]); // Designates an uncompressed key.
            const x = index_js_1.Convert.base64Url(jsonWebKey.x).toUint8Array();
            const y = index_js_1.Convert.base64Url(jsonWebKey.y).toUint8Array();
            const publicKey = new Uint8Array([...prefix, ...x, ...y]);
            keyMaterial = publicKey;
            keyType = 'public';
        }
        // Asymmetric public key ("OKP" - Ed25519, X25519).
        else if ('x' in jsonWebKey) {
            keyMaterial = index_js_1.Convert.base64Url(jsonWebKey.x).toUint8Array();
            keyType = 'public';
        }
        // Symmetric encryption or signature key ("oct" - AES, HMAC)
        else if ('k' in jsonWebKey) {
            keyMaterial = index_js_1.Convert.base64Url(jsonWebKey.k).toUint8Array();
            keyType = 'private';
        }
        else {
            throw new Error('Jose: Unknown JSON Web Key format.');
        }
        return { keyMaterial, keyType };
    }
    /**
    * Note: All secp public keys are converted to compressed point encoding
    *    before the multibase identifier is computed.
    *
    * Per {@link https://github.com/multiformats/multicodec/blob/master/table.csv | Multicodec table}:
    *    public keys for Elliptic Curve cryptography algorithms (e.g., secp256k1,
    *    secp256k1r1, secp384r1, etc.) are always represented with compressed point
    *    encoding (e.g., secp256k1-pub, p256-pub, p384-pub, etc.).
    *
    * Per {@link https://datatracker.ietf.org/doc/html/rfc8812#name-jose-and-cose-secp256k1-cur | RFC 8812}:
    *    "As a compressed point encoding representation is not defined for JWK
    *    elliptic curve points, the uncompressed point encoding defined there
    *    MUST be used. The x and y values represented MUST both be exactly
    *    256 bits, with any leading zeros preserved.
    *
    */
    static async jwkToMultibaseId(options) {
        const jsonWebKey = options.key;
        // Convert the algorithm into Multicodec name format.
        const { name: multicodecName } = await Jose.joseToMulticodec({ key: jsonWebKey });
        // Decode the key as a raw binary data from the JWK.
        let { keyMaterial } = await Jose.jwkToKey({ key: jsonWebKey });
        // Convert secp256k1 public keys to compressed format.
        if ('crv' in jsonWebKey && !('d' in jsonWebKey)) {
            switch (jsonWebKey.crv) {
                case 'secp256k1': {
                    keyMaterial = await index_js_3.Secp256k1.convertPublicKey({
                        publicKey: keyMaterial,
                        compressedPublicKey: true
                    });
                    break;
                }
            }
        }
        // Compute the multibase identifier based on the provided key.
        const multibaseId = (0, utils_js_1.keyToMultibaseId)({ key: keyMaterial, multicodecName });
        return multibaseId;
    }
    static async keyToJwk(options) {
        var _a, _b, _c;
        const { keyMaterial, keyType } = options, jsonWebKeyOptions = __rest(options, ["keyMaterial", "keyType"]);
        let jsonWebKey = Object.assign({}, jsonWebKeyOptions);
        /**
         * All Elliptic Curve (EC) and Octet Key Pair (OKP) keys
         * specify a "crv" (named curve) parameter.
         */
        if ('crv' in jsonWebKey) {
            switch (jsonWebKey.crv) {
                case 'Ed25519': {
                    const publicKey = (keyType === 'private')
                        ? await index_js_3.Ed25519.getPublicKey({ privateKey: keyMaterial })
                        : keyMaterial;
                    jsonWebKey.x = index_js_1.Convert.uint8Array(publicKey).toBase64Url();
                    (_a = jsonWebKey.kty) !== null && _a !== void 0 ? _a : (jsonWebKey.kty = 'OKP');
                    break;
                }
                case 'X25519': {
                    const publicKey = (keyType === 'private')
                        ? await index_js_3.X25519.getPublicKey({ privateKey: keyMaterial })
                        : keyMaterial;
                    jsonWebKey.x = index_js_1.Convert.uint8Array(publicKey).toBase64Url();
                    (_b = jsonWebKey.kty) !== null && _b !== void 0 ? _b : (jsonWebKey.kty = 'OKP');
                    break;
                }
                case 'secp256k1': {
                    const points = await index_js_3.Secp256k1.getCurvePoints({ key: keyMaterial });
                    jsonWebKey.x = index_js_1.Convert.uint8Array(points.x).toBase64Url();
                    jsonWebKey.y = index_js_1.Convert.uint8Array(points.y).toBase64Url();
                    (_c = jsonWebKey.kty) !== null && _c !== void 0 ? _c : (jsonWebKey.kty = 'EC');
                    break;
                }
                default: {
                    throw new Error(`Unsupported key to JWK conversion: ${jsonWebKey.crv}`);
                }
            }
            if (keyType === 'private') {
                jsonWebKey = Object.assign({ d: index_js_1.Convert.uint8Array(keyMaterial).toBase64Url() }, jsonWebKey);
            }
        }
        /**
         * All Octet Sequence (oct) symmetric encryption and signature keys
         * specify only an "alg" parameter.
         */
        if (!('crv' in jsonWebKey) && jsonWebKey.kty === 'oct') {
            jsonWebKey.k = index_js_1.Convert.uint8Array(keyMaterial).toBase64Url();
        }
        return Object.assign({}, jsonWebKey);
    }
    static async multicodecToJose(options) {
        let { code, name } = options;
        // Either code or name must be specified, but not both.
        if (!(name ? !code : code)) {
            throw new Error(`Either 'name' or 'code' must be defined, but not both.`);
        }
        // If name is undefined, lookup by code.
        name = (name === undefined) ? index_js_1.Multicodec.getNameFromCode({ code: code }) : name;
        const lookupKey = name;
        const jose = multicodecToJoseMapping[lookupKey];
        if (jose === undefined) {
            throw new Error(`Unsupported Multicodec to JOSE conversion: '${options.name}'`);
        }
        return Object.assign({}, jose);
    }
    static webCryptoToJose(options) {
        const params = [];
        /**
         * All WebCrypto algorithms have the "named" parameter.
         */
        params.push(options.name);
        /**
         * All Elliptic Curve (EC) WebCrypto algorithms
         * set a value for the "namedCurve" parameter.
         */
        if ('namedCurve' in options) {
            params.push(options.namedCurve);
            /**
             * All symmetric encryption (AES) WebCrypto algorithms
             * set a value for the "length" parameter.
             */
        }
        else if ('length' in options && options.length !== undefined) {
            params.push(options.length.toString());
            /**
             * All symmetric signature (HMAC) WebCrypto algorithms
             * set a value for the "hash" parameter.
             */
        }
        else if ('hash' in options) {
            params.push(options.hash.name);
        }
        else {
            throw new TypeError(`One or more parameters missing: 'name', 'namedCurve', 'length', or 'hash'`);
        }
        const lookupKey = params.join(':');
        const jose = webCryptoToJoseMapping[lookupKey];
        if (jose === undefined) {
            throw new Error(`Unsupported WebCrypto to JOSE conversion: '${lookupKey}'`);
        }
        return Object.assign({}, jose);
    }
    static canonicalize(obj) {
        const sortedKeys = Object.keys(obj).sort();
        const sortedObj = sortedKeys.reduce((acc, key) => {
            acc[key] = obj[key];
            return acc;
        }, {});
        return JSON.stringify(sortedObj);
    }
}
exports.Jose = Jose;
function CryptoKeyToJwkMixin(Base) {
    return class extends Base {
        async toJwk() {
            const jwk = Jose.cryptoKeyToJwk({ key: this });
            return jwk;
        }
    };
}
exports.CryptoKeyToJwkMixin = CryptoKeyToJwkMixin;
exports.CryptoKeyWithJwk = CryptoKeyToJwkMixin(index_js_2.CryptoKey);
//# sourceMappingURL=jose.js.map