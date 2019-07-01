const Base = require('../lib/Base');
const WordArray = require('../lib/WordArray');
const MD5 = require('../algo/MD5');

/**
 * This key derivation function is meant to conform with EVP_BytesToKey.
 * www.openssl.org/docs/crypto/EVP_BytesToKey.html
 */
const EvpKDF = Base.extend({
    /**
     * Configuration options.
     *
     * @property {number} keySize The key size in words to generate. Default: 4 (128 bits)
     * @property {Hasher} hasher The hash algorithm to use. Default: MD5
     * @property {number} iterations The number of iterations to perform. Default: 1
     */
    cfg: Base.extend({
        keySize: 128/32,
        hasher: MD5,
        iterations: 1
    }),

    /**
     * Initializes a newly created key derivation function.
     *
     * @param {Object} cfg (Optional) The configuration options to use for the derivation.
     *
     * @example
     *
     *     var kdf = CryptoJS.algo.EvpKDF.create();
     *     var kdf = CryptoJS.algo.EvpKDF.create({ keySize: 8 });
     *     var kdf = CryptoJS.algo.EvpKDF.create({ keySize: 8, iterations: 1000 });
     */
    init: function (cfg) {
        this.cfg = this.cfg.extend(cfg);
    },

    /**
     * Derives a key from a password.
     *
     * @param {WordArray|string} password The password.
     * @param {WordArray|string} salt A salt.
     *
     * @return {WordArray} The derived key.
     *
     * @example
     *
     *     var key = kdf.compute(password, salt);
     */
    compute: function (password, salt) {
        var block;

        // Shortcut
        var cfg = this.cfg;

        // Init hasher
        var hasher = cfg.hasher.create();

        // Initial values
        var derivedKey = WordArray.create();

        // Shortcuts
        var derivedKeyWords = derivedKey.words;
        var keySize = cfg.keySize;
        var iterations = cfg.iterations;

        // Generate key
        while (derivedKeyWords.length < keySize) {
            if (block) {
                hasher.update(block);
            }
            block = hasher.update(password).finalize(salt);
            hasher.reset();

            // Iterations
            for (var i = 1; i < iterations; i++) {
                block = hasher.finalize(block);
                hasher.reset();
            }

            derivedKey.concat(block);
        }
        derivedKey.sigBytes = keySize * 4;

        return derivedKey;
    }
});

module.exports = EvpKDF;
