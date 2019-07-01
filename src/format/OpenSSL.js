const WordArray = require('../lib/WordArray');
const Base64 = require('../enc/Base64');
const CipherParams = require('../lib/CipherParams');
/**
 * OpenSSL formatting strategy.
 */
const OpenSSLFormatter = {
    /**
     * Converts a cipher params object to an OpenSSL-compatible string.
     *
     * @param {CipherParams} cipherParams The cipher params object.
     *
     * @return {string} The OpenSSL-compatible string.
     *
     * @static
     *
     * @example
     *
     *     var openSSLString = CryptoJS.format.OpenSSL.stringify(cipherParams);
     */
    stringify: function (cipherParams) {
        var wordArray;

        // Shortcuts
        var ciphertext = cipherParams.ciphertext;
        var salt = cipherParams.salt;

        // Format
        if (salt) {
            wordArray = WordArray.create([0x53616c74, 0x65645f5f]).concat(salt).concat(ciphertext);
        } else {
            wordArray = ciphertext;
        }

        return wordArray.toString(Base64);
    },

    /**
     * Converts an OpenSSL-compatible string to a cipher params object.
     *
     * @param {string} openSSLStr The OpenSSL-compatible string.
     *
     * @return {CipherParams} The cipher params object.
     *
     * @static
     *
     * @example
     *
     *     var cipherParams = CryptoJS.format.OpenSSL.parse(openSSLString);
     */
    parse: function (openSSLStr) {
        var salt;

        // Parse base64
        var ciphertext = Base64.parse(openSSLStr);

        // Shortcut
        var ciphertextWords = ciphertext.words;

        // Test for salt
        if (ciphertextWords[0] == 0x53616c74 && ciphertextWords[1] == 0x65645f5f) {
            // Extract salt
            salt = WordArray.create(ciphertextWords.slice(2, 4));

            // Remove salt from ciphertext
            ciphertextWords.splice(0, 4);
            ciphertext.sigBytes -= 16;
        }

        return CipherParams.create({ ciphertext: ciphertext, salt: salt });
    }
};

module.exports = OpenSSLFormatter;
