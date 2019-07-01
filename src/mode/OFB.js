const BlockCipherMode = require('../lib/BlockCipherMode');

/**
 * Output Feedback block mode.
 */
const OFB = BlockCipherMode.extend();

OFB.Encryptor = OFB.extend({
    processBlock: function (words, offset) {
        // Shortcuts
        var cipher = this._cipher
        var blockSize = cipher.blockSize;
        var iv = this._iv;
        var keystream = this._keystream;

        // Generate keystream
        if (iv) {
            keystream = this._keystream = iv.slice(0);

            // Remove IV for subsequent blocks
            this._iv = undefined;
        }
        cipher.encryptBlock(keystream, 0);

        // Encrypt
        for (var i = 0; i < blockSize; i++) {
            words[offset + i] ^= keystream[i];
        }
    }
});

OFB.Decryptor = OFB.Encryptor;

module.exports = OFB;
