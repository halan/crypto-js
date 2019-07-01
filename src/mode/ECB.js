const BlockCipherMode = require('../lib/BlockCipherMode');

/**
 * Electronic Codebook block mode.
 */
const ECB = BlockCipherMode.extend();

ECB.Encryptor = ECB.extend({
    processBlock: function (words, offset) {
        this._cipher.encryptBlock(words, offset);
    }
});

ECB.Decryptor = ECB.extend({
    processBlock: function (words, offset) {
        this._cipher.decryptBlock(words, offset);
    }
});

module.exports = ECB;

