const BlockCipherMode = require('../lib/BlockCipherMode');
/**
 * Cipher Block Chaining mode.
 */
const CBC = BlockCipherMode.extend();

/**
 * CBC encryptor.
 */
CBC.Encryptor = CBC.extend({
    /**
     * Processes the data block at offset.
     *
     * @param {Array} words The data words to operate on.
     * @param {number} offset The offset where the block starts.
     *
     * @example
     *
     *     mode.processBlock(data.words, offset);
     */
    processBlock: function (words, offset) {
        // Shortcuts
        var cipher = this._cipher;
        var blockSize = cipher.blockSize;

        // XOR and encrypt
        xorBlock.call(this, words, offset, blockSize);
        cipher.encryptBlock(words, offset);

        // Remember this block to use with next block
        this._prevBlock = words.slice(offset, offset + blockSize);
    }
});

/**
 * CBC decryptor.
 */
CBC.Decryptor = CBC.extend({
    /**
     * Processes the data block at offset.
     *
     * @param {Array} words The data words to operate on.
     * @param {number} offset The offset where the block starts.
     *
     * @example
     *
     *     mode.processBlock(data.words, offset);
     */
    processBlock: function (words, offset) {
        // Shortcuts
        var cipher = this._cipher;
        var blockSize = cipher.blockSize;

        // Remember this block to use with next block
        var thisBlock = words.slice(offset, offset + blockSize);

        // Decrypt and XOR
        cipher.decryptBlock(words, offset);
        xorBlock.call(this, words, offset, blockSize);

        // This block becomes the previous block
        this._prevBlock = thisBlock;
    }
});

function xorBlock(words, offset, blockSize) {
    var block;

    // Shortcut
    var iv = this._iv;

    // Choose mixing block
    if (iv) {
        block = iv;

        // Remove IV for subsequent blocks
        this._iv = undefined;
    } else {
        block = this._prevBlock;
    }

    if(!block) {
      throw "IV is missing!"
    }

    // XOR blocks
    for (var i = 0; i < blockSize; i++) {
        words[offset + i] ^= block[i];
    }
};

module.exports = CBC;

