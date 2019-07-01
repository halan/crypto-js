const Cipher = require('./Cipher');
/**
 * Abstract base stream cipher template.
 *
 * @property {number} blockSize The number of 32-bit words this cipher operates on. Default: 1 (32 bits)
 */
const StreamCipher = Cipher.extend({
    _doFinalize: function () {
        // Process partial blocks
        var finalProcessedBlocks = this._process(!!'flush');

        return finalProcessedBlocks;
    },

    blockSize: 1
});

module.exports = StreamCipher;
