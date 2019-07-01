const Cipher = require('./Cipher');
const CBC = require('../mode/CBC');
const Pkcs7 = require('../pad/Pkcs7');

/**
 * Abstract base block cipher template.
 *
 * @property {number} blockSize The number of 32-bit words this cipher operates on. Default: 4 (128 bits)
 */
const BlockCipher = Cipher.extend({
    /**
     * Configuration options.
     *
     * @property {Mode} mode The block mode to use. Default: CBC
     * @property {Padding} padding The padding strategy to use. Default: Pkcs7
     */
    cfg: Cipher.cfg.extend({
        mode: CBC,
        padding: Pkcs7
    }),

    reset: function () {
        var modeCreator;

        // Reset cipher
        Cipher.reset.call(this);

        // Shortcuts
        var cfg = this.cfg;
        var iv = cfg.iv;
        var mode = cfg.mode;

        // Reset block mode
        if (this._xformMode == this._ENC_XFORM_MODE) {
            modeCreator = mode.createEncryptor;
        } else /* if (this._xformMode == this._DEC_XFORM_MODE) */ {
            modeCreator = mode.createDecryptor;
            // Keep at least one block in the buffer for unpadding
            this._minBufferSize = 1;
        }

        if (this._mode && this._mode.__creator == modeCreator) {
            this._mode.init(this, iv && iv.words);
        } else {
            this._mode = modeCreator.call(mode, this, iv && iv.words);
            this._mode.__creator = modeCreator;
        }
    },

    _doProcessBlock: function (words, offset) {
        this._mode.processBlock(words, offset);
    },

    _doFinalize: function () {
        var finalProcessedBlocks;

        // Shortcut
        var padding = this.cfg.padding;

        // Finalize
        if (this._xformMode == this._ENC_XFORM_MODE) {
            // Pad data
            padding.pad(this._data, this.blockSize);

            // Process final blocks
            finalProcessedBlocks = this._process(!!'flush');
        } else /* if (this._xformMode == this._DEC_XFORM_MODE) */ {
            // Process final blocks
            finalProcessedBlocks = this._process(!!'flush');

            // Unpad data
            padding.unpad(finalProcessedBlocks);
        }

        return finalProcessedBlocks;
    },

    blockSize: 128/32
});

module.exports = BlockCipher;
