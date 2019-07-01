const WordArray = require('../lib/WordArray');
const ZeroPadding = require('./ZeroPadding');

/**
 * ISO/IEC 9797-1 Padding Method 2.
 */
const Iso97971 = {
    pad: function (data, blockSize) {
        // Add 0x80 byte
        data.concat(WordArray.create([0x80000000], 1));

        // Zero pad the rest
        ZeroPadding.pad(data, blockSize);
    },

    unpad: function (data) {
        // Remove zero padding
        ZeroPadding.unpad(data);

        // Remove one more byte -- the 0x80 byte
        data.sigBytes--;
    }
};

module.exports = Iso97971;
