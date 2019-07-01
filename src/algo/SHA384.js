const SHA512 = require('./SHA512');
const X64WordArray = require('../lib/WordArray');
const X64Word = require('../x64/Word');

/**
 * SHA-384 hash algorithm.
 */
const SHA384 =  SHA512.extend({
    _doReset: function () {
        this._hash = new X64WordArray.init([
            new X64Word.init(0xcbbb9d5d, 0xc1059ed8), new X64Word.init(0x629a292a, 0x367cd507),
            new X64Word.init(0x9159015a, 0x3070dd17), new X64Word.init(0x152fecd8, 0xf70e5939),
            new X64Word.init(0x67332667, 0xffc00b31), new X64Word.init(0x8eb44a87, 0x68581511),
            new X64Word.init(0xdb0c2e0d, 0x64f98fa7), new X64Word.init(0x47b5481d, 0xbefa4fa4)
        ]);
    },

    _doFinalize: function () {
        var hash = SHA512._doFinalize.call(this);

        hash.sigBytes -= 16;

        return hash;
    }
});

module.exports = SHA384;
