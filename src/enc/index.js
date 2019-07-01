const Utf16 = require('./Utf16');

module.exports = {
  Hex: require('./Hex'),
  Latin1: require('./Latin1'),
  Utf8: require('./Utf8'),
  Utf16BE: Utf16.Utf16BE,
  Utf16: Utf16.Utf16BE,
  UTf16LE: Utf16.Utf16LE,
  Base64: require('./Base64')
}
