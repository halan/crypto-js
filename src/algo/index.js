const TripleDES = require('./TripleDES');
const RC4 = require('./RC4');

module.exports = {
  MD5: require('./MD5'),
  SHA1: require('./SHA1'),
  SHA256: require('./SHA256'),
  SHA224: require('./SHA224'),
  SHA512: require('./SHA512'),
  SHA384: require('./SHA384'),
  SHA3: require('./SHA3'),
  RIPEMD160: require('./RIPEMD160'),
  HMAC: require('./HMAC'),
  PBKDF2: require('./PBKDF2'),
  EvpKDF: require('./EvpKDF'),
  AES: require('./AES'),
  DES: TripleDES.DES,
  TripleDES: TripleDES.TripleDES,
  RC4: RC4.RC4,
  RC4Drop: RC4.RC4Drop,
  Rabbit: require('./Rabbit'),
  RabbitLegacy: require('./RabbitLegacy')
};
