const { encodeRecipient } = require('../dist/src/crypto/format-utils');
const crypto = require('crypto');

// Generate a random 33-byte compressed public key (first byte is 0x02 or 0x03)
const publicKey = Buffer.concat([
  Buffer.from([0x02]), // compressed key prefix
  crypto.randomBytes(32) // 32 random bytes
]);

const recipient = encodeRecipient(publicKey);
console.log('Valid test recipient:', recipient);
console.log('Public key hex:', publicKey.toString('hex'));